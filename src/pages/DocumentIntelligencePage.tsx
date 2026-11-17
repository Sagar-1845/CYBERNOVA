import React, { useState } from 'react';
import { toast } from 'sonner';
import {
  FileText,
  Shield,
  ShieldCheck,
  Sparkles,
  Play,
  Layers,
  Cpu,
  Info,
  AlertCircle,
  FileCheck2,
  Lock,
  Download,
  Terminal,
  UploadCloud,
  FileCode,
  ClipboardPaste,
  RotateCcw,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';
import { DocumentUploadZone } from '@/components/document/DocumentUploadZone';
import { DocumentFileList } from '@/components/document/DocumentFileList';
import { DocumentPreviewModal } from '@/components/document/DocumentPreviewModal';
import { DocumentFileItem } from '@/lib/document/types';
import { extractUnifiedDocument, normalizeRawText } from '@/lib/document/extractors';
import { sanitizeFileName } from '@/lib/document/magicBytes';

// Jury Mode Pipeline Imports
import {
  detectEntitiesInText,
  DetectedEntityItem,
  DetectionResult,
} from '@/lib/detection/detector';
import {
  POLICY_PROFILES,
  PolicyProfile,
  evaluatePolicyOnEntities,
} from '@/lib/policy/policyEngine';
import {
  maskDocumentByOffsets,
  MaskingResult,
  OffsetInvariantError,
} from '@/lib/masking/offsetMasker';
import {
  performIndependentVerification,
  VerificationReport,
} from '@/lib/verification/independentVerifier';
import {
  generateComplianceReport,
  ComplianceReport,
  ReviewedItemRecord,
} from '@/lib/compliance/reportGenerator';
import { REHEARSAL_DOCUMENTS } from '@/lib/rehearsal/rehearsalDocuments';

// Jury UI Components
import { JuryReviewPanel } from '@/components/document/JuryReviewPanel';
import { JuryExecutionWorkspace } from '@/components/document/JuryExecutionWorkspace';
import { ComplianceReportModal } from '@/components/document/ComplianceReportModal';

export const DocumentIntelligencePage: React.FC = () => {
  // Input Modes: 'upload' vs 'paste'
  const [inputMode, setInputMode] = useState<'upload' | 'paste'>('upload');
  const [pastedText, setPastedText] = useState<string>('');
  const [pastedDocName, setPastedDocName] = useState<string>('Pasted_Document.txt');

  // File Upload Queue State
  const [fileQueue, setFileQueue] = useState<DocumentFileItem[]>([]);
  const [selectedPreviewItem, setSelectedPreviewItem] = useState<DocumentFileItem | null>(null);

  // Policy Profile State
  const [selectedProfileId, setSelectedProfileId] = useState<string>('DPDP_STATUTORY_STRICT');
  const activeProfile: PolicyProfile =
    POLICY_PROFILES.find((p) => p.id === selectedProfileId) || POLICY_PROFILES[0];

  // Pipeline Execution State
  const [isProcessing, setIsProcessing] = useState<boolean>(false);
  const [activeRawText, setActiveRawText] = useState<string>('');
  const [activeFileName, setActiveFileName] = useState<string>('');
  const [detectedEntities, setDetectedEntities] = useState<DetectedEntityItem[]>([]);
  const [maskingResult, setMaskingResult] = useState<MaskingResult | null>(null);
  const [verificationReport, setVerificationReport] = useState<VerificationReport>({
    status: 'NOT EXECUTED',
    canDispatchToAI: false,
    canDownloadSanitized: false,
    totalLeaksCount: 0,
    leaks: [],
    summary: 'Independent verification not yet executed. Outbound dispatch and sanitized downloads are blocked.',
    timestamp: new Date().toISOString(),
    checksPerformed: {
      vaultReverseLookup: false,
      independentPatternScan: false,
      secretsExcisionCheck: false,
      formatIntegrityCheck: false,
    },
  });
  const [complianceReport, setComplianceReport] = useState<ComplianceReport | null>(null);
  const [reviewedItemsLog, setReviewedItemsLog] = useState<ReviewedItemRecord[]>([]);
  const [showReviewPanel, setShowReviewPanel] = useState<boolean>(false);
  const [showCertificateModal, setShowCertificateModal] = useState<boolean>(false);

  // File Selection & Extraction Handler
  const handleFilesSelected = async (newFiles: File[]) => {
    const queueItems: DocumentFileItem[] = newFiles.map((file) => ({
      id: 'F-' + Math.random().toString(36).substring(2, 9),
      file,
      name: file.name,
      sanitizedName: sanitizeFileName(file.name),
      size: file.size,
      type: file.name.split('.').pop()?.toUpperCase() || 'FILE',
      status: 'Queued',
      progress: 0,
    }));

    setFileQueue((prev) => [...prev, ...queueItems]);

    // Process each file sequentially in sovereign client memory
    for (const item of queueItems) {
      updateItemState(item.id, { status: 'Extracting', progress: 20 });

      try {
        const extracted = await extractUnifiedDocument(item.file, undefined, (pct) => {
          updateItemState(item.id, { progress: pct });
        });

        updateItemState(item.id, {
          status: 'Ready',
          progress: 100,
          extracted,
        });

        toast.success(`Extracted "${item.sanitizedName}" (${extracted.nodes.length} nodes parsed).`);
      } catch (err: any) {
        updateItemState(item.id, {
          status: 'Failed',
          progress: 100,
          error: err?.message || 'Document extraction failed.',
        });
        toast.error(`Error parsing "${item.sanitizedName}"`, {
          description: err?.message || 'Document validation or extraction failed.',
        });
      }
    }
  };

  const updateItemState = (id: string, updates: Partial<DocumentFileItem>) => {
    setFileQueue((prev) =>
      prev.map((item) => (item.id === id ? { ...item, ...updates } : item))
    );
  };

  const handleRemoveFile = (id: string) => {
    setFileQueue((prev) => prev.filter((item) => item.id !== id));
  };

  const handleClearAll = () => {
    setFileQueue([]);
    setPastedText('');
    setActiveRawText('');
    setActiveFileName('');
    setDetectedEntities([]);
    setMaskingResult(null);
    setVerificationReport({
      status: 'NOT EXECUTED',
      canDispatchToAI: false,
      canDownloadSanitized: false,
      totalLeaksCount: 0,
      leaks: [],
      summary: 'Pipeline reset. Independent verification not executed.',
      timestamp: new Date().toISOString(),
      checksPerformed: {
        vaultReverseLookup: false,
        independentPatternScan: false,
        secretsExcisionCheck: false,
        formatIntegrityCheck: false,
      },
    });
    setComplianceReport(null);
    setReviewedItemsLog([]);
    setShowReviewPanel(false);
    toast.info('Document queue and sovereign state wiped from memory.');
  };

  // Quick-load Rehearsal Benchmark Document
  const handleLoadRehearsalDoc = (rehearsal: typeof REHEARSAL_DOCUMENTS[0]) => {
    if (inputMode === 'paste') {
      setPastedText(rehearsal.rawText);
      setPastedDocName(rehearsal.fileName);
      toast.success(`Loaded "${rehearsal.title}" into text editor.`);
    } else {
      const blob = new Blob([rehearsal.rawText], { type: rehearsal.mimeType });
      const file = new File([blob], rehearsal.fileName, { type: rehearsal.mimeType });
      handleFilesSelected([file]);
    }
  };

  // Pipeline Execution: Extraction -> Detection -> Policy -> Masking -> Verification -> Report
  const executePipeline = (rawTextToProcess: string, fileNameToProcess: string, entitiesToMask?: DetectedEntityItem[]) => {
    setIsProcessing(true);

    try {
      const normalizedText = normalizeRawText(rawTextToProcess);
      setActiveRawText(normalizedText);
      setActiveFileName(fileNameToProcess);

      // 1. Detection Phase (if not already provided)
      let entities = entitiesToMask;
      if (!entities) {
        const detectionResult: DetectionResult = detectEntitiesInText(
          normalizedText,
          activeProfile.reviewConfidenceThreshold
        );

        // 2. Policy Decision Phase
        const policyEval = evaluatePolicyOnEntities(detectionResult.entities, activeProfile.id);
        entities = policyEval.evaluatedEntities;
        setDetectedEntities(entities);

        // 3. Low-Confidence Review Check
        const pendingReviewItems = entities.filter((e) => e.needsReview && !e.reviewDecision);
        if (pendingReviewItems.length > 0) {
          setShowReviewPanel(true);
          toast.warning(`${pendingReviewItems.length} candidate(s) need review`, {
            description: 'Detection confidence is below profile threshold. Review candidates or accept all to proceed.',
          });
          setIsProcessing(false);
          return;
        }
      }

      // 4. Offset Masking Phase (Strict Invariant Verification)
      const maskRes = maskDocumentByOffsets(normalizedText, entities);
      setMaskingResult(maskRes);

      // 5. Independent Second-Pass Verification
      const verifRes = performIndependentVerification(maskRes.maskedText, maskRes.vaultMapping);
      setVerificationReport(verifRes);

      // 6. DPDP Compliance Report Generation
      const docId = 'DPDP-DOC-' + Math.random().toString(36).substring(2, 9).toUpperCase();
      const compReport = generateComplianceReport({
        documentId: docId,
        fileName: fileNameToProcess,
        profile: activeProfile,
        entities,
        verification: verifRes,
        reviewedItems: reviewedItemsLog,
      });
      setComplianceReport(compReport);

      if (verifRes.status === 'VERIFIED SAFE') {
        toast.success('Pipeline Complete: VERIFIED SAFE', {
          description: `Zero leaks detected. Outbound AI dispatch & TXT download certified safe.`,
        });
      } else {
        toast.error(`Verification Result: ${verifRes.status}`, {
          description: `Potential sensitive leaks intercepted. Outbound dispatch strictly blocked.`,
        });
      }
    } catch (err: any) {
      if (err instanceof OffsetInvariantError) {
        toast.error('Offset Invariant Failure', {
          description: err.message,
        });
      } else {
        toast.error('Pipeline Processing Failed', {
          description: err?.message || 'Unexpected failure during document de-identification.',
        });
      }
    } finally {
      setIsProcessing(false);
    }
  };

  // Primary Analyze Trigger
  const handleAnalyzeClick = async () => {
    if (inputMode === 'paste') {
      if (!pastedText.trim()) {
        toast.error('Please paste or enter document text to analyze.');
        return;
      }
      executePipeline(pastedText, pastedDocName);
    } else {
      const readyItem = fileQueue.find((f) => f.status === 'Ready');
      if (!readyItem || !readyItem.extracted) {
        toast.error('No ready document in queue to analyze.');
        return;
      }
      executePipeline(readyItem.extracted.rawText, readyItem.name);
    }
  };

  // Review Decisions Handlers
  const handleReviewDecision = (entityId: string, decision: 'ACCEPTED' | 'REJECTED') => {
    setDetectedEntities((prev) =>
      prev.map((e) => (e.id === entityId ? { ...e, reviewDecision: decision } : e))
    );

    const target = detectedEntities.find((e) => e.id === entityId);
    if (target) {
      setReviewedItemsLog((prev) => [
        ...prev.filter((r) => r.entityId !== entityId),
        {
          entityId: target.id,
          type: target.type,
          confidence: target.confidence,
          decision,
          reviewedAt: new Date().toISOString(),
          explanation: decision === 'ACCEPTED' ? 'Confirmed by operator for statutory masking' : 'Rejected as non-sensitive or false positive',
        },
      ]);
    }
  };

  const handleAcceptAllReview = () => {
    setDetectedEntities((prev) =>
      prev.map((e) => (e.needsReview ? { ...e, reviewDecision: 'ACCEPTED' } : e))
    );
    const newLogs: ReviewedItemRecord[] = detectedEntities
      .filter((e) => e.needsReview)
      .map((e) => ({
        entityId: e.id,
        type: e.type,
        confidence: e.confidence,
        decision: 'ACCEPTED',
        reviewedAt: new Date().toISOString(),
        explanation: 'Bulk accepted by operator',
      }));
    setReviewedItemsLog((prev) => [...prev, ...newLogs]);
    toast.success('Accepted all low-confidence items.');
  };

  const handleRejectAllReview = () => {
    setDetectedEntities((prev) =>
      prev.map((e) => (e.needsReview ? { ...e, reviewDecision: 'REJECTED' } : e))
    );
    const newLogs: ReviewedItemRecord[] = detectedEntities
      .filter((e) => e.needsReview)
      .map((e) => ({
        entityId: e.id,
        type: e.type,
        confidence: e.confidence,
        decision: 'REJECTED',
        reviewedAt: new Date().toISOString(),
        explanation: 'Bulk rejected as non-sensitive by operator',
      }));
    setReviewedItemsLog((prev) => [...prev, ...newLogs]);
    toast.info('Rejected all low-confidence items (will remain unmasked).');
  };

  const handleApplyReviewAndVerify = () => {
    setShowReviewPanel(false);
    executePipeline(activeRawText, activeFileName, detectedEntities);
  };

  const readyFilesCount = fileQueue.filter((f) => f.status === 'Ready').length;
  const isAnalyzeDisabled =
    inputMode === 'upload' ? readyFilesCount === 0 : pastedText.trim().length === 0;

  return (
    <div className="pt-24 pb-20 min-h-screen">
      <div className="container mx-auto px-4 sm:px-6 max-w-6xl space-y-8">
        {/* Header Section */}
        <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 border-b border-border/80 pb-6">
          <div>
            <div className="flex items-center gap-2 mb-2 flex-wrap">
              <Badge variant="outline" className="border-neon/40 text-neon font-mono text-xs">
                <Cpu className="w-3.5 h-3.5 mr-1" /> JURY MODE // UNIVERSAL INGESTION & DE-IDENTIFICATION
              </Badge>
              <Badge variant="saffron" className="text-[10px] font-mono">
                DPDP Act 2023 Statutory Pipeline
              </Badge>
              <Badge variant="outline" className="border-emerald-500/40 text-emerald-300 text-[10px] font-mono">
                Zero-Persistence Sovereign Memory
              </Badge>
            </div>
            <h1 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-foreground">
              Document Intelligence & Statutory Masking
            </h1>
            <p className="text-sm sm:text-base text-muted-foreground mt-1 max-w-2xl font-body">
              Upload or paste unknown documents. Runs extraction, multilingual entity detection, statutory policy
              enforcement, absolute offset masking, independent 2nd-pass verification, and DPDP compliance reporting.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <Button
              variant="saffron"
              size="lg"
              onClick={handleAnalyzeClick}
              disabled={isAnalyzeDisabled || isProcessing}
              className={cn(
                'gap-2 font-mono text-xs sm:text-sm font-bold min-h-[44px] px-6 rounded-xl shadow-saffron-glow cursor-pointer',
                (isAnalyzeDisabled || isProcessing) && 'opacity-50 cursor-not-allowed shadow-none'
              )}
            >
              <Play className="w-4 h-4 fill-white" />
              <span>
                {isProcessing
                  ? 'Processing Pipeline...'
                  : inputMode === 'upload'
                  ? `Analyze Documents (${readyFilesCount})`
                  : 'Analyze & De-identify Text'}
              </span>
            </Button>
          </div>
        </div>

        {/* Policy Profile & Configuration Selector */}
        <div className="p-4 sm:p-5 rounded-2xl bg-card/60 border border-border/80 backdrop-blur-xl flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <Shield className="w-4 h-4 text-neon" />
              <span className="text-xs font-mono font-bold uppercase tracking-wider text-foreground">
                Active Governance Profile:
              </span>
            </div>
            <p className="text-xs text-muted-foreground font-body">
              {activeProfile.description} (Jurisdiction: {activeProfile.regulatoryJurisdiction})
            </p>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            {POLICY_PROFILES.map((prof) => (
              <button
                key={prof.id}
                type="button"
                onClick={() => setSelectedProfileId(prof.id)}
                className={cn(
                  'px-3 py-1.5 rounded-xl font-mono text-xs transition-all cursor-pointer border',
                  selectedProfileId === prof.id
                    ? 'bg-neon/15 border-neon text-neon font-bold shadow-neon-glow/20'
                    : 'bg-secondary/40 border-border/70 text-muted-foreground hover:text-foreground'
                )}
              >
                {prof.name.split(' (')[0]}
              </button>
            ))}
          </div>
        </div>

        {/* Rehearsal Benchmark Dataset Launcher */}
        <div className="p-5 rounded-2xl bg-card/60 border border-border/80 backdrop-blur-xl space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-muted-foreground font-mono uppercase tracking-wider">
              Quick Load Rehearsal Specimen Documents (Jury Benchmarks):
            </span>
            <span className="text-[11px] font-mono text-neon">5 Synthetic Test Fixtures</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3">
            {REHEARSAL_DOCUMENTS.map((doc) => (
              <button
                key={doc.id}
                type="button"
                onClick={() => handleLoadRehearsalDoc(doc)}
                className="flex flex-col p-3 text-left rounded-xl bg-secondary/40 border border-border/80 hover:border-neon/60 hover:bg-secondary/70 transition-all group cursor-pointer"
              >
                <div className="flex items-center gap-2 mb-1.5">
                  <div className="w-7 h-7 rounded-lg bg-card border border-border flex items-center justify-center text-neon group-hover:scale-105 transition-transform shrink-0">
                    <FileText className="w-3.5 h-3.5" />
                  </div>
                  <span className="text-xs font-bold text-foreground truncate">{doc.fileName}</span>
                </div>
                <p className="text-[11px] text-muted-foreground line-clamp-2 leading-snug">
                  {doc.description}
                </p>
                <div className="mt-2 text-[10px] font-mono text-neon/80">
                  {doc.answerKey.length} ground truth targets
                </div>
              </button>
            ))}
          </div>
        </div>

        {/* Input Mode Selector: Upload Document vs Direct Paste */}
        <div className="flex items-center gap-2 border-b border-border/80 pb-2">
          <button
            type="button"
            onClick={() => setInputMode('upload')}
            className={cn(
              'flex items-center gap-2 px-4 py-2 rounded-xl font-mono text-xs font-semibold transition-all cursor-pointer',
              inputMode === 'upload'
                ? 'bg-secondary text-foreground border border-border'
                : 'text-muted-foreground hover:text-foreground'
            )}
          >
            <UploadCloud className="w-4 h-4 text-neon" />
            Upload File (PDF, DOCX, XLSX, CSV, JSON, Images)
          </button>
          <button
            type="button"
            onClick={() => setInputMode('paste')}
            className={cn(
              'flex items-center gap-2 px-4 py-2 rounded-xl font-mono text-xs font-semibold transition-all cursor-pointer',
              inputMode === 'paste'
                ? 'bg-secondary text-foreground border border-border'
                : 'text-muted-foreground hover:text-foreground'
            )}
          >
            <ClipboardPaste className="w-4 h-4 text-saffron" />
            Direct Text / Unknown Document Paste
          </button>
        </div>

        {/* Direct Text Paste Input View */}
        {inputMode === 'paste' ? (
          <div className="p-5 rounded-2xl bg-card/60 border border-border/80 backdrop-blur-xl space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-muted-foreground font-mono uppercase tracking-wider">
                Paste Unknown Document Text:
              </span>
              <span className="text-xs font-mono text-muted-foreground">{pastedText.length} characters</span>
            </div>
            <textarea
              value={pastedText}
              onChange={(e) => setPastedText(e.target.value)}
              placeholder="Paste raw unstructured text here (e.g. bilingual loan contract, enterprise CSV, JSON config, grievance letter)..."
              rows={10}
              className="w-full p-4 rounded-xl bg-background/80 border border-border text-xs sm:text-sm font-mono text-foreground placeholder:text-muted-foreground focus:outline-none focus:border-neon transition-colors resize-y leading-relaxed"
            />
          </div>
        ) : (
          <>
            {/* Upload Zone */}
            <DocumentUploadZone onFilesSelected={handleFilesSelected} />

            {/* File Queue List */}
            <DocumentFileList
              files={fileQueue}
              onRemoveFile={handleRemoveFile}
              onPreviewFile={(item) => setSelectedPreviewItem(item)}
              onClearAll={handleClearAll}
            />
          </>
        )}

        {/* Low-Confidence Human Review Panel */}
        {showReviewPanel && (
          <JuryReviewPanel
            items={detectedEntities.filter((e) => e.needsReview)}
            onReviewDecision={handleReviewDecision}
            onAcceptAll={handleAcceptAllReview}
            onRejectAll={handleRejectAllReview}
            onApplyAndVerify={handleApplyReviewAndVerify}
          />
        )}

        {/* Execution Results Workspace (if pipeline has executed) */}
        {maskingResult && (
          <JuryExecutionWorkspace
            rawText={activeRawText}
            fileName={activeFileName}
            maskingResult={maskingResult}
            verificationReport={verificationReport}
            complianceReport={complianceReport}
            entities={detectedEntities}
            activeProfile={activeProfile}
            onOpenReportModal={() => setShowCertificateModal(true)}
            onReset={handleClearAll}
            onUpdateVerificationReport={(newRep) => setVerificationReport(newRep)}
          />
        )}

        {/* Preview Modal for extracted files */}
        <DocumentPreviewModal
          item={selectedPreviewItem}
          onClose={() => setSelectedPreviewItem(null)}
        />

        {/* Printable DPDP Compliance Certificate Modal */}
        {showCertificateModal && (
          <ComplianceReportModal
            report={complianceReport}
            onClose={() => setShowCertificateModal(false)}
          />
        )}
      </div>
    </div>
  );
};

export default DocumentIntelligencePage;
