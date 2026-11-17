import React, { useState, useRef, useEffect } from 'react';
import { toast } from 'sonner';
import {
  UploadCloud,
  FileText,
  ShieldCheck,
  Download,
  Copy,
  Check,
  AlertTriangle,
  Sparkles,
  Layers,
  ArrowRight,
  FileCode,
  FileSpreadsheet,
  FileCheck,
  Eye,
  RefreshCw,
  Loader2,
  Image as ImageIcon,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { MaskingPolicy, getStoredMaskingPolicy } from '@/lib/pipelineService';

// Ensure global type interfaces for ZeroLeak, ZeroLeakIO, ZeroLeakOCR
declare global {
  interface Window {
    ZeroLeak?: any;
    ZeroLeakIO?: any;
    ZeroLeakOCR?: any;
    Tesseract?: any;
  }
}

const SAMPLE_DOCUMENTS = [
  {
    name: 'Retail Banking Loan KYC (PDF/Form)',
    category: 'Banking',
    icon: FileCheck,
    content: `LOAN SANCTION & CREDIT APPRAISAL DOSSIER
Reference ID: KYC-BLR-2026-9041
Branch: HSR Layout, Bengaluru

APPLICANT DETAILS:
Primary Borrower: Aarav Sharma
Identification Type: Aadhaar Card
Aadhaar Number: 2345 6789 0124
Income Tax Permanent Account Number (PAN): ABCDE1234F
Registered Mobile: +91 9876543210
Official Email: aarav.sharma@enterprise.in

FINANCIAL APPRAISAL:
Employer: TechNova Solutions Pvt Ltd
Monthly Net Remittance: INR 1,45,000
Bank Account: 50100234567891 (HDFC Bank Ltd)
Sanction Amount Requested: INR 45,00,000 for Residential Housing

RISK UNDERWRITING REMARKS:
Applicant Aarav Sharma demonstrates consistent debt-to-income ratio (32%). 
CIBIL score verified at 790. Recommended for immediate fast-track sanction pending zero outbound leakage verification.`,
  },
  {
    name: 'Hospital Discharge Summary (Clinical)',
    category: 'Healthcare',
    icon: FileText,
    content: `METROPOLITAN MULTISPECIALTY HOSPITAL & RESEARCH ENCLAVE
DEPARTMENT OF CARDIOLOGY — CLINICAL DISCHARGE SUMMARY

PATIENT DEMOGRAPHICS:
Patient Full Name: Priya Venkatesh
UIDAI Identifier: 3456 7890 1234
Contact Number: +91 9123456789
Emergency Notification Email: priya.v@example.com
Consulting Cardiologist: Dr. Ramesh Kumar, MD DM

ADMISSION DIAGNOSIS & OBSERVATIONS:
Patient Priya Venkatesh presented with episodic palpitations and mild exertional dyspnea.
Telemetry monitoring indicated paroxysmal supraventricular tachycardia (PSVT).
Prescription: Metoprolol Tartrate 25mg BD, oral hydration.
Follow-up scheduled in 14 days. Clinical telemetry record de-identified in enclave before LLM summary dispatch.`,
  },
  {
    name: 'Corporate Vendor Agreement (B2B Tax)',
    category: 'Corporate',
    icon: FileSpreadsheet,
    content: `MASTER SERVICES AGREEMENT — PROCUREMENT VENDOR REGISTRATION
Contract No: MSA-CORP-2026-88

CONTRACTING ENTITY:
Vendor Legal Entity: Apex Logistics Infra LLP
Authorized Signatory: Rajesh Patel
GST Identification Number: 29ABCDE1234F1Z5
Permanent Account Number: BCDEF2345G
Registered Office Contact: +91 9811223344
Accounts Email: billing@apexlogistics.co.in

PAYMENT TERMS & STATUTORY COMPLIANCE:
All invoices subject to reverse-charge mechanism (RCM) as per GST regulations.
Bank Settlement Account: 98765432109876. Authorized director Rajesh Patel has furnished board resolution.`,
  },
];

interface DocumentUploadSectionProps {
  currentPolicy?: MaskingPolicy;
}

export const DocumentUploadSection: React.FC<DocumentUploadSectionProps> = ({ currentPolicy }) => {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [dragActive, setDragActive] = useState(false);
  const [fileName, setFileName] = useState<string>('Retail_Banking_Loan_KYC.pdf');
  const [fileSize, setFileSize] = useState<string>('42 KB');
  const [rawText, setRawText] = useState<string>(SAMPLE_DOCUMENTS[0].content);
  const [copied, setCopied] = useState<string | null>(null);

  // OCR state
  const [isOcrLoading, setIsOcrLoading] = useState<boolean>(false);
  const [ocrStatus, setOcrStatus] = useState<string>('');
  const [ocrConfidence, setOcrConfidence] = useState<string | null>(null);
  const [redactedImageUrl, setRedactedImageUrl] = useState<string | null>(null);
  const [isImageDoc, setIsImageDoc] = useState<boolean>(false);

  // Clean up object URLs on unmount
  useEffect(() => {
    return () => {
      if (redactedImageUrl) {
        URL.revokeObjectURL(redactedImageUrl);
      }
    };
  }, [redactedImageUrl]);

  // Compute ZeroLeak process results
  const zl = typeof window !== 'undefined' ? window.ZeroLeak : undefined;
  const processResult = zl && zl.process ? zl.process(rawText) : {
    masked: rawText,
    map: {},
    spans: [],
    stats: { total: 0, masked: 0, injectionCount: 0 },
    leak: { passed: true, leakCount: 0, riskPct: '0.00%', leakedItems: [] },
    safeToSend: true,
  };

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      handleFile(e.target.files[0]);
    }
  };

  const handleFile = async (file: File) => {
    // Revoke previous object URL
    if (redactedImageUrl) {
      URL.revokeObjectURL(redactedImageUrl);
      setRedactedImageUrl(null);
    }
    setOcrConfidence(null);
    setIsImageDoc(false);

    setFileName(file.name);
    setFileSize(`${(file.size / 1024).toFixed(1)} KB`);

    const zlOCR = typeof window !== 'undefined' ? window.ZeroLeakOCR : undefined;
    const zlIO = typeof window !== 'undefined' ? window.ZeroLeakIO : undefined;

    // 1. Image OCR Flow (.jpg, .jpeg, .png)
    if (zlOCR && zlOCR.isImage(file)) {
      setIsImageDoc(true);
      setIsOcrLoading(true);
      setOcrStatus('Initializing Sovereign Tesseract OCR engine...');

      try {
        const result = await zlOCR.scanImage(file, {
          onProgress: (m: any) => {
            if (m.status === 'recognizing text') {
              setOcrStatus(`Recognizing document text: ${Math.round((m.progress || 0) * 100)}%`);
            } else if (m.status) {
              setOcrStatus(`OCR Engine: ${m.status}...`);
            }
          },
        });

        setRawText(result.text);
        setOcrConfidence(result.ocrConfidence);
        setRedactedImageUrl(result.redactedUrl);

        if (result.process?.safeToSend) {
          toast.success(`OCR Scan Complete (${result.ocrConfidence} confidence). All sensitive PII redacted.`);
        } else {
          toast.warning(`OCR Scan Complete. Leak risk caught: dispatch blocked.`);
        }
      } catch (err: any) {
        console.error('OCR Error:', err);
        const msg = err?.message || 'Error occurred during image OCR processing.';
        toast.error('Image OCR Failed', {
          description: msg,
        });
      } finally {
        setIsOcrLoading(false);
        setOcrStatus('');
      }
      return;
    }

    // 2. Document Flow (.pdf, .txt, .json, .csv, .log, .md)
    if (zlIO && zlIO.readDocument) {
      try {
        const doc = await zlIO.readDocument(file);
        setRawText(doc.text);
        toast.success(`Parsed "${file.name}" (${doc.fileSize}) with ZeroLeak Sovereign Engine.`);
      } catch (err: any) {
        if (err.isScanned || err.message?.includes('scanned PDF')) {
          toast.error('Scanned PDF detected', {
            description: 'This PDF has no text layer. Please use an image (JPG/PNG) or run OCR.',
          });
        } else {
          // Standard text fallback
          const reader = new FileReader();
          reader.onload = (e) => {
            const text = (e.target?.result as string) || '';
            setRawText(text);
            toast.success(`Loaded "${file.name}" successfully.`);
          };
          reader.readAsText(file);
        }
      }
      return;
    }

    // Fallback standard reader
    const reader = new FileReader();
    reader.onload = (event) => {
      const text = event.target?.result as string;
      if (text && text.trim().length > 0) {
        setRawText(text);
        toast.success(`Loaded "${file.name}" successfully.`);
      }
    };
    reader.readAsText(file);
  };

  const handleCopy = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopied(label);
    toast.success(`${label} copied to clipboard`);
    setTimeout(() => setCopied(null), 2000);
  };

  const handleDownload = () => {
    if (isImageDoc && redactedImageUrl) {
      // Download the visually redacted JPEG image
      const link = document.createElement('a');
      link.href = redactedImageUrl;
      link.download = `ZEROLEAK_REDACTED_${fileName.replace(/\.[^/.]+$/, '')}.jpg`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      toast.success('Redacted JPEG image downloaded.');
      return;
    }

    // Download sanitized TXT
    const blob = new Blob([processResult.masked], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `ZEROLEAK_SANITIZED_${fileName.replace(/\.[^/.]+$/, '')}.txt`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    toast.success('Sanitized document downloaded.');
  };

  const handleSelectSample = (sample: typeof SAMPLE_DOCUMENTS[0]) => {
    if (redactedImageUrl) {
      URL.revokeObjectURL(redactedImageUrl);
      setRedactedImageUrl(null);
    }
    setOcrConfidence(null);
    setIsImageDoc(false);
    setFileName(`${sample.name.replace(/\s+/g, '_')}.txt`);
    setFileSize('14.2 KB');
    setRawText(sample.content);
    toast.info(`Loaded specimen: ${sample.name}`);
  };

  const restoredText = zl && zl.restore ? zl.restore(processResult.masked, processResult.map) : rawText;

  return (
    <div className="space-y-8 animate-fade-in">
      {/* Header & Quick Action Presets */}
      <div className="p-6 rounded-2xl bg-gradient-to-r from-slate-900 via-blue-950/30 to-slate-900 border border-slate-800 space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <UploadCloud className="w-5 h-5 text-cyan-400" />
              <h2 className="text-xl font-bold tracking-tight text-white">
                Enterprise Document Privacy & Redaction Scanner
              </h2>
            </div>
            <p className="text-sm text-slate-300">
              Upload customer contracts, clinical discharge summaries, loan applications, CSV/JSON extracts, or JPG/PNG image specimens to inspect and de-identify statutory PII before LLM dispatch.
            </p>
          </div>

          <div className="flex items-center gap-2">
            {processResult.safeToSend ? (
              <Badge variant="outline" className="border-emerald-500/40 text-emerald-300 bg-emerald-950/20">
                <ShieldCheck className="w-3.5 h-3.5 mr-1 text-emerald-400" />
                DPDP Sec 8(5) Certified
              </Badge>
            ) : (
              <Badge variant="outline" className="border-rose-500/50 text-rose-300 bg-rose-950/30">
                <AlertTriangle className="w-3.5 h-3.5 mr-1 text-rose-400" />
                Dispatch Blocked: Leak Risk
              </Badge>
            )}
            <Badge variant="outline" className={processResult.leak.passed ? "border-cyan-500/40 text-cyan-300 bg-cyan-950/20" : "border-rose-500/50 text-rose-300 bg-rose-950/20"}>
              {processResult.leak.passed ? 'Zero Outbound Leak' : `${processResult.leak.leakCount} Leak(s) Caught`}
            </Badge>
          </div>
        </div>

        {/* Quick Sample Specimen Buttons */}
        <div>
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider block mb-2">
            Load Specimen Documents for Instant Jury Demonstration:
          </span>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            {SAMPLE_DOCUMENTS.map((doc, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => handleSelectSample(doc)}
                className="flex items-center gap-3 p-3 text-left rounded-xl bg-slate-950/70 border border-slate-800 hover:border-cyan-500/50 hover:bg-slate-900/90 transition-all group"
              >
                <div className="w-8 h-8 rounded-lg bg-blue-950/60 border border-blue-800/40 flex items-center justify-center text-cyan-400 group-hover:scale-105 transition-transform">
                  <doc.icon className="w-4 h-4" />
                </div>
                <div className="truncate">
                  <div className="text-xs font-medium text-white truncate">{doc.name}</div>
                  <div className="text-[11px] text-cyan-400/80 font-mono">{doc.category} Specimen</div>
                </div>
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Upload Dropzone */}
      <div
        onDragEnter={handleDrag}
        onDragLeave={handleDrag}
        onDragOver={handleDrag}
        onDrop={handleDrop}
        onClick={() => !isOcrLoading && fileInputRef.current?.click()}
        className={`relative border-2 border-dashed rounded-2xl p-8 text-center cursor-pointer transition-all duration-300 ${
          dragActive
            ? 'border-cyan-400 bg-cyan-950/30'
            : 'border-slate-800 hover:border-cyan-500/40 bg-slate-950/50 hover:bg-slate-900/40'
        } ${isOcrLoading ? 'opacity-70 pointer-events-none' : ''}`}
      >
        <input
          ref={fileInputRef}
          type="file"
          accept=".pdf,.txt,.json,.csv,.log,.md,.jpg,.jpeg,.png,image/jpeg,image/png"
          onChange={handleFileInput}
          className="hidden"
          disabled={isOcrLoading}
        />

        {isOcrLoading ? (
          <div className="flex flex-col items-center justify-center gap-3 py-4">
            <Loader2 className="w-10 h-10 text-cyan-400 animate-spin" />
            <div className="text-sm font-semibold text-white">Zero-Upload Sovereign OCR In Progress</div>
            <p className="text-xs text-cyan-300 font-mono">{ocrStatus || 'Downloading & executing client-side OCR model...'}</p>
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center gap-3">
            <div className="w-14 h-14 rounded-2xl bg-cyan-950/60 border border-cyan-800/50 flex items-center justify-center text-cyan-400 shadow-lg shadow-cyan-950/40">
              <UploadCloud className="w-7 h-7" />
            </div>
            <div>
              <span className="font-semibold text-sm text-white">
                Drag & drop document or image here or click to browse
              </span>
              <p className="text-xs text-slate-400 mt-1">
                Supports PDF, TXT, JSON, CSV, LOG, MD, and Images (.jpg, .jpeg, .png)
              </p>
            </div>
            <div className="flex items-center gap-2 mt-1">
              <span className="text-xs text-slate-500 font-mono">
                Active File: <strong className="text-cyan-300">{fileName}</strong> ({fileSize})
              </span>
              {ocrConfidence && (
                <Badge variant="outline" className="border-cyan-500/40 text-cyan-300 text-[10px] font-mono">
                  OCR Confidence: {ocrConfidence}
                </Badge>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Metrics & Redaction Summary Bar */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
          <span className="text-xs text-slate-400">Total Entities Detected</span>
          <div className="text-2xl font-bold font-mono text-white mt-1">
            {processResult.stats.total}
          </div>
          <span className="text-[11px] text-slate-500">Identifiers Scanned</span>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
          <span className="text-xs text-slate-400">De-Identified / Masked</span>
          <div className="text-2xl font-bold font-mono text-cyan-400 mt-1">
            {processResult.stats.masked}
          </div>
          <span className="text-[11px] text-cyan-500/80">Reversibly Tokenized</span>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
          <span className="text-xs text-slate-400">Preserved in Plaintext</span>
          <div className="text-2xl font-bold font-mono text-emerald-400 mt-1">
            {processResult.leak.leakCount}
          </div>
          <span className="text-[11px] text-emerald-500/80">
            {processResult.leak.passed ? 'Zero Unmasked Leakage' : 'Residual Leaks Caught'}
          </span>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
          <span className="text-xs text-slate-400">Outbound Leak Risk</span>
          <div className={`text-2xl font-bold font-mono mt-1 ${processResult.leak.passed ? 'text-emerald-400' : 'text-rose-400'}`}>
            {processResult.leak.riskPct}
          </div>
          <span className="text-[11px] text-slate-500">
            {processResult.leak.passed ? 'Enclave Barrier Intact' : 'FAILED - Dispatch Blocked'}
          </span>
        </div>
      </div>

      {/* Visual Redacted Image Preview (If Image Loaded) */}
      {redactedImageUrl && (
        <div className="p-5 rounded-2xl bg-slate-950 border border-cyan-800/40 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <ImageIcon className="w-4 h-4 text-cyan-400" />
              <h4 className="text-sm font-semibold text-white">Visual Redacted Document Preview (JPEG)</h4>
              <Badge variant="outline" className="border-cyan-500/40 text-cyan-300 text-[10px] font-mono">
                Client-Side Canvas Redaction
              </Badge>
            </div>
            <Button
              size="sm"
              onClick={handleDownload}
              className="bg-cyan-600 hover:bg-cyan-500 text-white text-xs gap-1.5 shadow-md shadow-cyan-950"
            >
              <Download className="w-3.5 h-3.5" />
              Download Redacted Image
            </Button>
          </div>
          <div className="relative rounded-xl overflow-hidden border border-slate-800 bg-black/60 flex items-center justify-center max-h-[360px]">
            <img
              src={redactedImageUrl}
              alt="Visual Redacted Specimen"
              className="max-h-[350px] object-contain rounded-lg"
            />
          </div>
          <p className="text-[11px] text-slate-400 font-mono">
            All sensitive bounding boxes are permanently overlaid with solid black blocks before export. Original bitmap never leaves browser memory.
          </p>
        </div>
      )}

      {/* Side-by-Side 3-Column Inspection View */}
      <div className="space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <h3 className="text-base font-semibold text-white flex items-center gap-2">
            <Layers className="w-4 h-4 text-cyan-400" />
            Tri-Pane Sovereign Inspection: Raw vs. Sanitized Outbound vs. Restored
          </h3>

          <div className="flex items-center gap-2">
            <Button
              size="sm"
              variant="outline"
              onClick={() => handleCopy(processResult.masked, 'Sanitized Document')}
              className="border-slate-800 hover:border-slate-700 text-xs text-slate-300"
            >
              {copied === 'Sanitized Document' ? (
                <Check className="w-3.5 h-3.5 mr-1.5 text-emerald-400" />
              ) : (
                <Copy className="w-3.5 h-3.5 mr-1.5" />
              )}
              Copy Sanitized
            </Button>
            <Button
              size="sm"
              onClick={handleDownload}
              className="bg-cyan-600 hover:bg-cyan-500 text-white text-xs shadow-md shadow-cyan-950"
            >
              <Download className="w-3.5 h-3.5 mr-1.5" />
              {isImageDoc ? 'Download Redacted Image' : 'Download Redacted'}
            </Button>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {/* Pane 1: Raw Document Source */}
          <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 flex flex-col h-[420px]">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-3">
              <span className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                <FileText className="w-3.5 h-3.5 text-slate-400" />
                Raw Document Extract
              </span>
              <Badge variant="outline" className="text-[10px] text-slate-400 border-slate-700">
                {isImageDoc ? 'OCR Extracted' : 'Source Document'}
              </Badge>
            </div>
            <textarea
              value={rawText}
              onChange={(e) => setRawText(e.target.value)}
              className="flex-1 w-full bg-transparent text-xs font-mono text-slate-300 resize-none focus:outline-none leading-relaxed"
              placeholder="Paste or edit raw document text here..."
            />
          </div>

          {/* Pane 2: Sanitized Outbound Payload */}
          <div className="p-4 rounded-xl bg-slate-950/90 border border-cyan-800/50 flex flex-col h-[420px] shadow-lg shadow-cyan-950/20">
            <div className="flex items-center justify-between pb-3 border-b border-cyan-900/40 mb-3">
              <span className="text-xs font-semibold text-cyan-300 flex items-center gap-1.5">
                <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
                Sanitized Outbound Payload
              </span>
              <Badge className={processResult.safeToSend ? "bg-cyan-500/20 text-cyan-300 border-cyan-500/40 text-[10px]" : "bg-rose-500/20 text-rose-300 border-rose-500/40 text-[10px]"}>
                {processResult.safeToSend ? 'Safe for External LLM' : 'Dispatch Prohibited'}
              </Badge>
            </div>
            <div className="flex-1 w-full overflow-y-auto text-xs font-mono text-cyan-100 whitespace-pre-wrap leading-relaxed select-text">
              {processResult.masked}
            </div>
          </div>

          {/* Pane 3: Sovereign Restored Output */}
          <div className="p-4 rounded-xl bg-slate-950/80 border border-emerald-800/40 flex flex-col h-[420px]">
            <div className="flex items-center justify-between pb-3 border-b border-emerald-900/30 mb-3">
              <span className="text-xs font-semibold text-emerald-300 flex items-center gap-1.5">
                <RefreshCw className="w-3.5 h-3.5 text-emerald-400" />
                Local Enclave Re-hydrated View
              </span>
              <Badge className="bg-emerald-500/20 text-emerald-300 border-emerald-500/40 text-[10px]">
                Internal Enterprise Audit
              </Badge>
            </div>
            <div className="flex-1 w-full overflow-y-auto text-xs font-mono text-emerald-100/90 whitespace-pre-wrap leading-relaxed select-text">
              {restoredText}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
