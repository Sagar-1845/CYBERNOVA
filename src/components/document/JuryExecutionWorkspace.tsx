import React, { useState } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Download,
  FileCheck2,
  Lock,
  Eye,
  FileText,
  KeyRound,
  RotateCcw,
  CheckCircle2,
  Layers,
  Sparkles,
  Info,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { MaskingResult } from '@/lib/masking/offsetMasker';
import { VerificationReport, testOriginalDocumentLeak } from '@/lib/verification/independentVerifier';
import { ComplianceReport, downloadComplianceReportJSON } from '@/lib/compliance/reportGenerator';
import { DetectedEntityItem } from '@/lib/detection/detector';
import { PolicyProfile } from '@/lib/policy/policyEngine';
import { toast } from 'sonner';
import { cn } from '@/lib/utils';

interface JuryExecutionWorkspaceProps {
  rawText: string;
  fileName: string;
  maskingResult: MaskingResult | null;
  verificationReport: VerificationReport;
  complianceReport: ComplianceReport | null;
  entities: DetectedEntityItem[];
  activeProfile: PolicyProfile;
  onOpenReportModal: () => void;
  onReset: () => void;
  onUpdateVerificationReport: (report: VerificationReport) => void;
}

export const JuryExecutionWorkspace: React.FC<JuryExecutionWorkspaceProps> = ({
  rawText,
  fileName,
  maskingResult,
  verificationReport,
  complianceReport,
  entities,
  activeProfile,
  onOpenReportModal,
  onReset,
  onUpdateVerificationReport,
}) => {
  const [activeTab, setActiveTab] = useState<'comparison' | 'vault' | 'entities'>('comparison');
  const [testingRawLeak, setTestingRawLeak] = useState(false);

  const isSafe = verificationReport.status === 'VERIFIED SAFE';
  const isLeak = verificationReport.status === 'LEAK DETECTED';

  const handleDownloadSanitizedTXT = () => {
    if (!maskingResult || !isSafe) {
      toast.error('Download Blocked by Safety Invariant', {
        description: 'Sanitized document export is strictly prohibited unless verification status is VERIFIED SAFE.',
      });
      return;
    }

    const blob = new Blob([maskingResult.maskedText], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `SANITIZED_${fileName.replace(/\.[^/.]+$/, '')}.txt`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success('Sanitized document downloaded successfully.');
  };

  const handleRunLeakTestOnOriginal = () => {
    setTestingRawLeak(true);
    const leakReport = testOriginalDocumentLeak(rawText);
    onUpdateVerificationReport(leakReport);
    toast.error('Invariant Proof: Leak Detected on Original Document', {
      description: `Unmasked input produced status LEAK DETECTED (${leakReport.totalLeaksCount} exposed sensitive items intercepted).`,
    });
  };

  return (
    <div className="space-y-6 animate-fade-in">
      {/* 1. Independent Verification Status Banner */}
      <div
        className={cn(
          'p-5 sm:p-6 rounded-3xl border-2 backdrop-blur-xl transition-all shadow-xl space-y-4',
          isSafe && 'bg-emerald-950/20 border-emerald-500/50 shadow-emerald-950/20',
          isLeak && 'bg-rose-950/20 border-rose-500/60 shadow-rose-950/20',
          !isSafe && !isLeak && 'bg-card/70 border-border/80'
        )}
      >
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-start gap-4">
            <div
              className={cn(
                'w-14 h-14 rounded-2xl flex items-center justify-center shrink-0 border',
                isSafe && 'bg-emerald-500/20 border-emerald-500/40 text-emerald-400',
                isLeak && 'bg-rose-500/20 border-rose-500/40 text-rose-400',
                !isSafe && !isLeak && 'bg-muted/40 border-border text-muted-foreground'
              )}
            >
              {isSafe ? <ShieldCheck className="w-8 h-8" /> : <ShieldAlert className="w-8 h-8" />}
            </div>

            <div className="space-y-1">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-[11px] font-mono tracking-widest uppercase font-bold text-muted-foreground">
                  SECOND-PASS INDEPENDENT VERIFIER
                </span>
                <Badge
                  variant="outline"
                  className={cn(
                    'font-mono font-bold text-xs px-2.5 py-0.5',
                    isSafe && 'border-emerald-400 text-emerald-300 bg-emerald-950/40',
                    isLeak && 'border-rose-400 text-rose-300 bg-rose-950/40',
                    !isSafe && !isLeak && 'border-border text-muted-foreground'
                  )}
                >
                  {verificationReport.status}
                </Badge>
                {maskingResult?.invariantVerified && (
                  <Badge variant="outline" className="border-neon/40 text-neon font-mono text-[10px]">
                    Offset Invariant 100% Verified
                  </Badge>
                )}
              </div>
              <h3 className="text-xl font-extrabold tracking-tight text-foreground">
                {isSafe
                  ? 'Certified Safe for Outbound AI Dispatch & Download'
                  : isLeak
                  ? 'Leak Intercepted — Outbound Transmission Strictly Blocked'
                  : 'Independent Verification Pending or Failed'}
              </h3>
              <p className="text-xs text-muted-foreground font-body max-w-3xl leading-relaxed">
                {verificationReport.summary}
              </p>
            </div>
          </div>

          {/* Test Invariant Proof Button */}
          <div className="flex flex-col gap-2 shrink-0 self-start md:self-center">
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={handleRunLeakTestOnOriginal}
              className="text-xs font-mono h-9 border-rose-500/40 text-rose-300 hover:bg-rose-500/20"
            >
              <ShieldAlert className="w-3.5 h-3.5 mr-1" />
              Test Invariant: Verify Unmasked Raw
            </Button>
            <span className="text-[10px] font-mono text-muted-foreground text-center">
              Proves original doc triggers LEAK DETECTED
            </span>
          </div>
        </div>

        {/* Leaks breakdown if any */}
        {verificationReport.leaks.length > 0 && (
          <div className="p-3.5 rounded-xl bg-rose-950/30 border border-rose-500/40 space-y-2 text-xs font-mono text-rose-300">
            <div className="font-bold flex items-center gap-1.5">
              <AlertTriangle className="w-4 h-4 text-rose-400" />
              Intercepted Leak Findings ({verificationReport.leaks.length}):
            </div>
            <ul className="list-disc list-inside space-y-1 text-[11px] text-rose-200/80">
              {verificationReport.leaks.map((leak, idx) => (
                <li key={idx}>
                  [{leak.type}] "{leak.snippet}" ({leak.detectionSource}) — {leak.description}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>

      {/* 2. Primary Actions Bar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 p-4 rounded-2xl bg-card/60 border border-border/80 backdrop-blur-xl">
        <div className="flex items-center gap-2 flex-wrap">
          <Button
            type="button"
            variant="saffron"
            size="sm"
            onClick={handleDownloadSanitizedTXT}
            disabled={!isSafe}
            className={cn(
              'font-mono text-xs font-bold h-9 px-4',
              !isSafe && 'opacity-50 cursor-not-allowed'
            )}
          >
            <Download className="w-3.5 h-3.5 mr-1" />
            Download Sanitized Document (TXT)
          </Button>

          {complianceReport && (
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => downloadComplianceReportJSON(complianceReport)}
              className="font-mono text-xs h-9 border-border hover:border-neon"
            >
              <Download className="w-3.5 h-3.5 mr-1" />
              Download Report (JSON)
            </Button>
          )}

          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={onOpenReportModal}
            className="font-mono text-xs h-9 border-neon/40 text-neon hover:bg-neon/10"
          >
            <FileCheck2 className="w-3.5 h-3.5 mr-1" />
            View Printable Compliance Certificate
          </Button>
        </div>

        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={onReset}
          className="font-mono text-xs h-9 text-muted-foreground hover:text-foreground self-end sm:self-auto"
        >
          <RotateCcw className="w-3.5 h-3.5 mr-1" />
          Clear & Reset Memory
        </Button>
      </div>

      {/* 3. Tabbed Details Inspector */}
      <div className="space-y-4">
        <div className="flex items-center gap-2 border-b border-border/80 pb-2">
          <button
            type="button"
            onClick={() => setActiveTab('comparison')}
            className={cn(
              'px-3.5 py-1.5 rounded-lg font-mono text-xs font-semibold transition-all cursor-pointer',
              activeTab === 'comparison'
                ? 'bg-secondary text-foreground border border-border'
                : 'text-muted-foreground hover:text-foreground'
            )}
          >
            Side-by-Side Text Comparison
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('vault')}
            className={cn(
              'px-3.5 py-1.5 rounded-lg font-mono text-xs font-semibold transition-all cursor-pointer',
              activeTab === 'vault'
                ? 'bg-secondary text-foreground border border-border'
                : 'text-muted-foreground hover:text-foreground'
            )}
          >
            Token Vault ({Object.keys(maskingResult?.vaultMapping || {}).length})
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('entities')}
            className={cn(
              'px-3.5 py-1.5 rounded-lg font-mono text-xs font-semibold transition-all cursor-pointer',
              activeTab === 'entities'
                ? 'bg-secondary text-foreground border border-border'
                : 'text-muted-foreground hover:text-foreground'
            )}
          >
            Detected Entities ({entities.length})
          </button>
        </div>

        {/* Tab 1: Side-by-Side Comparison */}
        {activeTab === 'comparison' && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-4 rounded-2xl bg-card/50 border border-border/80 space-y-2">
              <div className="flex items-center justify-between text-xs font-mono text-muted-foreground">
                <span className="font-bold uppercase tracking-wider text-foreground">Original Document (Raw)</span>
                <span>{rawText.length} chars</span>
              </div>
              <pre className="p-3.5 rounded-xl bg-background/80 border border-border text-xs font-mono text-muted-foreground overflow-x-auto whitespace-pre-wrap max-h-[460px] leading-relaxed">
                {rawText}
              </pre>
            </div>

            <div className="p-4 rounded-2xl bg-card/50 border border-border/80 space-y-2">
              <div className="flex items-center justify-between text-xs font-mono text-muted-foreground">
                <span className="font-bold uppercase tracking-wider text-neon">Sanitized Document (Masked TXT)</span>
                <span>{maskingResult?.maskedText.length || 0} chars</span>
              </div>
              <pre className="p-3.5 rounded-xl bg-background/80 border border-border text-xs font-mono text-foreground overflow-x-auto whitespace-pre-wrap max-h-[460px] leading-relaxed">
                {maskingResult?.maskedText}
              </pre>
            </div>
          </div>
        )}

        {/* Tab 2: Token Vault */}
        {activeTab === 'vault' && maskingResult && (
          <div className="p-5 rounded-2xl bg-card/50 border border-border/80 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-border/60 pb-3">
              <div>
                <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-foreground">
                  Zero-Persistence Sovereign Token Vault
                </h4>
                <p className="text-xs text-muted-foreground font-body mt-0.5">
                  Consistent bidirectional tokens mapped in client ephemeral memory. High-risk cloud credentials and secrets are excluded.
                </p>
              </div>
              <Badge variant="outline" className="border-emerald-500/40 text-emerald-300 font-mono text-[10px] self-start sm:self-auto">
                Secrets Excluded from Vault
              </Badge>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-border text-muted-foreground">
                    <th className="py-2 pr-4">Surrogate Token</th>
                    <th className="py-2 pr-4">Protected Original Value (Ephemeral)</th>
                    <th className="py-2 pr-4">Category</th>
                    <th className="py-2">Storage Horizon</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/40">
                  {Object.entries(maskingResult.vaultMapping).map(([token, orig]) => (
                    <tr key={token} className="hover:bg-muted/20">
                      <td className="py-2.5 pr-4 font-bold text-neon">{token}</td>
                      <td className="py-2.5 pr-4 text-foreground font-mono">{orig}</td>
                      <td className="py-2.5 pr-4 text-muted-foreground">{token.replace(/[\[\]0-9_]/g, '')}</td>
                      <td className="py-2.5 text-muted-foreground text-[11px]">10-minute client horizon</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {maskingResult.secretsRedacted.length > 0 && (
              <div className="p-3 rounded-xl bg-rose-950/20 border border-rose-500/40 text-xs font-mono text-rose-300">
                <span className="font-bold">Irreversibly Redacted Secrets ({maskingResult.secretsRedacted.length}):</span>{' '}
                {maskingResult.secretsRedacted.map((s) => s.type).join(', ')} (Permanently purged from vault).
              </div>
            )}
          </div>
        )}

        {/* Tab 3: Detected Entities Table */}
        {activeTab === 'entities' && (
          <div className="p-5 rounded-2xl bg-card/50 border border-border/80 space-y-4">
            <div className="flex items-center justify-between border-b border-border/60 pb-3">
              <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-foreground">
                Detected Entity Registry & Statutory Rule Mapping
              </h4>
              <Badge variant="outline" className="border-neon/40 text-neon font-mono text-[10px]">
                {entities.length} Detected Items
              </Badge>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-border text-muted-foreground">
                    <th className="py-2 pr-3">Type</th>
                    <th className="py-2 pr-3">Location (Offsets & Line)</th>
                    <th className="py-2 pr-3">Confidence</th>
                    <th className="py-2 pr-3">Sensitivity</th>
                    <th className="py-2 pr-3">Action</th>
                    <th className="py-2 pr-3">Statutory Scope</th>
                    <th className="py-2 pr-3">Rule IDs</th>
                    <th className="py-2">Explanation</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/40">
                  {entities.map((ent) => (
                    <tr key={ent.id} className="hover:bg-muted/20">
                      <td className="py-2.5 pr-3 font-semibold text-foreground">{ent.type}</td>
                      <td className="py-2.5 pr-3 text-muted-foreground">
                        [{ent.location.start}..{ent.location.end}] (L{ent.location.line ?? 1})
                      </td>
                      <td className="py-2.5 pr-3">
                        <span
                          className={cn(
                            'font-bold',
                            ent.confidence >= 0.8 ? 'text-emerald-400' : 'text-amber-400'
                          )}
                        >
                          {(ent.confidence * 100).toFixed(0)}%
                        </span>
                      </td>
                      <td className="py-2.5 pr-3">
                        <Badge
                          variant="outline"
                          className={cn(
                            'text-[10px]',
                            ent.sensitivity === 'CRITICAL' && 'border-rose-500 text-rose-400',
                            ent.sensitivity === 'HIGH' && 'border-amber-500 text-amber-400',
                            ent.sensitivity === 'MEDIUM' && 'border-blue-500 text-blue-400',
                            ent.sensitivity === 'LOW' && 'border-muted text-muted-foreground'
                          )}
                        >
                          {ent.sensitivity}
                        </Badge>
                      </td>
                      <td className="py-2.5 pr-3">
                        <Badge variant="outline" className="text-[10px] border-neon/50 text-neon">
                          {ent.action}
                        </Badge>
                      </td>
                      <td className="py-2.5 pr-3">
                        <Badge
                          variant="outline"
                          className={cn(
                            'text-[10px]',
                            ent.scope === 'DPDP personal data'
                              ? 'border-saffron/50 text-saffron'
                              : 'border-purple-500/50 text-purple-400'
                          )}
                        >
                          {ent.scope}
                        </Badge>
                      </td>
                      <td className="py-2.5 pr-3 text-muted-foreground text-[11px]">
                        {ent.ruleIds.join(', ')}
                      </td>
                      <td className="py-2.5 text-muted-foreground text-[11px] max-w-xs truncate">
                        {ent.explanation}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
