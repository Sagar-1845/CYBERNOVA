import React from 'react';
import {
  FileCheck2,
  Printer,
  Download,
  X,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Scale,
  Calendar,
  CheckCircle2,
  FileText,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { ComplianceReport, downloadComplianceReportJSON } from '@/lib/compliance/reportGenerator';
import { cn } from '@/lib/utils';

interface ComplianceReportModalProps {
  report: ComplianceReport | null;
  onClose: () => void;
}

export const ComplianceReportModal: React.FC<ComplianceReportModalProps> = ({ report, onClose }) => {
  if (!report) return null;

  const handlePrint = () => {
    window.print();
  };

  const isSafe = report.verificationStatus === 'VERIFIED SAFE';

  return (
    <div
      role="dialog"
      aria-modal="true"
      className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-6 bg-black/80 backdrop-blur-md overflow-y-auto animate-fade-in"
    >
      <div className="w-full max-w-4xl rounded-3xl bg-[#070d24] border border-border/90 shadow-2xl overflow-hidden flex flex-col max-h-[92vh]">
        {/* Modal Top Bar (Non-printed controls) */}
        <div className="flex items-center justify-between p-4 sm:p-5 border-b border-border/80 bg-card/60 shrink-0 print:hidden">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-neon" />
            <span className="font-mono text-xs sm:text-sm font-bold text-foreground">
              DPDP STATUTORY COMPLIANCE CERTIFICATE
            </span>
            <Badge variant="outline" className="border-neon/40 text-neon font-mono text-[10px]">
              AUDIT READY
            </Badge>
          </div>

          <div className="flex items-center gap-2">
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={handlePrint}
              className="text-xs font-mono h-8 border-border hover:border-neon"
            >
              <Printer className="w-3.5 h-3.5 mr-1" /> Print
            </Button>
            <Button
              type="button"
              variant="saffron"
              size="sm"
              onClick={() => downloadComplianceReportJSON(report)}
              className="text-xs font-mono h-8"
            >
              <Download className="w-3.5 h-3.5 mr-1" /> Download JSON
            </Button>
            <button
              type="button"
              onClick={onClose}
              className="p-1.5 rounded-lg text-muted-foreground hover:text-foreground hover:bg-secondary/60 transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Printable Certificate Body */}
        <div className="p-6 sm:p-8 overflow-y-auto space-y-6 text-foreground font-body print:p-0 print:text-black">
          {/* Certificate Header */}
          <div className="border-b-2 border-border/80 pb-5 space-y-2">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div>
                <div className="text-[11px] font-mono tracking-widest text-neon uppercase font-bold">
                  ZEROLEAK AI // STATUTORY ATTESTATION RECORD
                </div>
                <h2 className="text-2xl font-extrabold tracking-tight mt-0.5">
                  DPDP De-Identification & AI Governance Report
                </h2>
              </div>
              <div className="text-right">
                <div className="font-mono text-xs text-muted-foreground">Document ID: {report.documentId}</div>
                <div className="font-mono text-[11px] text-muted-foreground">
                  Timestamp: {new Date(report.generatedAt).toLocaleString()}
                </div>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-3 text-xs font-mono">
              <div className="p-2.5 rounded-lg bg-card/60 border border-border/60">
                <span className="text-muted-foreground block text-[10px]">TARGET DOCUMENT</span>
                <span className="font-semibold text-foreground truncate block">{report.fileName}</span>
              </div>
              <div className="p-2.5 rounded-lg bg-card/60 border border-border/60">
                <span className="text-muted-foreground block text-[10px]">POLICY PROFILE</span>
                <span className="font-semibold text-neon block">{report.profile.name}</span>
              </div>
              <div className="p-2.5 rounded-lg bg-card/60 border border-border/60">
                <span className="text-muted-foreground block text-[10px]">RETENTION POLICY</span>
                <span className="font-semibold text-foreground block">{report.profile.retentionSetting}</span>
              </div>
            </div>
          </div>

          {/* Verification Status & Dispatch Decision Banner */}
          <div
            className={cn(
              'p-4 rounded-2xl border-2 flex flex-col sm:flex-row sm:items-center justify-between gap-3',
              isSafe
                ? 'bg-emerald-950/20 border-emerald-500/50 text-emerald-300'
                : 'bg-rose-950/20 border-rose-500/50 text-rose-300'
            )}
          >
            <div className="flex items-center gap-3">
              {isSafe ? <ShieldCheck className="w-8 h-8 text-emerald-400 shrink-0" /> : <ShieldAlert className="w-8 h-8 text-rose-400 shrink-0" />}
              <div>
                <div className="font-mono text-xs tracking-wider uppercase font-bold">
                  SECOND-PASS INDEPENDENT VERIFICATION: {report.verificationStatus}
                </div>
                <div className="text-xs mt-0.5 font-body leading-relaxed opacity-90">
                  {report.executiveSummary}
                </div>
              </div>
            </div>
            <Badge
              variant="outline"
              className={cn(
                'font-mono text-xs px-3 py-1 shrink-0 self-start sm:self-auto',
                isSafe ? 'border-emerald-400 text-emerald-300 bg-emerald-950/40' : 'border-rose-400 text-rose-300 bg-rose-950/40'
              )}
            >
              DISPATCH: {report.dispatchDecision}
            </Badge>
          </div>

          {/* Entity Counts & Actions Breakdown */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-4 rounded-xl bg-card/50 border border-border/80 space-y-3">
              <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-muted-foreground">
                Detected Entity Volume by Class
              </h4>
              <div className="space-y-1.5">
                {Object.entries(report.entityCountsByType).length === 0 ? (
                  <div className="text-xs text-muted-foreground italic">Zero sensitive entities detected (Clean Document Baseline).</div>
                ) : (
                  Object.entries(report.entityCountsByType).map(([type, count]) => (
                    <div key={type} className="flex items-center justify-between text-xs py-1 border-b border-border/40 font-mono">
                      <span>{type}</span>
                      <span className="font-bold px-2 py-0.5 rounded bg-secondary/80 text-foreground">{count}</span>
                    </div>
                  ))
                )}
              </div>
            </div>

            <div className="p-4 rounded-xl bg-card/50 border border-border/80 space-y-3">
              <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-muted-foreground">
                De-Identification Actions Applied
              </h4>
              <div className="space-y-2">
                {report.actionsApplied.map((act) => (
                  <div key={act.action} className="text-xs space-y-0.5">
                    <div className="flex items-center justify-between font-mono">
                      <span className="font-bold text-neon">{act.action}</span>
                      <span className="font-semibold text-foreground">{act.count} entity instances</span>
                    </div>
                    <div className="text-[11px] text-muted-foreground leading-snug">{act.description}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Statutory Rules Triggered Table */}
          <div className="p-4 rounded-xl bg-card/50 border border-border/80 space-y-3">
            <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-muted-foreground flex items-center justify-between">
              <span>Statutory Rules Triggered & Legal Governance</span>
              <span className="text-[11px] font-normal text-neon">{report.rulesTriggered.length} Statutory Safeguards</span>
            </h4>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-border/60 text-muted-foreground">
                    <th className="py-2 pr-3">Rule Identifier</th>
                    <th className="py-2 pr-3">Section / Mandate</th>
                    <th className="py-2 pr-3">Status</th>
                    <th className="py-2 pr-3">Effective Status</th>
                    <th className="py-2 text-right">Items</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/30">
                  {report.rulesTriggered.map((rule) => (
                    <tr key={rule.ruleId} className="hover:bg-muted/20">
                      <td className="py-2.5 pr-3 font-semibold text-foreground">{rule.ruleId}</td>
                      <td className="py-2.5 pr-3 text-muted-foreground">{rule.regulatorySection}</td>
                      <td className="py-2.5 pr-3">
                        <Badge
                          variant="outline"
                          className={cn(
                            'text-[10px] px-2 py-0',
                            rule.status === 'VERIFIED'
                              ? 'border-emerald-500/50 text-emerald-400 bg-emerald-950/20'
                              : 'border-amber-500/50 text-amber-400 bg-amber-950/20'
                          )}
                        >
                          {rule.status}
                        </Badge>
                      </td>
                      <td className="py-2.5 pr-3 text-muted-foreground text-[11px]">{rule.effectiveDateStatus}</td>
                      <td className="py-2.5 text-right font-bold text-foreground">{rule.entityCount}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Items Reviewed Log (if any) */}
          {report.itemsReviewed.length > 0 && (
            <div className="p-4 rounded-xl bg-card/50 border border-border/80 space-y-2">
              <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-muted-foreground">
                Human Review Audit Log ({report.itemsReviewed.length} decisions recorded)
              </h4>
              <div className="space-y-1.5 max-h-40 overflow-y-auto pr-1">
                {report.itemsReviewed.map((rev) => (
                  <div key={rev.entityId} className="flex items-center justify-between text-xs py-1 border-b border-border/30 font-mono">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-foreground">[{rev.type}]</span>
                      <span className="text-muted-foreground">{rev.explanation}</span>
                    </div>
                    <Badge
                      variant="outline"
                      className={cn(
                        'text-[10px]',
                        rev.decision === 'ACCEPTED' ? 'border-emerald-500 text-emerald-400' : 'border-rose-500 text-rose-400'
                      )}
                    >
                      {rev.decision}
                    </Badge>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Residual Risk Assessment */}
          <div className="p-4 rounded-xl bg-card/40 border border-border/70 space-y-2 text-xs">
            <div className="flex items-center justify-between font-mono">
              <span className="font-bold text-foreground uppercase tracking-wider">Residual Exposure Risk Level:</span>
              <Badge
                variant="outline"
                className={cn(
                  'font-mono font-bold',
                  report.residualRisks.riskLevel === 'ZERO'
                    ? 'border-emerald-400 text-emerald-400 bg-emerald-950/30'
                    : report.residualRisks.riskLevel === 'LOW'
                    ? 'border-blue-400 text-blue-400 bg-blue-950/30'
                    : report.residualRisks.riskLevel === 'MEDIUM'
                    ? 'border-amber-400 text-amber-400 bg-amber-950/30'
                    : 'border-rose-400 text-rose-400 bg-rose-950/30'
                )}
              >
                {report.residualRisks.riskLevel} RESIDUAL RISK
              </Badge>
            </div>
            <div className="text-muted-foreground">{report.residualRisks.summary}</div>
            <ul className="list-disc list-inside space-y-0.5 text-[11px] text-muted-foreground">
              {report.residualRisks.indicators.map((ind, i) => (
                <li key={i}>{ind}</li>
              ))}
            </ul>
          </div>

          {/* Mandatory Statutory Disclaimer */}
          <div className="p-3.5 rounded-xl bg-secondary/60 border border-border text-center text-xs text-muted-foreground font-mono">
            <strong>Mandatory Legal Notice:</strong> {report.disclaimer} This compliance certificate is generated
            automatically via structural cryptographic validation and programmatic statutory policy heuristics under Republic of India DPDP Act 2023. Zero original sensitive entity values are stored in this report.
          </div>
        </div>
      </div>
    </div>
  );
};
