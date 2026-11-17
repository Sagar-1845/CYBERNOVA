import React from 'react';
import { ShieldAlert, CheckCircle2, XCircle, AlertTriangle, CheckCheck, RefreshCw } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { DetectedEntityItem } from '@/lib/detection/detector';
import { cn } from '@/lib/utils';

interface JuryReviewPanelProps {
  items: DetectedEntityItem[];
  onReviewDecision: (entityId: string, decision: 'ACCEPTED' | 'REJECTED') => void;
  onAcceptAll: () => void;
  onRejectAll: () => void;
  onApplyAndVerify: () => void;
}

export const JuryReviewPanel: React.FC<JuryReviewPanelProps> = ({
  items,
  onReviewDecision,
  onAcceptAll,
  onRejectAll,
  onApplyAndVerify,
}) => {
  const pendingCount = items.filter((i) => !i.reviewDecision).length;
  const acceptedCount = items.filter((i) => i.reviewDecision === 'ACCEPTED').length;
  const rejectedCount = items.filter((i) => i.reviewDecision === 'REJECTED').length;

  return (
    <div className="rounded-2xl border-2 border-amber-500/40 bg-amber-950/20 p-5 sm:p-6 backdrop-blur-xl space-y-5 animate-fade-in">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-amber-500/20 pb-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-amber-500/20 border border-amber-500/40 flex items-center justify-center text-amber-400 shrink-0">
            <AlertTriangle className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-base font-bold text-foreground tracking-tight">
                Needs Human Review // Low Confidence Entities
              </h3>
              <Badge variant="outline" className="border-amber-500/50 text-amber-400 font-mono text-[10px]">
                {items.length} Flagged
              </Badge>
            </div>
            <p className="text-xs text-muted-foreground mt-0.5 font-body">
              The detection engine flagged these items below the confidence threshold. Accepted items will be masked; rejected items will remain unmasked and recorded in the audit log.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 self-end sm:self-auto flex-wrap">
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={onAcceptAll}
            className="text-xs font-mono h-8 border-emerald-500/40 hover:bg-emerald-500/20 text-emerald-400"
          >
            <CheckCheck className="w-3.5 h-3.5 mr-1" /> Accept All
          </Button>
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={onRejectAll}
            className="text-xs font-mono h-8 border-rose-500/40 hover:bg-rose-500/20 text-rose-400"
          >
            <XCircle className="w-3.5 h-3.5 mr-1" /> Reject All
          </Button>
          <Button
            type="button"
            variant="saffron"
            size="sm"
            onClick={onApplyAndVerify}
            className="text-xs font-mono font-bold h-8 px-4"
          >
            <RefreshCw className="w-3.5 h-3.5 mr-1" /> Apply & Run Verification
          </Button>
        </div>
      </div>

      <div className="space-y-2.5 max-h-[360px] overflow-y-auto pr-1">
        {items.map((entity) => {
          const isAccepted = entity.reviewDecision === 'ACCEPTED';
          const isRejected = entity.reviewDecision === 'REJECTED';

          return (
            <div
              key={entity.id}
              className={cn(
                'flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-3.5 rounded-xl border transition-all text-xs',
                isAccepted && 'bg-emerald-950/20 border-emerald-500/40',
                isRejected && 'bg-rose-950/20 border-rose-500/40 opacity-70',
                !entity.reviewDecision && 'bg-card/70 border-border/80 hover:border-amber-500/40'
              )}
            >
              <div className="space-y-1 min-w-0 flex-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <Badge variant="outline" className="font-mono text-[10px] bg-secondary/60">
                    {entity.type}
                  </Badge>
                  <span className="font-mono font-semibold text-foreground px-2 py-0.5 rounded bg-muted/60 text-xs">
                    "{entity.value}"
                  </span>
                  <span className="font-mono text-[11px] text-amber-400">
                    Confidence: {(entity.confidence * 100).toFixed(0)}%
                  </span>
                  <span className="text-[10px] font-mono text-muted-foreground">
                    Offset: [{entity.location.start}..{entity.location.end}] (Line {entity.location.line ?? 1})
                  </span>
                </div>
                <div className="text-[11px] text-muted-foreground leading-relaxed">
                  {entity.explanation}
                </div>
              </div>

              <div className="flex items-center gap-2 shrink-0">
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  onClick={() => onReviewDecision(entity.id, 'ACCEPTED')}
                  className={cn(
                    'h-7 px-2.5 font-mono text-[11px] border-emerald-500/40 hover:bg-emerald-500/20',
                    isAccepted ? 'bg-emerald-500/30 text-emerald-300 font-bold border-emerald-400' : 'text-emerald-400'
                  )}
                >
                  <CheckCircle2 className="w-3 h-3 mr-1" />
                  {isAccepted ? 'Accepted (Mask)' : 'Accept'}
                </Button>
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  onClick={() => onReviewDecision(entity.id, 'REJECTED')}
                  className={cn(
                    'h-7 px-2.5 font-mono text-[11px] border-rose-500/40 hover:bg-rose-500/20',
                    isRejected ? 'bg-rose-500/30 text-rose-300 font-bold border-rose-400' : 'text-rose-400'
                  )}
                >
                  <XCircle className="w-3 h-3 mr-1" />
                  {isRejected ? 'Rejected (Allow)' : 'Reject'}
                </Button>
              </div>
            </div>
          );
        })}
      </div>

      <div className="flex items-center justify-between text-[11px] font-mono text-muted-foreground pt-1 border-t border-amber-500/20">
        <div>
          Pending: <span className="text-amber-400 font-semibold">{pendingCount}</span> | Accepted:{' '}
          <span className="text-emerald-400 font-semibold">{acceptedCount}</span> | Rejected:{' '}
          <span className="text-rose-400 font-semibold">{rejectedCount}</span>
        </div>
        <div>Offset invariant re-verified on every mutation</div>
      </div>
    </div>
  );
};
