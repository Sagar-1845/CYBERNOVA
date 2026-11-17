import React, { useState, useRef, useCallback } from 'react';
import { toast } from 'sonner';
import {
  Upload,
  FileText,
  FileType,
  File as FileIcon,
  X,
  ShieldAlert,
  ShieldCheck,
  ShieldOff,
  ShieldEllipsis,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Info,
  Download,
  Scissors,
  RefreshCw,
  Clock,
  Filter,
  ChevronDown,
  ChevronRight,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';
import {
  apiScan,
  apiRedact,
  apiAuditLog,
  type ScanResult,
  type RedactResult,
  type AuditEntry,
  type Destination,
  type Department,
  type KnownAction,
  type RedactionMode,
  type ScanFinding,
  ApiError,
} from '@/lib/scanRedactApi';

// ─── Constants ────────────────────────────────────────────────────────────────

const ACCEPTED_TYPES = [
  'application/pdf',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'text/plain',
];
const ACCEPTED_EXT = ['.pdf', '.docx', '.txt'];

const DESTINATIONS: { value: Destination; label: string }[] = [
  { value: 'internal', label: 'Internal (Intranet)' },
  { value: 'external', label: 'External (Partner / Third-party)' },
  { value: 'llm', label: 'LLM / AI Model' },
];

const DEPARTMENTS: { value: Department; label: string }[] = [
  { value: 'banking', label: 'Banking & Finance' },
  { value: 'hr', label: 'Human Resources' },
  { value: 'healthcare', label: 'Healthcare' },
  { value: 'legal', label: 'Legal & Compliance' },
  { value: 'finance', label: 'Finance & Accounts' },
  { value: 'default', label: 'General / Default' },
];

const REDACTION_MODES: { value: RedactionMode; label: string; desc: string }[] = [
  { value: 'partial',       label: 'Partial',       desc: 'Mask middle chars, keep type prefix' },
  { value: 'full',          label: 'Full',           desc: 'Replace with [TYPE_N] placeholder token' },
  { value: 'irreversible',  label: 'Irreversible',  desc: 'Cryptographic shred – cannot be restored' },
];

/** All actions shown in the audit filter dropdown. */
const ALL_KNOWN_ACTIONS: KnownAction[] = [
  'ALLOW',
  'REDACT_AND_FORWARD',
  'QUARANTINE',
  'BLOCK',
];

// ─── Policy Decision UI config ────────────────────────────────────────────────

interface BannerCfg {
  bg: string;
  text: string;
  icon: React.ElementType;
  iconColor: string;
  glow: string;
  label: string;
  badgeVariant: 'green' | 'cyan' | 'saffron' | 'destructive' | 'secondary';
}

/** Returns styling config for a policy action string.
 *  Tolerant: unknown actions get a neutral grey banner instead of crashing. */
function policyDecisionConfig(action: string): BannerCfg {
  switch (action as KnownAction) {
    case 'ALLOW':
      return {
        bg: 'bg-emerald-500/15 border-emerald-500/50',
        text: 'text-emerald-400',
        icon: ShieldCheck,
        iconColor: 'text-emerald-400',
        glow: 'shadow-[0_0_28px_-6px_rgba(52,211,153,0.5)]',
        label: 'ALLOW',
        badgeVariant: 'green',
      };
    case 'REDACT_AND_FORWARD':
      return {
        bg: 'bg-blue-500/15 border-blue-500/50',
        text: 'text-blue-400',
        icon: ShieldAlert,
        iconColor: 'text-blue-400',
        glow: 'shadow-[0_0_28px_-6px_rgba(59,130,246,0.5)]',
        label: 'REDACT & FORWARD',
        badgeVariant: 'cyan',
      };
    case 'QUARANTINE':
      return {
        bg: 'bg-amber-500/15 border-amber-500/50',
        text: 'text-amber-400',
        icon: ShieldEllipsis,
        iconColor: 'text-amber-400',
        glow: 'shadow-[0_0_28px_-6px_rgba(245,158,11,0.5)]',
        label: 'QUARANTINE',
        badgeVariant: 'saffron',
      };
    case 'BLOCK':
      return {
        bg: 'bg-red-600/15 border-red-500/50',
        text: 'text-red-400',
        icon: ShieldOff,
        iconColor: 'text-red-400',
        glow: 'shadow-[0_0_28px_-6px_rgba(239,68,68,0.6)]',
        label: 'BLOCK',
        badgeVariant: 'destructive',
      };
    default:
      // Unknown action – neutral grey, show raw text
      return {
        bg: 'bg-secondary/40 border-border/70',
        text: 'text-foreground',
        icon: ShieldEllipsis,
        iconColor: 'text-muted-foreground',
        glow: '',
        label: action || 'UNKNOWN',
        badgeVariant: 'secondary',
      };
  }
}

function sensitivityColor(label: string) {
  const u = label?.toUpperCase() ?? '';
  if (u.includes('TOP') || u.includes('SECRET')) return 'text-red-400 border-red-500/50 bg-red-500/10';
  if (u.includes('CONF'))                          return 'text-amber-400 border-amber-500/50 bg-amber-500/10';
  return 'text-cyan-400 border-cyan-500/50 bg-cyan-500/10';
}

function riskScoreColor(score: number) {
  if (score >= 75) return 'text-red-400';
  if (score >= 55) return 'text-amber-400';
  if (score >= 30) return 'text-blue-400';
  return 'text-emerald-400';
}

// ─── Mock banner ──────────────────────────────────────────────────────────────

function MockBanner() {
  return (
    <div className="flex items-center gap-2.5 px-4 py-2.5 rounded-2xl border border-amber-500/50 bg-amber-500/10 text-amber-400 text-xs font-mono font-semibold">
      <AlertTriangle className="w-4 h-4 shrink-0" />
      <span>MOCK DATA — backend not connected</span>
      <span className="ml-auto text-amber-400/60 font-normal">
        (set VITE_USE_MOCK=false to use the live API)
      </span>
    </div>
  );
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function DropZone({
  onFile,
  file,
  onClear,
}: {
  onFile: (f: File) => void;
  file: File | null;
  onClear: () => void;
}) {
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragging(false);
      const dropped = e.dataTransfer.files[0];
      if (dropped && ACCEPTED_TYPES.includes(dropped.type)) {
        onFile(dropped);
      } else {
        toast.error('Unsupported file type. Use PDF, DOCX, or TXT.');
      }
    },
    [onFile]
  );

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    if (f) onFile(f);
  };

  if (file) {
    return (
      <div className="flex items-center gap-3 p-4 rounded-2xl border border-cyan-500/40 bg-cyan-500/5 backdrop-blur">
        <div className="w-10 h-10 rounded-xl bg-cyan-500/15 border border-cyan-500/40 flex items-center justify-center shrink-0">
          <FileText className="w-5 h-5 text-cyan-400" />
        </div>
        <div className="flex-1 min-w-0">
          <p className="text-sm font-mono font-semibold text-foreground truncate">{file.name}</p>
          <p className="text-xs text-muted-foreground">
            {(file.size / 1024).toFixed(1)} KB &bull; {file.type || 'unknown'}
          </p>
        </div>
        <button
          onClick={onClear}
          className="ml-auto p-1.5 rounded-lg hover:bg-destructive/20 text-muted-foreground hover:text-destructive transition-colors"
          aria-label="Remove file"
        >
          <X className="w-4 h-4" />
        </button>
      </div>
    );
  }

  return (
    <div
      onDragOver={e => { e.preventDefault(); setDragging(true); }}
      onDragLeave={() => setDragging(false)}
      onDrop={handleDrop}
      onClick={() => inputRef.current?.click()}
      className={cn(
        'relative cursor-pointer flex flex-col items-center justify-center gap-3 py-10 px-6 rounded-2xl border-2 border-dashed transition-all duration-200',
        dragging
          ? 'border-cyan-400 bg-cyan-400/10 scale-[1.01]'
          : 'border-border/60 hover:border-cyan-500/60 hover:bg-cyan-500/5 bg-card/40'
      )}
      role="button"
      tabIndex={0}
      onKeyDown={e => e.key === 'Enter' && inputRef.current?.click()}
      aria-label="Upload document"
    >
      <input
        ref={inputRef}
        type="file"
        accept={ACCEPTED_EXT.join(',')}
        className="hidden"
        onChange={handleChange}
      />
      <div className="w-14 h-14 rounded-2xl bg-[#0a1628] border border-cyan-500/30 flex items-center justify-center">
        <Upload className={cn('w-7 h-7 transition-colors', dragging ? 'text-cyan-400' : 'text-muted-foreground')} />
      </div>
      <div className="text-center">
        <p className="text-sm font-semibold text-foreground">
          {dragging ? 'Drop to upload' : 'Drag & drop your document'}
        </p>
        <p className="text-xs text-muted-foreground mt-1">PDF, DOCX, TXT &bull; Max 50 MB</p>
      </div>
      <div className="flex gap-2">
        {[FileType, FileText, FileIcon].map((Icon, i) => (
          <span
            key={i}
            className="px-2 py-0.5 rounded text-[10px] font-mono border border-border/60 text-muted-foreground"
          >
            {ACCEPTED_EXT[i]}
          </span>
        ))}
      </div>
    </div>
  );
}

function PolicyBanner({ action }: { action: string }) {
  const cfg = policyDecisionConfig(action);
  const Icon = cfg.icon;
  return (
    <div
      className={cn(
        'flex items-center gap-4 px-6 py-5 rounded-2xl border-2 transition-all',
        cfg.bg,
        cfg.glow
      )}
    >
      <Icon className={cn('w-10 h-10 shrink-0', cfg.iconColor)} />
      <div>
        <span className={cn('text-3xl font-black tracking-widest font-mono', cfg.text)}>
          {cfg.label}
        </span>
        <p className="text-xs text-muted-foreground mt-0.5 font-mono">
          Policy Decision &bull; Scan completed
        </p>
      </div>
    </div>
  );
}

function FindingsTable({ findings }: { findings: ScanFinding[] }) {
  const byType = findings.reduce<Record<string, ScanFinding[]>>((acc, f) => {
    acc[f.type] = acc[f.type] ?? [];
    acc[f.type].push(f);
    return acc;
  }, {});

  const [expanded, setExpanded] = useState<Record<string, boolean>>({});

  if (findings.length === 0) {
    return (
      <div className="rounded-2xl border border-border/70 bg-card/60 backdrop-blur p-6 text-center text-sm text-muted-foreground font-mono">
        No findings detected.
      </div>
    );
  }

  return (
    <div className="rounded-2xl border border-border/70 overflow-hidden bg-card/60 backdrop-blur">
      <div className="px-4 py-3 border-b border-border/60 bg-secondary/30 flex items-center justify-between">
        <span className="text-xs font-mono font-bold uppercase tracking-wider text-muted-foreground">
          Findings by Type
        </span>
        <span className="text-xs font-mono text-muted-foreground">
          {findings.length} total
        </span>
      </div>
      <div className="divide-y divide-border/40">
        {Object.entries(byType).map(([type, items]) => {
          const isOpen = expanded[type] ?? true;
          const avgConf = items.reduce((s, f) => s + f.confidence, 0) / items.length;
          return (
            <div key={type}>
              <button
                className="w-full flex items-center justify-between px-4 py-3 hover:bg-secondary/20 transition-colors"
                onClick={() => setExpanded(prev => ({ ...prev, [type]: !isOpen }))}
              >
                <div className="flex items-center gap-2">
                  {isOpen
                    ? <ChevronDown className="w-3.5 h-3.5 text-muted-foreground" />
                    : <ChevronRight className="w-3.5 h-3.5 text-muted-foreground" />}
                  <span className="text-xs font-mono font-bold text-cyan-400">{type}</span>
                  <span className="text-[10px] font-mono text-muted-foreground">
                    ({items.length} instance{items.length !== 1 ? 's' : ''})
                  </span>
                </div>
                <span className="text-[10px] font-mono text-muted-foreground">
                  avg. confidence {(avgConf * 100).toFixed(0)}%
                </span>
              </button>

              {isOpen && (
                <div className="overflow-x-auto">
                  <table className="w-full text-xs font-mono">
                    <thead>
                      <tr className="border-t border-border/40 bg-background/40 text-muted-foreground text-[10px] uppercase tracking-wider">
                        <th className="text-left py-2 px-4">ID</th>
                        <th className="text-left py-2 px-4">Page</th>
                        <th className="text-left py-2 px-4">Masked Preview</th>
                        <th className="text-left py-2 px-4">Confidence</th>
                        <th className="text-left py-2 px-4">Span</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border/30">
                      {items.map(f => (
                        <tr key={f.id} className="hover:bg-secondary/15 transition-colors">
                          <td className="py-2 px-4 text-muted-foreground">{f.id}</td>
                          <td className="py-2 px-4 text-muted-foreground">{f.page ?? '—'}</td>
                          <td className="py-2 px-4">
                            <code className="px-1.5 py-0.5 rounded bg-[#0a1628] border border-cyan-500/25 text-cyan-300 text-[11px]">
                              {f.masked_preview}
                            </code>
                          </td>
                          <td className="py-2 px-4">
                            <div className="flex items-center gap-2">
                              <div className="w-16 h-1.5 rounded-full bg-secondary overflow-hidden">
                                <div
                                  className="h-full bg-cyan-400 rounded-full"
                                  style={{ width: `${f.confidence * 100}%` }}
                                />
                              </div>
                              <span className={f.confidence >= 0.9 ? 'text-emerald-400' : 'text-amber-400'}>
                                {(f.confidence * 100).toFixed(0)}%
                              </span>
                            </div>
                          </td>
                          <td className="py-2 px-4 text-muted-foreground">
                            {f.start}–{f.end}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ─── Verification Card ────────────────────────────────────────────────────────

function VerificationCard({
  result,
  onDownload,
}: {
  result: RedactResult;
  onDownload: () => void;
}) {
  const isVerified = result.verified && result.findings_remaining === 0;

  return (
    <div
      className={cn(
        'p-5 rounded-2xl border-2 space-y-4 transition-all',
        isVerified
          ? 'border-emerald-500/50 bg-emerald-500/10 shadow-[0_0_28px_-6px_rgba(52,211,153,0.4)]'
          : 'border-red-500/50 bg-red-500/10 shadow-[0_0_28px_-6px_rgba(239,68,68,0.4)]'
      )}
    >
      <div className="flex items-center gap-3">
        {isVerified
          ? <CheckCircle2 className="w-7 h-7 text-emerald-400 shrink-0" />
          : <XCircle className="w-7 h-7 text-red-400 shrink-0" />}
        <div>
          <p className={cn('font-bold font-mono text-base', isVerified ? 'text-emerald-400' : 'text-red-400')}>
            {isVerified ? 'Verified: 0 findings remaining' : 'Verification Warning'}
          </p>
          <p className="text-xs text-muted-foreground font-mono">
            Doc ID: {result.doc_id}
            {result.mock && <>&nbsp;&bull;&nbsp;<span className="text-cyan-400">Enclave Mode</span></>}
          </p>
        </div>
      </div>

      {!isVerified && (
        <div className="flex items-start gap-2 p-3 rounded-xl bg-background/40 border border-red-500/30 text-red-400 text-xs font-mono">
          <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
          <span>
            {result.findings_remaining > 0
              ? `${result.findings_remaining} finding${result.findings_remaining !== 1 ? 's' : ''} remain after redaction. Manual review required.`
              : 'Backend reported verified=false. Document may not be fully clean.'}
          </span>
        </div>
      )}

      <div className="grid grid-cols-2 gap-3">
        <div className="p-3 rounded-xl bg-background/50 border border-border/50 text-center">
          <p className="text-xs font-mono text-muted-foreground">Findings Removed</p>
          <p className={cn('text-2xl font-black', isVerified ? 'text-emerald-400' : 'text-foreground')}>
            {result.findings_removed}
          </p>
        </div>
        <div className="p-3 rounded-xl bg-background/50 border border-border/50 text-center">
          <p className="text-xs font-mono text-muted-foreground">Remaining</p>
          <p className={cn('text-2xl font-black', result.findings_remaining > 0 ? 'text-red-400' : 'text-foreground')}>
            {result.findings_remaining}
          </p>
        </div>
      </div>

      <Button
        onClick={onDownload}
        className={cn(
          'w-full gap-2 font-mono font-semibold min-h-[42px] rounded-xl',
          isVerified
            ? 'bg-gradient-to-r from-emerald-500 to-teal-500 hover:from-emerald-400 hover:to-teal-400 text-white shadow-[0_0_20px_-6px_rgba(52,211,153,0.5)]'
            : 'bg-gradient-to-r from-amber-500 to-orange-500 hover:from-amber-400 hover:to-orange-400 text-white'
        )}
      >
        <Download className="w-4 h-4" />
        Download Redacted Document
      </Button>
    </div>
  );
}

// ─── Audit Log Tab ────────────────────────────────────────────────────────────

function AuditLogTab({ onMock }: { onMock: (isMock: boolean) => void }) {
  const [entries, setEntries] = useState<AuditEntry[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [filterDept, setFilterDept] = useState('ALL');
  const [filterDecision, setFilterDecision] = useState('ALL');

  const fetchAudit = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await apiAuditLog();
      setEntries(data);
      // apiAuditLog mock returns entries with MOCK-like scan IDs; heuristic
      const isMock = data.some(e => e.scan_id.startsWith('SCN-'));
      onMock(isMock);
    } catch (e: unknown) {
      if (e instanceof ApiError) {
        setError(`Server error ${e.status}: ${e.message}`);
      } else if (e instanceof Error) {
        setError(e.message);
      } else {
        setError('Failed to load audit log');
      }
    } finally {
      setLoading(false);
    }
  };

  React.useEffect(() => { fetchAudit(); }, []);

  const filtered = (entries ?? []).filter(e =>
    (filterDept === 'ALL' || e.department === filterDept) &&
    (filterDecision === 'ALL' || e.policy_decision === filterDecision)
  );

  return (
    <div className="space-y-5">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <h2 className="text-lg font-bold text-foreground font-mono flex items-center gap-2">
          <Clock className="w-4 h-4 text-cyan-400" />
          Scan &amp; Redact Audit Log
        </h2>
        <div className="flex flex-wrap items-center gap-2">
          <div className="flex items-center gap-1.5 text-xs font-mono text-muted-foreground">
            <Filter className="w-3.5 h-3.5" />
          </div>
          <select
            value={filterDept}
            onChange={e => setFilterDept(e.target.value)}
            className="bg-background border border-border text-foreground text-xs font-mono rounded-xl px-3 py-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400"
          >
            <option value="ALL">All Departments</option>
            {DEPARTMENTS.map(d => (
              <option key={d.value} value={d.value}>{d.label}</option>
            ))}
          </select>
          <select
            value={filterDecision}
            onChange={e => setFilterDecision(e.target.value)}
            className="bg-background border border-border text-foreground text-xs font-mono rounded-xl px-3 py-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400"
          >
            <option value="ALL">All Decisions</option>
            {ALL_KNOWN_ACTIONS.map(d => (
              <option key={d} value={d}>{d}</option>
            ))}
          </select>
          <Button
            variant="outline"
            size="sm"
            onClick={fetchAudit}
            disabled={loading}
            className="gap-1.5 font-mono text-xs border-border/80 min-h-[36px]"
          >
            <RefreshCw className={cn('w-3.5 h-3.5', loading && 'animate-spin')} />
            Refresh
          </Button>
        </div>
      </div>

      {loading && (
        <div className="flex flex-col items-center justify-center py-16 gap-3">
          <div className="w-8 h-8 rounded-full border-2 border-cyan-400 border-t-transparent animate-spin" />
          <span className="text-xs font-mono text-muted-foreground">Loading audit records…</span>
        </div>
      )}

      {error && !loading && (
        <div className="p-4 rounded-2xl border border-destructive/40 bg-destructive/10 text-destructive text-sm font-mono flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          {error}
        </div>
      )}

      {!loading && !error && entries !== null && (
        <div className="rounded-2xl border border-border/70 overflow-hidden bg-card/60 backdrop-blur">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs font-mono">
              <thead>
                <tr className="border-b border-border bg-secondary/40 text-muted-foreground uppercase tracking-wider text-[10px]">
                  <th className="py-3 px-4 font-bold">Audit ID</th>
                  <th className="py-3 px-4 font-bold">Timestamp</th>
                  <th className="py-3 px-4 font-bold">File</th>
                  <th className="py-3 px-4 font-bold">Dept</th>
                  <th className="py-3 px-4 font-bold">Destination</th>
                  <th className="py-3 px-4 font-bold">Decision</th>
                  <th className="py-3 px-4 font-bold">Risk</th>
                  <th className="py-3 px-4 font-bold">Findings</th>
                  <th className="py-3 px-4 font-bold">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/50">
                {filtered.length === 0 ? (
                  <tr>
                    <td colSpan={9} className="py-10 text-center text-muted-foreground">
                      No records match the current filters.
                    </td>
                  </tr>
                ) : (
                  filtered.map(entry => {
                    const cfg = policyDecisionConfig(entry.policy_decision);
                    return (
                      <tr key={entry.id} className="hover:bg-secondary/20 transition-colors">
                        <td className="py-3 px-4 whitespace-nowrap font-bold text-foreground">{entry.id}</td>
                        <td className="py-3 px-4 whitespace-nowrap text-muted-foreground">
                          {new Date(entry.timestamp).toLocaleString([], { dateStyle: 'short', timeStyle: 'short' })}
                        </td>
                        <td className="py-3 px-4 max-w-[160px] truncate text-foreground/80">{entry.filename}</td>
                        <td className="py-3 px-4 uppercase text-muted-foreground">{entry.department}</td>
                        <td className="py-3 px-4 capitalize text-muted-foreground">{entry.destination}</td>
                        <td className="py-3 px-4">
                          <Badge variant={cfg.badgeVariant} className="text-[10px] font-mono whitespace-nowrap">
                            {entry.policy_decision}
                          </Badge>
                        </td>
                        <td className={cn('py-3 px-4 font-bold', riskScoreColor(entry.risk_score))}>
                          {entry.risk_score}
                        </td>
                        <td className="py-3 px-4 text-muted-foreground">{entry.findings_count}</td>
                        <td className="py-3 px-4 text-foreground/70 max-w-[200px] truncate">{entry.action_taken}</td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

type TabId = 'scan' | 'audit';

export const ScanRedactPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<TabId>('scan');
  const [isMockMode, setIsMockMode] = useState(false);

  // Upload state
  const [file, setFile] = useState<File | null>(null);
  const [destination, setDestination] = useState<Destination>('internal');
  const [department, setDepartment] = useState<Department>('banking');

  // Scan state
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);

  // Redact state
  const [redactionMode, setRedactionMode] = useState<RedactionMode>('full');
  const [redacting, setRedacting] = useState(false);
  const [redactResult, setRedactResult] = useState<RedactResult | null>(null);
  const [redactError, setRedactError] = useState<string | null>(null);

  const handleFileSelected = (f: File) => {
    setFile(f);
    setScanResult(null);
    setScanError(null);
    setRedactResult(null);
    setRedactError(null);
    setIsMockMode(false);
  };

  const handleClearFile = () => {
    setFile(null);
    setScanResult(null);
    setScanError(null);
    setRedactResult(null);
    setRedactError(null);
    setIsMockMode(false);
  };

  const handleScan = async () => {
    if (!file) return;
    setScanning(true);
    setScanError(null);
    setScanResult(null);
    setRedactResult(null);
    setIsMockMode(false);
    try {
      const result = await apiScan(file, destination, department);
      setScanResult(result);
      if (result.mock) setIsMockMode(true);
      toast.success('Document scanned successfully');
    } catch (e: unknown) {
      let msg: string;
      if (e instanceof ApiError) {
        msg = `Server error ${e.status}: ${e.message}`;
      } else if (e instanceof Error) {
        msg = e.message;
      } else {
        msg = 'Scan failed';
      }
      setScanError(msg);
      toast.error('Scan failed', { description: msg });
    } finally {
      setScanning(false);
    }
  };

  const handleRedact = async () => {
    if (!scanResult || !file) return;
    setRedacting(true);
    setRedactError(null);
    try {
      const result = await apiRedact(file, scanResult.doc_id, redactionMode, scanResult.findings.length);
      setRedactResult(result);
      if (result.mock) setIsMockMode(true);
      toast.success('Redaction complete');
    } catch (e: unknown) {
      let msg: string;
      if (e instanceof ApiError) {
        msg = `Server error ${e.status}: ${e.message}`;
      } else if (e instanceof Error) {
        msg = e.message;
      } else {
        msg = 'Redaction failed';
      }
      setRedactError(msg);
      toast.error('Redaction failed', { description: msg });
    } finally {
      setRedacting(false);
    }
  };

  const handleDownload = async () => {
    if (!redactResult) return;
    const filename = redactResult.download_filename;

    if (redactResult.mock) {
      // Mock: generate a placeholder text file
      const content = [
        'ZEROLEAK AI — REDACTED DOCUMENT',
        '',
        `Doc ID:            ${redactResult.doc_id}`,
        `Findings Removed:  ${redactResult.findings_removed}`,
        `Findings Remaining:${redactResult.findings_remaining}`,
        `Verified:          ${redactResult.verified}`,
        '',
        '[Document content redacted per policy]',
        '',
        `Generated: ${new Date().toISOString()}`,
      ].join('\n');
      const blob = new Blob([content], { type: 'text/plain' });
      triggerDownload(URL.createObjectURL(blob), filename, true);
    } else {
      // Live: fetch from the resolved URL
      try {
        const res = await fetch(redactResult.resolved_download_url);
        if (!res.ok) throw new Error(`Download failed: HTTP ${res.status}`);
        const blob = await res.blob();
        triggerDownload(URL.createObjectURL(blob), filename, true);
      } catch (e: unknown) {
        toast.error('Download failed', { description: e instanceof Error ? e.message : String(e) });
        return;
      }
    }
    toast.success('Redacted document downloaded');
  };

  function triggerDownload(url: string, filename: string, revoke: boolean) {
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    if (revoke) setTimeout(() => URL.revokeObjectURL(url), 5000);
  }

  const TABS: { id: TabId; label: string }[] = [
    { id: 'scan', label: 'Scan & Redact' },
    { id: 'audit', label: 'Audit Log' },
  ];

  return (
    <div className="pt-24 pb-20 min-h-screen relative">
      {/* Ambient background grid */}
      <div className="fixed inset-0 pointer-events-none security-grid opacity-20" aria-hidden />

      <div className="container mx-auto px-4 sm:px-6 max-w-5xl relative">

        {/* Mock banner – shown whenever mock data is active */}
        {isMockMode && (
          <div className="mb-5">
            <MockBanner />
          </div>
        )}

        {/* Page Header */}
        <div className="mb-8">
          <div className="flex items-center gap-2 mb-3">
            <Badge variant="outline" className="border-cyan-400/40 text-cyan-400 font-mono text-xs">
              <Scissors className="w-3.5 h-3.5 mr-1" />
              DOCUMENT INTELLIGENCE
            </Badge>
            <Badge variant="neon" className="text-[10px] font-mono">
              DPDP Compliant
            </Badge>
          </div>
          <h1 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-foreground">
            Scan &amp;{' '}
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-400">
              Redact
            </span>
          </h1>
          <p className="text-sm text-muted-foreground mt-1.5 max-w-2xl">
            Upload a document, choose the destination and department, and let ZeroLeak AI detect
            sensitive data, assess policy risk, and redact PII before egress.
          </p>
        </div>

        {/* Tabs */}
        <div className="flex gap-1 p-1 rounded-2xl bg-card/60 border border-border/60 backdrop-blur mb-8 w-fit">
          {TABS.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={cn(
                'px-5 py-2 rounded-xl text-sm font-mono font-medium transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400',
                activeTab === tab.id
                  ? 'bg-secondary text-foreground shadow border border-border'
                  : 'text-muted-foreground hover:text-foreground'
              )}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* ── SCAN & REDACT TAB ── */}
        {activeTab === 'scan' && (
          <div className="space-y-6">
            {/* Upload + Config Card */}
            <div className="p-5 sm:p-6 rounded-3xl border border-border/70 bg-card/80 backdrop-blur-xl shadow-xl space-y-5">
              <h2 className="text-base font-bold text-foreground font-mono flex items-center gap-2">
                <Upload className="w-4 h-4 text-cyan-400" />
                Step 1 — Upload Document
              </h2>

              <DropZone file={file} onFile={handleFileSelected} onClear={handleClearFile} />

              {/* Dropdowns */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <label className="text-xs font-mono text-muted-foreground uppercase tracking-wider">
                    Destination
                  </label>
                  <select
                    value={destination}
                    onChange={e => setDestination(e.target.value as Destination)}
                    className="w-full bg-background border border-border text-foreground text-sm font-mono rounded-xl px-3 py-2.5 min-h-[42px] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400"
                  >
                    {DESTINATIONS.map(d => (
                      <option key={d.value} value={d.value}>{d.label}</option>
                    ))}
                  </select>
                </div>

                <div className="space-y-1.5">
                  <label className="text-xs font-mono text-muted-foreground uppercase tracking-wider">
                    Department
                  </label>
                  <select
                    value={department}
                    onChange={e => setDepartment(e.target.value as Department)}
                    className="w-full bg-background border border-border text-foreground text-sm font-mono rounded-xl px-3 py-2.5 min-h-[42px] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400"
                  >
                    {DEPARTMENTS.map(d => (
                      <option key={d.value} value={d.value}>{d.label}</option>
                    ))}
                  </select>
                </div>
              </div>

              <Button
                onClick={handleScan}
                disabled={!file || scanning}
                className={cn(
                  'w-full sm:w-auto gap-2 font-mono font-semibold min-h-[44px] px-8 rounded-xl transition-all',
                  'bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white',
                  'shadow-[0_0_20px_-4px_rgba(34,211,238,0.5)] hover:shadow-[0_0_28px_-4px_rgba(34,211,238,0.7)]',
                  'disabled:opacity-50 disabled:cursor-not-allowed'
                )}
              >
                {scanning ? (
                  <><RefreshCw className="w-4 h-4 animate-spin" />Scanning…</>
                ) : (
                  <><ShieldAlert className="w-4 h-4" />Run Scan</>
                )}
              </Button>
            </div>

            {/* Scan Error */}
            {scanError && (
              <div className="flex items-start gap-3 p-4 rounded-2xl border border-destructive/40 bg-destructive/10 text-destructive text-sm font-mono">
                <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                <div>
                  <p className="font-semibold">Scan Error</p>
                  <p className="text-xs opacity-80 mt-0.5">{scanError}</p>
                </div>
              </div>
            )}

            {/* Scan Loading Skeleton */}
            {scanning && (
              <div className="p-6 rounded-3xl border border-cyan-500/30 bg-card/60 backdrop-blur-xl animate-pulse space-y-4">
                <div className="h-5 w-48 bg-secondary rounded-lg" />
                <div className="h-20 bg-secondary rounded-2xl" />
                <div className="h-4 w-72 bg-secondary rounded-lg" />
                <div className="h-4 w-56 bg-secondary rounded-lg" />
              </div>
            )}

            {/* Scan Results */}
            {scanResult && !scanning && (
              <div className="space-y-5">
                {/* Overview row */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  {/* Sensitivity */}
                  <div className="col-span-2 sm:col-span-1 p-4 rounded-2xl border border-border/60 bg-card/70 backdrop-blur flex flex-col gap-1">
                    <span className="text-[10px] font-mono text-muted-foreground uppercase tracking-wider">
                      Sensitivity
                    </span>
                    <span
                      className={cn(
                        'text-sm font-mono font-bold px-2 py-1 rounded-lg border w-fit',
                        sensitivityColor(scanResult.sensitivity)
                      )}
                    >
                      {scanResult.sensitivity}
                    </span>
                  </div>

                  {/* Risk Score */}
                  <div className="p-4 rounded-2xl border border-border/60 bg-card/70 backdrop-blur flex flex-col gap-1">
                    <span className="text-[10px] font-mono text-muted-foreground uppercase tracking-wider">
                      Risk Score
                    </span>
                    <span className={cn('text-2xl font-black font-mono', riskScoreColor(scanResult.risk_score))}>
                      {scanResult.risk_score}
                      <span className="text-xs text-muted-foreground font-normal">/100</span>
                    </span>
                  </div>

                  {/* Findings */}
                  <div className="p-4 rounded-2xl border border-border/60 bg-card/70 backdrop-blur flex flex-col gap-1">
                    <span className="text-[10px] font-mono text-muted-foreground uppercase tracking-wider">
                      Findings
                    </span>
                    <span className="text-2xl font-black font-mono text-foreground">
                      {scanResult.findings.length}
                    </span>
                  </div>

                  {/* Engine */}
                  <div className="p-4 rounded-2xl border border-border/60 bg-card/70 backdrop-blur flex flex-col gap-1">
                    <span className="text-[10px] font-mono text-muted-foreground uppercase tracking-wider">
                      Engine
                    </span>
                    <span className="text-xs font-mono text-cyan-400 font-semibold">
                      {scanResult.mock ? 'Sovereign Enclave' : 'Live Backend'}
                    </span>
                    <span className="text-[10px] font-mono text-muted-foreground">
                      {scanResult.format}
                    </span>
                  </div>
                </div>

                {/* Policy Decision Banner */}
                <PolicyBanner action={scanResult.decision.action} />

                {/* Reasons */}
                {scanResult.decision.reasons.length > 0 && (
                  <div className="p-4 rounded-2xl border border-border/60 bg-card/60 backdrop-blur space-y-2">
                    <div className="flex items-center gap-2 mb-1">
                      <Info className="w-3.5 h-3.5 text-blue-400" />
                      <span className="text-xs font-mono font-bold text-muted-foreground uppercase tracking-wider">
                        Policy Reasons
                      </span>
                    </div>
                    <ul className="space-y-1.5">
                      {scanResult.decision.reasons.map((r, i) => (
                        <li key={i} className="flex items-start gap-2 text-sm text-foreground/80">
                          <span className="mt-1.5 w-1.5 h-1.5 rounded-full bg-cyan-400 shrink-0" />
                          {r}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Findings table */}
                <FindingsTable findings={scanResult.findings} />

                {/* ── Redact Section ── */}
                <div className="p-5 sm:p-6 rounded-3xl border border-border/70 bg-card/80 backdrop-blur-xl shadow-xl space-y-5">
                  <h2 className="text-base font-bold text-foreground font-mono flex items-center gap-2">
                    <Scissors className="w-4 h-4 text-amber-400" />
                    Step 2 — Redact
                  </h2>

                  {/* Redaction Mode Selector */}
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                    {REDACTION_MODES.map(m => (
                      <button
                        key={m.value}
                        onClick={() => setRedactionMode(m.value)}
                        className={cn(
                          'flex flex-col gap-1 p-4 rounded-2xl border-2 text-left transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400',
                          redactionMode === m.value
                            ? 'border-amber-400/60 bg-amber-500/10 shadow-[0_0_16px_-4px_rgba(251,191,36,0.4)]'
                            : 'border-border/50 bg-card/40 hover:border-border hover:bg-secondary/20'
                        )}
                      >
                        <span className={cn(
                          'text-sm font-mono font-bold',
                          redactionMode === m.value ? 'text-amber-400' : 'text-foreground'
                        )}>
                          {m.label}
                        </span>
                        <span className="text-[11px] text-muted-foreground leading-snug">{m.desc}</span>
                      </button>
                    ))}
                  </div>

                  <Button
                    onClick={handleRedact}
                    disabled={redacting}
                    className={cn(
                      'w-full sm:w-auto gap-2 font-mono font-semibold min-h-[44px] px-8 rounded-xl transition-all',
                      'bg-gradient-to-r from-amber-500 to-orange-500 hover:from-amber-400 hover:to-orange-400 text-white',
                      'shadow-[0_0_20px_-4px_rgba(251,191,36,0.5)] hover:shadow-[0_0_28px_-4px_rgba(251,191,36,0.7)]',
                      'disabled:opacity-50 disabled:cursor-not-allowed'
                    )}
                  >
                    {redacting ? (
                      <><RefreshCw className="w-4 h-4 animate-spin" />Redacting…</>
                    ) : (
                      <><Scissors className="w-4 h-4" />Apply Redaction</>
                    )}
                  </Button>

                  {redactError && (
                    <div className="flex items-start gap-2 p-3 rounded-xl border border-destructive/40 bg-destructive/10 text-destructive text-xs font-mono">
                      <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                      {redactError}
                    </div>
                  )}

                  {/* Verification Card */}
                  {redactResult && !redacting && (
                    <VerificationCard result={redactResult} onDownload={handleDownload} />
                  )}
                </div>
              </div>
            )}
          </div>
        )}

        {/* ── AUDIT LOG TAB ── */}
        {activeTab === 'audit' && (
          <AuditLogTab onMock={setIsMockMode} />
        )}
      </div>
    </div>
  );
};

export default ScanRedactPage;
