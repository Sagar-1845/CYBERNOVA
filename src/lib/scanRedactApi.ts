/**
 * src/lib/scanRedactApi.ts
 * ─────────────────────────
 * API client for the ZeroLeak DLP backend.
 *
 * Endpoints (base: http://127.0.0.1:8001):
 *   POST /api/v1/dlp/scan      multipart: file, destination, department
 *   POST /api/v1/dlp/redact    multipart: file, mode
 *   GET  /api/v1/dlp/download/{doc_id}
 *   GET  /api/v1/dlp/audit
 *
 * Mock fallback rules:
 *   - Only fallback on network errors (fetch throws / no response).
 *   - HTTP 4xx/5xx responses are NEVER mocked; they throw ApiError with the
 *     real server message.
 *   - VITE_USE_MOCK=true env flag forces mock mode unconditionally.
 *   - When mock data is returned, `mock: true` is set on the result.
 */

export const BASE = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

// ─── Force-mock env flag ──────────────────────────────────────────────────────
// Set VITE_USE_MOCK=true in your .env to bypass the backend entirely.
const FORCE_MOCK = import.meta.env.VITE_USE_MOCK === 'true';

// ─── Custom error ─────────────────────────────────────────────────────────────

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    message: string,
    public readonly body?: unknown
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

/** Extract a human-readable message from an error response body. */
async function extractErrorMessage(res: Response): Promise<string> {
  try {
    const body = await res.json();
    return (
      body?.detail ??
      body?.message ??
      body?.error ??
      (typeof body === 'string' ? body : null) ??
      `HTTP ${res.status} ${res.statusText}`
    );
  } catch {
    return `HTTP ${res.status} ${res.statusText}`;
  }
}

// ─── Types ───────────────────────────────────────────────────────────────────

export type Destination = 'internal' | 'external' | 'llm';
export type Department =
  | 'banking'
  | 'hr'
  | 'healthcare'
  | 'legal'
  | 'finance'
  | 'default';

/** All known policy actions. The UI handles unknown strings gracefully. */
export type KnownAction = 'ALLOW' | 'REDACT_AND_FORWARD' | 'QUARANTINE' | 'BLOCK';

export type RedactionMode = 'full' | 'partial' | 'irreversible';

export interface ScanFinding {
  id: string;
  type: string;
  confidence: number;
  page?: number;
  start: number;
  end: number;
  masked_preview: string;
}

export interface PolicyDecision {
  action: string;        // KnownAction or any unknown string
  reasons: string[];
}

export interface ScanResult {
  doc_id: string;
  filename: string;
  format: string;
  sensitivity: string;   // e.g. "CONFIDENTIAL", "TOP SECRET"
  risk_score: number;    // 0–100
  findings: ScanFinding[];
  decision: PolicyDecision;
  mock?: boolean;
}

export interface RedactResult {
  doc_id: string;
  download_url: string;  // may be relative – resolve against BASE
  findings_removed: number;
  findings_remaining: number;
  verified: boolean;
  mock?: boolean;
  /** Resolved absolute URL for downloading the redacted file. */
  resolved_download_url: string;
  /** Suggested local filename (original name prefixed with "redacted_"). */
  download_filename: string;
}

export interface AuditEntry {
  id: string;
  timestamp: string;
  scan_id: string;
  filename: string;
  department: string;
  destination: string;
  policy_decision: string;
  risk_score: number;
  findings_count: number;
  action_taken: string;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** Make a download_url absolute by resolving relative paths against BASE. */
export function resolveDownloadUrl(downloadUrl: string): string {
  if (!downloadUrl) return '';
  if (downloadUrl.startsWith('http://') || downloadUrl.startsWith('https://')) {
    return downloadUrl;
  }
  // Relative path – prefix with BASE
  const sep = downloadUrl.startsWith('/') ? '' : '/';
  return `${BASE}${sep}${downloadUrl}`;
}

// ─── Mock generators ─────────────────────────────────────────────────────────

function mockScanResult(
  filename: string,
  destination: Destination,
  department: Department
): ScanResult {
  const findings: ScanFinding[] = [
    { id: 'F-001', type: 'AADHAAR',   confidence: 0.97, page: 1, start: 42,  end: 56,  masked_preview: '9876 **** ****' },
    { id: 'F-002', type: 'PAN',       confidence: 0.99, page: 1, start: 110, end: 120, masked_preview: 'ABCDE****' },
    { id: 'F-003', type: 'PHONE',     confidence: 0.93, page: 1, start: 155, end: 170, masked_preview: '+91 9876*****' },
    { id: 'F-004', type: 'EMAIL',     confidence: 0.98, page: 2, start: 200, end: 219, masked_preview: 'ci***@example.com' },
    { id: 'F-005', type: 'NAME',      confidence: 0.84, page: 1, start: 10,  end: 22,  masked_preview: 'Ra*** Sh***' },
    { id: 'F-006', type: 'FINANCIAL', confidence: 0.91, page: 3, start: 300, end: 310, masked_preview: '₹**,**,***' },
  ];

  const riskScore = destination === 'llm' ? 78 : destination === 'external' ? 62 : 34;

  let action: KnownAction = 'ALLOW';
  if (riskScore >= 75)      action = 'BLOCK';
  else if (riskScore >= 55) action = 'QUARANTINE';
  else if (riskScore >= 25) action = 'REDACT_AND_FORWARD';

  const reasons: string[] = [];
  if (riskScore >= 55) reasons.push('Risk score exceeds department threshold');
  if (destination === 'llm') reasons.push('LLM destinations require full PII masking per policy');
  if (findings.some(f => f.type === 'AADHAAR')) reasons.push('Aadhaar detected – DPDP Act Section 8(5) applies');
  if (findings.some(f => f.type === 'PAN'))     reasons.push('PAN card data present – financial data protection required');
  if (action === 'ALLOW')   reasons.push('Risk within acceptable threshold for internal routing');

  const docId = `SCN-${Date.now().toString(36).toUpperCase()}`;
  return {
    doc_id: docId,
    filename,
    format: filename.split('.').pop()?.toUpperCase() ?? 'UNKNOWN',
    sensitivity: riskScore >= 70 ? 'TOP SECRET' : riskScore >= 45 ? 'CONFIDENTIAL' : 'INTERNAL',
    risk_score: riskScore,
    findings,
    decision: { action, reasons },
    mock: true,
  };
}

function mockRedactResult(
  docId: string,
  totalFindings: number,
  originalFilename: string,
  _mode: RedactionMode
): RedactResult {
  const relUrl = `/api/v1/dlp/download/${docId}`;
  return {
    doc_id: docId,
    download_url: relUrl,
    findings_removed: totalFindings,
    findings_remaining: 0,
    verified: true,
    mock: true,
    resolved_download_url: resolveDownloadUrl(relUrl),
    download_filename: `redacted_${originalFilename}`,
  };
}

function mockAuditLog(): AuditEntry[] {
  return [
    {
      id: 'AUD-SR-001',
      timestamp: new Date(Date.now() - 3_600_000).toISOString(),
      scan_id: 'SCN-M8X2A',
      filename: 'employee_records.docx',
      department: 'hr',
      destination: 'llm',
      policy_decision: 'BLOCK',
      risk_score: 82,
      findings_count: 14,
      action_taken: 'Document upload blocked – LLM egress denied',
    },
    {
      id: 'AUD-SR-002',
      timestamp: new Date(Date.now() - 7_200_000).toISOString(),
      scan_id: 'SCN-K3P9Q',
      filename: 'loan_application.pdf',
      department: 'banking',
      destination: 'internal',
      policy_decision: 'REDACT_AND_FORWARD',
      risk_score: 48,
      findings_count: 6,
      action_taken: 'PII redacted – forwarded to internal processing',
    },
    {
      id: 'AUD-SR-003',
      timestamp: new Date(Date.now() - 14_400_000).toISOString(),
      scan_id: 'SCN-R7T1B',
      filename: 'patient_summary.txt',
      department: 'healthcare',
      destination: 'external',
      policy_decision: 'QUARANTINE',
      risk_score: 61,
      findings_count: 9,
      action_taken: 'Quarantined – external sharing requires manual review',
    },
    {
      id: 'AUD-SR-004',
      timestamp: new Date(Date.now() - 86_400_000).toISOString(),
      scan_id: 'SCN-J5V3C',
      filename: 'contract_draft.docx',
      department: 'legal',
      destination: 'internal',
      policy_decision: 'ALLOW',
      risk_score: 12,
      findings_count: 1,
      action_taken: 'Allowed – risk within threshold',
    },
  ];
}

// ─── API functions ────────────────────────────────────────────────────────────

/**
 * POST /api/v1/dlp/scan
 * Multipart form: file, destination, department
 */
export async function apiScan(
  file: File,
  destination: Destination,
  department: Department
): Promise<ScanResult> {
  if (FORCE_MOCK) {
    await delay(1200);
    return mockScanResult(file.name, destination, department);
  }

  let res: Response;
  try {
    const form = new FormData();
    form.append('file', file);
    form.append('destination', destination);
    form.append('department', department);
    res = await fetch(`${BASE}/api/v1/dlp/scan`, { method: 'POST', body: form });
  } catch (networkErr) {
    // Network error (backend unreachable) → mock
    await delay(1200);
    return mockScanResult(file.name, destination, department);
  }

  if (!res.ok) {
    const msg = await extractErrorMessage(res);
    throw new ApiError(res.status, msg);
  }

  const data = await res.json();
  const findings: ScanFinding[] = (data.findings || []).map((f: any, idx: number) => ({
    id: f.id || f.rule_id || `F-${String(idx + 1).padStart(3, '0')}`,
    type: f.type || f.entity_type || 'UNKNOWN',
    confidence: f.confidence ?? 1.0,
    page: f.page ?? 1,
    start: f.start ?? 0,
    end: f.end ?? 0,
    masked_preview: f.masked_preview || '***',
  }));

  return {
    ...data,
    findings,
  };
}

/**
 * POST /api/v1/dlp/redact
 * Multipart form: file, mode
 * Returns RedactResult with resolved download URL and suggested filename.
 */
export async function apiRedact(
  file: File,
  docId: string,
  mode: RedactionMode,
  totalFindings: number
): Promise<RedactResult> {
  if (FORCE_MOCK) {
    await delay(900);
    return mockRedactResult(docId, totalFindings, file.name, mode);
  }

  let res: Response;
  try {
    const form = new FormData();
    form.append('file', file);
    form.append('mode', mode);
    res = await fetch(`${BASE}/api/v1/dlp/redact`, { method: 'POST', body: form });
  } catch {
    // Network error → mock
    await delay(900);
    return mockRedactResult(docId, totalFindings, file.name, mode);
  }

  if (!res.ok) {
    const msg = await extractErrorMessage(res);
    throw new ApiError(res.status, msg);
  }

  const data = await res.json();
  return {
    ...data,
    resolved_download_url: resolveDownloadUrl(data.download_url ?? ''),
    download_filename: `redacted_${file.name}`,
  };
}

/**
 * GET /api/v1/dlp/audit
 */
export async function apiAuditLog(): Promise<AuditEntry[]> {
  if (FORCE_MOCK) {
    await delay(400);
    return mockAuditLog();
  }

  let res: Response;
  try {
    res = await fetch(`${BASE}/api/v1/dlp/audit`);
  } catch {
    // Network error → mock
    await delay(400);
    return mockAuditLog();
  }

  if (!res.ok) {
    const msg = await extractErrorMessage(res);
    throw new ApiError(res.status, msg);
  }

  const data = await res.json();
  const rawList = Array.isArray(data) ? data : (data.entries ?? data.results ?? []);
  return rawList.map((inc: any, idx: number) => ({
    id: inc.incident_id || inc.id || `AUD-${String(idx + 1).padStart(3, '0')}`,
    timestamp: inc.timestamp || new Date().toISOString(),
    scan_id: inc.doc_id || inc.scan_id || 'N/A',
    filename: inc.filename || 'unknown',
    department: inc.department || 'general',
    destination: inc.destination || 'external',
    policy_decision: inc.decision?.action || inc.policy_decision || 'ALLOW',
    risk_score: inc.risk_score ?? 0,
    findings_count: (inc.findings_summary || []).reduce((acc: number, curr: any) => acc + (curr.count || 1), 0),
    action_taken: (inc.decision?.reasons && inc.decision.reasons[0]) || inc.action_taken || inc.decision?.action || 'Processed',
  }));
}

// ─── Utilities ────────────────────────────────────────────────────────────────

function delay(ms: number): Promise<void> {
  return new Promise(r => setTimeout(r, ms));
}
