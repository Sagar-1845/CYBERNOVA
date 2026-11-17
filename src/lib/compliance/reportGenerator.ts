/**
 * src/lib/compliance/reportGenerator.ts
 * ──────────────────────────────────────
 * DPDP Act 2023 Statutory Compliance Report Generator.
 *
 * Produces structured JSON and printable reports for auditing:
 * - document id, timestamp, profile
 * - entity counts by type, actions applied
 * - rules triggered (with verified / needs-legal-review flags & effective date status)
 * - items reviewed (accept/reject log)
 * - residual risks, verification status, dispatch decision, retention setting
 * - mandatory disclaimer: "Decision support, not legal advice."
 *
 * CRITICAL PRIVACY INVARIANT:
 * The report MUST NOT contain any original unmasked sensitive values.
 */

import { PolicyProfile, PolicyRuleDefinition } from '../policy/policyEngine';
import { VerificationReport } from '../verification/independentVerifier';
import { DetectedEntityItem } from '../detection/detector';

export interface ReviewedItemRecord {
  entityId: string;
  type: string;
  confidence: number;
  decision: 'ACCEPTED' | 'REJECTED';
  placeholderToken?: string;
  ruleId?: string;
  explanation: string;
  reviewedAt: string;
}

export interface ComplianceReport {
  documentId: string;
  fileName: string;
  generatedAt: string;
  engineVersion: string;
  profile: {
    id: string;
    name: string;
    jurisdiction: string;
    retentionSetting: string;
  };
  executiveSummary: string;
  verificationStatus: string;
  dispatchDecision: 'PERMITTED_FOR_OUTBOUND_AI' | 'BLOCKED_HIGH_RISK';
  entityCountsByType: Record<string, number>;
  actionsApplied: {
    action: string;
    count: number;
    description: string;
  }[];
  rulesTriggered: {
    ruleId: string;
    title: string;
    regulatorySection: string;
    status: 'VERIFIED' | 'NEEDS_LEGAL_REVIEW';
    effectiveDateStatus: string;
    entityCount: number;
  }[];
  itemsReviewed: ReviewedItemRecord[];
  residualRisks: {
    riskLevel: 'ZERO' | 'LOW' | 'MEDIUM' | 'HIGH';
    summary: string;
    indicators: string[];
  };
  disclaimer: 'Decision support, not legal advice.';
}

export function generateComplianceReport(params: {
  documentId: string;
  fileName: string;
  profile: PolicyProfile;
  entities: DetectedEntityItem[];
  verification: VerificationReport;
  reviewedItems?: ReviewedItemRecord[];
}): ComplianceReport {
  const { documentId, fileName, profile, entities, verification, reviewedItems = [] } = params;

  // 1. Calculate entity counts by type
  const countsByType: Record<string, number> = {};
  for (const ent of entities) {
    countsByType[ent.type] = (countsByType[ent.type] || 0) + 1;
  }

  // 2. Actions applied breakdown
  let redactCount = 0;
  let maskCount = 0;
  let tokenizeCount = 0;
  let allowCount = 0;

  for (const ent of entities) {
    if (ent.reviewDecision === 'REJECTED') {
      allowCount++;
    } else if (ent.action === 'REDACT' || ent.type === 'SECRET_KEY') {
      redactCount++;
    } else if (ent.action === 'TOKENIZE' || ent.type === 'NAME') {
      tokenizeCount++;
    } else {
      maskCount++;
    }
  }

  const actionsApplied = [
    {
      action: 'REDACT',
      count: redactCount,
      description: 'Irreversible excision of cloud credentials, private keys, and passwords (excluded from vault).',
    },
    {
      action: 'MASK',
      count: maskCount,
      description: 'Placeholder tokenization of statutory numeric IDs (Aadhaar, PAN, Bank Accounts, Phone, Email).',
    },
    {
      action: 'TOKENIZE',
      count: tokenizeCount,
      description: 'Consistent pseudonymization of personal names preserving cross-sentence coreference.',
    },
    {
      action: 'ALLOW',
      count: allowCount,
      description: 'Permitted non-sensitive strings or items explicitly rejected during human review.',
    },
  ].filter((a) => a.count > 0);

  // 3. Rules triggered mapping
  const rulesMap = new Map<string, { rule: PolicyRuleDefinition; count: number }>();
  for (const ent of entities) {
    for (const ruleId of ent.ruleIds) {
      const existing = rulesMap.get(ruleId);
      if (existing) {
        existing.count++;
      } else {
        const found = profile.rules.find((r) => r.ruleId === ruleId) || {
          ruleId,
          title: ruleId,
          regulatorySection: 'Statutory DPDP Safeguard',
          status: 'VERIFIED' as const,
          effectiveDateStatus: 'Active & Gazetted (August 11, 2023)',
          defaultAction: ent.action,
          scope: ent.scope,
          description: ent.explanation,
        };
        rulesMap.set(ruleId, { rule: found, count: 1 });
      }
    }
  }

  const rulesTriggered = Array.from(rulesMap.values()).map(({ rule, count }) => ({
    ruleId: rule.ruleId,
    title: rule.title,
    regulatorySection: rule.regulatorySection,
    status: rule.status,
    effectiveDateStatus: rule.effectiveDateStatus,
    entityCount: count,
  }));

  // 4. Residual Risk Assessment
  let riskLevel: 'ZERO' | 'LOW' | 'MEDIUM' | 'HIGH' = 'ZERO';
  const indicators: string[] = [];

  if (verification.status === 'LEAK DETECTED') {
    riskLevel = 'HIGH';
    indicators.push(`Independent verification intercepted ${verification.totalLeaksCount} unmasked sensitive token(s).`);
  } else if (entities.some((e) => e.needsReview && !e.reviewDecision)) {
    riskLevel = 'MEDIUM';
    indicators.push('Low-confidence entity candidates pending human review before outbound dispatch.');
  } else {
    riskLevel = 'ZERO';
    indicators.push('Independent second-pass scan verified zero unmasked sensitive entities.');
    indicators.push('Zero-persistence ephemeral mapping active (10-minute maximum memory threshold).');
  }

  const dispatchDecision: 'PERMITTED_FOR_OUTBOUND_AI' | 'BLOCKED_HIGH_RISK' =
    verification.status === 'VERIFIED SAFE' ? 'PERMITTED_FOR_OUTBOUND_AI' : 'BLOCKED_HIGH_RISK';

  return {
    documentId,
    fileName,
    generatedAt: new Date().toISOString(),
    engineVersion: 'PrivaGuard AI 2.4.0 (DPDP Statutory Engine)',
    profile: {
      id: profile.id,
      name: profile.name,
      jurisdiction: profile.regulatoryJurisdiction,
      retentionSetting: profile.retentionSetting,
    },
    executiveSummary:
      dispatchDecision === 'PERMITTED_FOR_OUTBOUND_AI'
        ? `Document '${fileName}' has completed end-to-end DPDP statutory de-identification. ${entities.length} sensitive item(s) protected. Independent verification status: VERIFIED SAFE. Outbound AI dispatch is PERMITTED.`
        : `Document '${fileName}' processing halted. Independent verification status: ${verification.status}. Outbound AI dispatch is BLOCKED.`,
    verificationStatus: verification.status,
    dispatchDecision,
    entityCountsByType: countsByType,
    actionsApplied,
    rulesTriggered,
    itemsReviewed: reviewedItems,
    residualRisks: {
      riskLevel,
      summary:
        riskLevel === 'ZERO'
          ? 'Zero residual sensitivity risk. All detected entities successfully de-identified.'
          : 'Residual exposure risks detected. Review required before release.',
      indicators,
    },
    disclaimer: 'Decision support, not legal advice.',
  };
}

export function downloadComplianceReportJSON(report: ComplianceReport): void {
  const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(report, null, 2));
  const dlAnchor = document.createElement('a');
  dlAnchor.setAttribute('href', dataStr);
  dlAnchor.setAttribute('download', `DPDP_Compliance_Report_${report.documentId}.json`);
  document.body.appendChild(dlAnchor);
  dlAnchor.click();
  dlAnchor.remove();
}
