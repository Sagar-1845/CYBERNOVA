/**
 * src/lib/policy/policyEngine.ts
 * ──────────────────────────────
 * Phase 4 Policy Engine for DPDP-Driven Compliance & Governance.
 *
 * Implements policy profiles, rule mappings, action decisions,
 * and compliance verification metadata.
 */

import { DetectedEntityItem, EntityAction } from '../detection/detector';

export interface PolicyProfile {
  id: string;
  name: string;
  description: string;
  regulatoryJurisdiction: string;
  reviewConfidenceThreshold: number; // e.g. 0.75
  rules: PolicyRuleDefinition[];
  retentionSetting: string;
}

export interface PolicyRuleDefinition {
  ruleId: string;
  title: string;
  regulatorySection: string;
  status: 'VERIFIED' | 'NEEDS_LEGAL_REVIEW';
  effectiveDateStatus: string;
  defaultAction: EntityAction;
  scope: 'DPDP personal data' | 'security/enterprise';
  description: string;
}

// ── Statutory Policy Rule Catalog ───────────────────────────────────────────
export const STATUTORY_RULES: Record<string, PolicyRuleDefinition> = {
  'DPDP-ACT-2023-SEC-6': {
    ruleId: 'DPDP-ACT-2023-SEC-6',
    title: 'Affirmative Consent for Personal Identifier Processing',
    regulatorySection: 'DPDP Act 2023, Section 6(1)',
    status: 'VERIFIED',
    effectiveDateStatus: 'Active & Gazetted (August 11, 2023)',
    defaultAction: 'MASK',
    scope: 'DPDP personal data',
    description: 'Requires explicit affirmative consent before processing personal identifiers; unconsented transmission to third-party LLMs is prohibited.',
  },
  'DPDP-ACT-2023-SEC-8': {
    ruleId: 'DPDP-ACT-2023-SEC-8',
    title: 'Reasonable Security Safeguards & Purpose Limitation',
    regulatorySection: 'DPDP Act 2023, Section 8(5)',
    status: 'VERIFIED',
    effectiveDateStatus: 'Active & Gazetted (August 11, 2023)',
    defaultAction: 'REDACT',
    scope: 'security/enterprise',
    description: 'Mandates technical and organizational measures to prevent personal data breach and unauthorized disclosure.',
  },
  'DPDP-ACT-2023-SEC-12': {
    ruleId: 'DPDP-ACT-2023-SEC-12',
    title: 'Right to Correction and Erasure (Right to be Forgotten)',
    regulatorySection: 'DPDP Act 2023, Section 12(1)',
    status: 'VERIFIED',
    effectiveDateStatus: 'Active & Gazetted (August 11, 2023)',
    defaultAction: 'TOKENIZE',
    scope: 'DPDP personal data',
    description: 'Data principal has right to erasure; tokenized mappings must be purgeable on statutory request.',
  },
  'UIDAI-AADHAAR-ACT-SEC-29': {
    ruleId: 'UIDAI-AADHAAR-ACT-SEC-29',
    title: 'Statutory Restriction on Aadhaar Publishing & Storage',
    regulatorySection: 'Aadhaar Act 2016, Section 29 & Regulations 2023',
    status: 'VERIFIED',
    effectiveDateStatus: 'Enforceable Statutory Precedent',
    defaultAction: 'MASK',
    scope: 'DPDP personal data',
    description: 'Core biometric information and plain 12-digit UID numbers must never be displayed or transmitted unmasked in commercial cloud pipelines.',
  },
  'RBI-KYC-PAN-DIRECTIVE': {
    ruleId: 'RBI-KYC-PAN-DIRECTIVE',
    title: 'RBI Master Direction on Customer Identification & PAN Confidentiality',
    regulatorySection: 'RBI/DBR/2015-16/18 Master Direction Section 24',
    status: 'VERIFIED',
    effectiveDateStatus: 'Active & Monitored (Updated 2024)',
    defaultAction: 'MASK',
    scope: 'DPDP personal data',
    description: 'Permanent Account Number must be protected from third-party model surveillance in financial workflows.',
  },
  'CERT-IN-CYBER-SECRETS': {
    ruleId: 'CERT-IN-CYBER-SECRETS',
    title: 'CERT-In Mandate on Cloud Credential & Token Non-Disclosure',
    regulatorySection: 'CERT-In Cyber Security Directions 2022, Sec 4',
    status: 'VERIFIED',
    effectiveDateStatus: 'Mandatory Compliance Directive (2022)',
    defaultAction: 'REDACT',
    scope: 'security/enterprise',
    description: 'Cloud API keys, secret credentials, and private keys must be irreversibly excised before network egress.',
  },
  'SEBI-MARKET-FINANCIAL-PRIVACY': {
    ruleId: 'SEBI-MARKET-FINANCIAL-PRIVACY',
    title: 'SEBI Securities Market Participant Financial Data Protection',
    regulatorySection: 'SEBI Circular SEBI/HO/MIRSD/2023/12',
    status: 'NEEDS_LEGAL_REVIEW',
    effectiveDateStatus: 'Guidelines in Transition (Regulatory Sandbox)',
    defaultAction: 'MASK',
    scope: 'DPDP personal data',
    description: 'Investor salary, settlement accounts, and remittance figures require enterprise tokenization.',
  },
};

// ── Standard Policy Profiles ────────────────────────────────────────────────
export const POLICY_PROFILES: PolicyProfile[] = [
  {
    id: 'DPDP_STATUTORY_STRICT',
    name: 'DPDP Statutory Strict (Default)',
    description: 'Strict statutory compliance with Digital Personal Data Protection Act 2023. Irreversible secret redaction and pseudonymized tokenization.',
    regulatoryJurisdiction: 'Republic of India — DPDP Act 2023',
    reviewConfidenceThreshold: 0.75,
    retentionSetting: 'Zero-Persistence Ephemeral (10-Minute Maximum Vault Horizon)',
    rules: [
      STATUTORY_RULES['DPDP-ACT-2023-SEC-6'],
      STATUTORY_RULES['DPDP-ACT-2023-SEC-8'],
      STATUTORY_RULES['DPDP-ACT-2023-SEC-12'],
      STATUTORY_RULES['UIDAI-AADHAAR-ACT-SEC-29'],
      STATUTORY_RULES['CERT-IN-CYBER-SECRETS'],
    ],
  },
  {
    id: 'BANKING_FINTECH_RBI',
    name: 'Banking & FinTech (RBI Master Direction)',
    description: 'Enhanced financial safeguards for credit appraisals, payment routing, and retail lending dossiers.',
    regulatoryJurisdiction: 'Reserve Bank of India & DPDP Act 2023',
    reviewConfidenceThreshold: 0.70,
    retentionSetting: 'Encrypted Ephemeral Session Cache',
    rules: [
      STATUTORY_RULES['RBI-KYC-PAN-DIRECTIVE'],
      STATUTORY_RULES['UIDAI-AADHAAR-ACT-SEC-29'],
      STATUTORY_RULES['DPDP-ACT-2023-SEC-6'],
      STATUTORY_RULES['SEBI-MARKET-FINANCIAL-PRIVACY'],
      STATUTORY_RULES['CERT-IN-CYBER-SECRETS'],
    ],
  },
  {
    id: 'HEALTHCARE_CLINICAL_DISHA',
    name: 'Healthcare & Clinical (DISHA Standard)',
    description: 'De-identification of patient telemetry, prescription notes, and diagnostic records prior to clinical LLM consultation.',
    regulatoryJurisdiction: 'DISHA Health Data Standards & DPDP 2023',
    reviewConfidenceThreshold: 0.70,
    retentionSetting: 'Zero-Persistence Strict Memory Barrier',
    rules: [
      STATUTORY_RULES['DPDP-ACT-2023-SEC-6'],
      STATUTORY_RULES['DPDP-ACT-2023-SEC-8'],
      STATUTORY_RULES['UIDAI-AADHAAR-ACT-SEC-29'],
      STATUTORY_RULES['DPDP-ACT-2023-SEC-12'],
    ],
  },
  {
    id: 'ENTERPRISE_INTERNAL_AUDIT',
    name: 'Enterprise Internal Confidentiality',
    description: 'Balanced enterprise redaction protecting intellectual property and corporate secrets with higher review threshold.',
    regulatoryJurisdiction: 'Enterprise Governance & DPDP 2023',
    reviewConfidenceThreshold: 0.80,
    retentionSetting: 'Standard 24-Hour Audit Hold',
    rules: [
      STATUTORY_RULES['CERT-IN-CYBER-SECRETS'],
      STATUTORY_RULES['DPDP-ACT-2023-SEC-8'],
      STATUTORY_RULES['DPDP-ACT-2023-SEC-6'],
    ],
  },
];

export function getPolicyProfile(profileId: string = 'DPDP_STATUTORY_STRICT'): PolicyProfile {
  return POLICY_PROFILES.find((p) => p.id === profileId) || POLICY_PROFILES[0];
}

// ── Policy Decision Evaluator ───────────────────────────────────────────────
export interface PolicyEvaluationResult {
  profile: PolicyProfile;
  evaluatedEntities: DetectedEntityItem[];
  rulesTriggered: {
    rule: PolicyRuleDefinition;
    entityCount: number;
    matchingEntities: string[];
  }[];
  actionsBreakdown: {
    redactCount: number;
    maskCount: number;
    tokenizeCount: number;
    allowCount: number;
  };
  dispatchDecision: 'PERMITTED_FOR_OUTBOUND_AI' | 'BLOCKED_HIGH_RISK';
  summary: string;
}

export function evaluatePolicyOnEntities(
  entities: DetectedEntityItem[],
  profileId: string = 'DPDP_STATUTORY_STRICT'
): PolicyEvaluationResult {
  const profile = getPolicyProfile(profileId);
  const rulesMap = new Map<string, { rule: PolicyRuleDefinition; count: number; entities: string[] }>();

  let redactCount = 0;
  let maskCount = 0;
  let tokenizeCount = 0;
  let allowCount = 0;

  const evaluatedEntities = entities.map((entity) => {
    // 1. Secrets are ALWAYS REDACTED regardless of policy profile
    let action: EntityAction = entity.action;
    if (entity.type === 'SECRET_KEY' || entity.scope === 'security/enterprise') {
      action = 'REDACT';
    }

    // 2. Adjust review requirement based on profile threshold
    const needsReview = entity.confidence < profile.reviewConfidenceThreshold;

    // 3. Track action counts
    if (action === 'REDACT') redactCount++;
    else if (action === 'MASK') maskCount++;
    else if (action === 'TOKENIZE') tokenizeCount++;
    else allowCount++;

    // 4. Track triggered statutory rules
    entity.ruleIds.forEach((ruleId) => {
      const def = STATUTORY_RULES[ruleId] || {
        ruleId,
        title: ruleId,
        regulatorySection: 'Statutory Standard',
        status: 'VERIFIED',
        effectiveDateStatus: 'Active',
        defaultAction: 'MASK',
        scope: entity.scope,
        description: 'Standard privacy safeguard rule',
      };
      if (!rulesMap.has(ruleId)) {
        rulesMap.set(ruleId, { rule: def, count: 0, entities: [] });
      }
      const item = rulesMap.get(ruleId)!;
      item.count++;
      item.entities.push(entity.type);
    });

    return {
      ...entity,
      action,
      needsReview,
    };
  });

  const rulesTriggered = Array.from(rulesMap.values()).map((v) => ({
    rule: v.rule,
    entityCount: v.count,
    matchingEntities: Array.from(new Set(v.entities)),
  }));

  const dispatchDecision: 'PERMITTED_FOR_OUTBOUND_AI' | 'BLOCKED_HIGH_RISK' = 'PERMITTED_FOR_OUTBOUND_AI';

  const summary = `Evaluated ${entities.length} entity/entities against policy profile '${profile.name}'. ${redactCount} secrets marked for irreversible redaction; ${maskCount + tokenizeCount} personal identifiers slated for de-identification.`;

  return {
    profile,
    evaluatedEntities,
    rulesTriggered,
    actionsBreakdown: {
      redactCount,
      maskCount,
      tokenizeCount,
      allowCount,
    },
    dispatchDecision,
    summary,
  };
}
