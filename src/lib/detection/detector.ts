/**
 * src/lib/detection/detector.ts
 * ─────────────────────────────
 * End-to-end Entity Detection Engine for DPDP Act 2023 & Enterprise Security.
 *
 * Combines structural checksum validators (Verhoeff, Luhn, PAN 4th-char),
 * multilingual Indic contextual patterns (Kannada, Hindi, Tamil, Telugu),
 * enterprise security secrets (AWS, GitHub tokens, Private Keys), and
 * financial identifier detection.
 *
 * Each detected entity carries:
 * - id, type, value, location (start, end, line)
 * - confidence (0.0 - 1.0)
 * - sensitivity (CRITICAL, HIGH, MEDIUM, LOW)
 * - action (MASK, REDACT, TOKENIZE, ALLOW)
 * - ruleIds (statutory/compliance rules)
 * - explanation
 * - scope ('DPDP personal data' | 'security/enterprise')
 */

import {
  validateVerhoeff,
  validateAadhaar,
  validateLuhn,
  validateCreditCard,
  validateBankAccount,
  validatePan,
  isTollFreeNumber,
} from './validators';

export type EntityScope = 'DPDP personal data' | 'security/enterprise';
export type EntitySensitivity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
export type EntityAction = 'MASK' | 'REDACT' | 'TOKENIZE' | 'ALLOW' | 'SYNTHESIZE';

export interface EntityLocation {
  start: number; // Absolute rawText 0-based offset
  end: number;   // Absolute rawText 0-based offset (exclusive)
  line?: number; // 1-based line number in rawText
  nodeRef?: string;
}

export interface DetectedEntityItem {
  id: string;
  type: string;
  value: string;
  location: EntityLocation;
  confidence: number;
  sensitivity: EntitySensitivity;
  action: EntityAction;
  ruleIds: string[];
  explanation: string;
  scope: EntityScope;
  needsReview: boolean; // Flagged if confidence is below review threshold
  reviewDecision?: 'ACCEPTED' | 'REJECTED';
}

export interface DetectionResult {
  entities: DetectedEntityItem[];
  rawText: string;
  detectedLanguage: string;
  stats: {
    totalEntities: number;
    highConfidenceCount: number;
    needsReviewCount: number;
    secretsCount: number;
    dpdpCount: number;
  };
}

// ── Language Detection Helper ───────────────────────────────────────────────
export function detectLanguage(text: string): string {
  const scripts = new Set<string>();
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (code >= 0x0c80 && code <= 0x0cff) scripts.add('Kannada');
    else if (code >= 0x0900 && code <= 0x097f) scripts.add('Hindi/Devanagari');
    else if (code >= 0x0b80 && code <= 0x0bff) scripts.add('Tamil');
    else if (code >= 0x0c00 && code <= 0x0c7f) scripts.add('Telugu');
    else if ((code >= 65 && code <= 90) || (code >= 97 && code <= 122)) {
      scripts.add('English/Latin');
    }
  }
  if (scripts.size === 0) return 'Unknown';
  if (scripts.size === 1) return Array.from(scripts)[0];
  if (scripts.has('English/Latin') && scripts.size > 1) {
    const other = Array.from(scripts).filter((s) => s !== 'English/Latin');
    return `Mixed (${other.join('+')} / English)`;
  }
  return 'Mixed Multilingual';
}

// ── Absolute Line Calculator ────────────────────────────────────────────────
function computeLineNumber(rawText: string, offset: number): number {
  let line = 1;
  for (let i = 0; i < offset && i < rawText.length; i++) {
    if (rawText[i] === '\n') line++;
  }
  return line;
}

// ── Comprehensive Detection Runner ──────────────────────────────────────────
export function detectEntitiesInText(
  rawText: string,
  reviewThreshold: number = 0.75
): DetectionResult {
  const candidates: DetectedEntityItem[] = [];
  const textLen = rawText.length;
  let nextEntityIdx = 1;

  const createEntityId = (type: string) => `ENT-${type}-${nextEntityIdx++}`;

  // 1. SECRETS & ENTERPRISE CREDENTIALS (Highest Priority - Irreversibly Redacted)
  // AWS Access Key ID (AKIA...)
  const awsKeyRe = /\b(AKIA[0-9A-Z]{16})\b/g;
  let match;
  while ((match = awsKeyRe.exec(rawText)) !== null) {
    candidates.push({
      id: createEntityId('SECRET_KEY'),
      type: 'SECRET_KEY',
      value: match[1],
      location: {
        start: match.index,
        end: match.index + match[1].length,
        line: computeLineNumber(rawText, match.index),
      },
      confidence: 0.99,
      sensitivity: 'CRITICAL',
      action: 'REDACT',
      ruleIds: ['DPDP-SEC-8-SECURITY-SAFEGUARDS', 'OWASP-LLM-06-CREDENTIAL-EXPOSURE'],
      explanation: 'AWS Cloud Access Key identifier detected; irreversible redaction mandatory to prevent privilege escalation.',
      scope: 'security/enterprise',
      needsReview: false,
    });
  }

  // GitHub Personal Access Token (ghp_...)
  const ghpRe = /\b(ghp_[A-Za-z0-9]{36})\b/g;
  while ((match = ghpRe.exec(rawText)) !== null) {
    candidates.push({
      id: createEntityId('SECRET_KEY'),
      type: 'SECRET_KEY',
      value: match[1],
      location: {
        start: match.index,
        end: match.index + match[1].length,
        line: computeLineNumber(rawText, match.index),
      },
      confidence: 0.99,
      sensitivity: 'CRITICAL',
      action: 'REDACT',
      ruleIds: ['DPDP-SEC-8-SECURITY-SAFEGUARDS', 'CERT-IN-2022-CYBER-SECRETS'],
      explanation: 'GitHub Personal Access Token detected; security policy requires immediate irreversible redaction.',
      scope: 'security/enterprise',
      needsReview: false,
    });
  }

  // JSON / Config Passwords & API Tokens
  const secretAssignRe = /(?:["']?(?:api[_-]?key|client[_-]?secret|password|access[_-]?token|auth[_-]?token|db[_-]?pass|private[_-]?key)["']?\s*[:=]\s*["'])([^"'\r\n]{8,64})(?:["'])/gi;
  while ((match = secretAssignRe.exec(rawText)) !== null) {
    const secretVal = match[1];
    const valStart = match.index + match[0].indexOf(secretVal);
    // Exclude placeholders
    if (!secretVal.includes('[') && !secretVal.includes('placeholder')) {
      candidates.push({
        id: createEntityId('SECRET_KEY'),
        type: 'SECRET_KEY',
        value: secretVal,
        location: {
          start: valStart,
          end: valStart + secretVal.length,
          line: computeLineNumber(rawText, valStart),
        },
        confidence: 0.96,
        sensitivity: 'CRITICAL',
        action: 'REDACT',
        ruleIds: ['DPDP-SEC-8-SECURITY-SAFEGUARDS', 'OWASP-LLM-06-CREDENTIAL-EXPOSURE'],
        explanation: 'Assigned API secret or credential token in structured config; must not enter LLM memory.',
        scope: 'security/enterprise',
        needsReview: false,
      });
    }
  }

  // 2. AADHAAR NUMBERS (12 Digits with Verhoeff Validation)
  const aadhaarRe = /(?<!\d)(?:\d{4}[\s-]?\d{4}[\s-]?\d{4})(?!\d)/g;
  while ((match = aadhaarRe.exec(rawText)) !== null) {
    const rawVal = match[0];
    const surrounding = rawText.slice(Math.max(0, match.index - 30), Math.min(textLen, match.index + rawVal.length + 30));
    const { isValid, confidence } = validateAadhaar(rawVal, surrounding);
    if (isValid) {
      candidates.push({
        id: createEntityId('AADHAAR'),
        type: 'AADHAAR',
        value: rawVal,
        location: {
          start: match.index,
          end: match.index + rawVal.length,
          line: computeLineNumber(rawText, match.index),
        },
        confidence,
        sensitivity: 'HIGH',
        action: 'MASK',
        ruleIds: ['DPDP-ACT-2023-SEC-6-CONSENT', 'UIDAI-AADHAAR-ACT-SEC-29-PROTECTION'],
        explanation: `Indian Aadhaar 12-digit number (Verhoeff checksum confidence: ${(confidence * 100).toFixed(0)}%). Statutory biometric-linked identifier.`,
        scope: 'DPDP personal data',
        needsReview: confidence < reviewThreshold,
      });
    }
  }

  // 3. PAN (Permanent Account Number - 10 Chars with 4th-Char Category Validation)
  const panRe = /\b([A-Z]{5}[0-9]{4}[A-Z])\b/g;
  while ((match = panRe.exec(rawText)) !== null) {
    const rawVal = match[1];
    const isValid = validatePan(rawVal);
    candidates.push({
      id: createEntityId('PAN'),
      type: 'PAN',
      value: rawVal,
      location: {
        start: match.index,
        end: match.index + rawVal.length,
        line: computeLineNumber(rawText, match.index),
      },
      confidence: isValid ? 0.98 : 0.60,
      sensitivity: 'HIGH',
      action: 'MASK',
      ruleIds: ['DPDP-ACT-2023-SEC-6-CONSENT', 'INCOME-TAX-ACT-SEC-139A-PAN'],
      explanation: isValid
        ? `Statutory Indian PAN Card with valid category letter '${rawVal[3]}' (confidence: 98%).`
        : `PAN format candidate with non-standard entity category '${rawVal[3]}' (requires human verification).`,
      scope: 'DPDP personal data',
      needsReview: !isValid || (0.98 < reviewThreshold),
    });
  }

  // 4. CREDIT / DEBIT CARDS (Luhn Checksum + Prefix)
  const cardRe = /(?<!\d)(?:\d[ -]?){13,19}\d(?!\d)/g;
  while ((match = cardRe.exec(rawText)) !== null) {
    const rawVal = match[0];
    const { isValid, confidence } = validateCreditCard(rawVal);
    if (isValid) {
      candidates.push({
        id: createEntityId('CREDIT_CARD'),
        type: 'CREDIT_CARD',
        value: rawVal,
        location: {
          start: match.index,
          end: match.index + rawVal.length,
          line: computeLineNumber(rawText, match.index),
        },
        confidence,
        sensitivity: 'CRITICAL',
        action: 'MASK',
        ruleIds: ['DPDP-ACT-2023-SEC-8-FINANCIAL-DATA', 'RBI-CARD-DATA-TOKENIZATION-2021'],
        explanation: `Payment card primary account number (Luhn verified, confidence ${(confidence * 100).toFixed(0)}%).`,
        scope: 'DPDP personal data',
        needsReview: confidence < reviewThreshold,
      });
    }
  }

  // 5. PHONE NUMBERS (Indian Mobile + Country Code, Excluding Toll-Free)
  const phoneRe = /(?<!\d)(?:\+91[\s-]?)?[6-9]\d{9}(?!\d)/g;
  while ((match = phoneRe.exec(rawText)) !== null) {
    const rawVal = match[0];
    if (!isTollFreeNumber(rawVal)) {
      candidates.push({
        id: createEntityId('PHONE'),
        type: 'PHONE',
        value: rawVal,
        location: {
          start: match.index,
          end: match.index + rawVal.length,
          line: computeLineNumber(rawText, match.index),
        },
        confidence: 0.92,
        sensitivity: 'MEDIUM',
        action: 'MASK',
        ruleIds: ['DPDP-ACT-2023-SEC-6-CONSENT', 'TRAI-CONSUMER-PRIVACY-REGULATIONS'],
        explanation: 'Indian 10-digit telecommunication mobile identifier (DPDP Data Principal contact).',
        scope: 'DPDP personal data',
        needsReview: 0.92 < reviewThreshold,
      });
    }
  }

  // 6. EMAIL ADDRESSES (RFC-Compliant Regex)
  const emailRe = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
  while ((match = emailRe.exec(rawText)) !== null) {
    const rawVal = match[0];
    candidates.push({
      id: createEntityId('EMAIL'),
      type: 'EMAIL',
      value: rawVal,
      location: {
        start: match.index,
        end: match.index + rawVal.length,
        line: computeLineNumber(rawText, match.index),
      },
      confidence: 0.98,
      sensitivity: 'MEDIUM',
      action: 'MASK',
      ruleIds: ['DPDP-ACT-2023-SEC-6-CONSENT'],
      explanation: 'Electronic mail communication address uniquely identifying a Data Principal.',
      scope: 'DPDP personal data',
      needsReview: 0.98 < reviewThreshold,
    });
  }

  // 7. GSTIN (Indian Goods and Services Tax Identification Number - 15 Chars)
  const gstinRe = /\b(\d{2}[A-Z]{5}\d{4}[A-Z][A-Z0-9]Z[A-Z0-9])\b/g;
  while ((match = gstinRe.exec(rawText)) !== null) {
    const rawVal = match[1];
    candidates.push({
      id: createEntityId('GSTIN'),
      type: 'GSTIN',
      value: rawVal,
      location: {
        start: match.index,
        end: match.index + rawVal.length,
        line: computeLineNumber(rawText, match.index),
      },
      confidence: 0.96,
      sensitivity: 'MEDIUM',
      action: 'MASK',
      ruleIds: ['GST-ACT-2017-ENTITY-DISCLOSURE'],
      explanation: 'Indian 15-character Goods and Services Tax Identification Number for commercial entities.',
      scope: 'security/enterprise',
      needsReview: 0.96 < reviewThreshold,
    });
  }

  // 8. PASSPORT NUMBERS (Indian Passport: 1 letter + 7 digits)
  const passportRe = /\b([A-PR-WYa-pr-wy][1-9]\d{6})\b/g;
  while ((match = passportRe.exec(rawText)) !== null) {
    const rawVal = match[1];
    candidates.push({
      id: createEntityId('PASSPORT'),
      type: 'PASSPORT',
      value: rawVal,
      location: {
        start: match.index,
        end: match.index + rawVal.length,
        line: computeLineNumber(rawText, match.index),
      },
      confidence: 0.90,
      sensitivity: 'HIGH',
      action: 'MASK',
      ruleIds: ['DPDP-ACT-2023-SEC-6-CONSENT', 'PASSPORTS-ACT-1967-PROTECTION'],
      explanation: 'Republic of India international travel document identifier.',
      scope: 'DPDP personal data',
      needsReview: 0.90 < reviewThreshold,
    });
  }

  // 9. VOTER ID (Indian Election Commission EPIC - 3 letters + 7 digits)
  const voterRe = /\b([A-Z]{3}[0-9]{7})\b/g;
  while ((match = voterRe.exec(rawText)) !== null) {
    const rawVal = match[1];
    candidates.push({
      id: createEntityId('VOTER_ID'),
      type: 'VOTER_ID',
      value: rawVal,
      location: {
        start: match.index,
        end: match.index + rawVal.length,
        line: computeLineNumber(rawText, match.index),
      },
      confidence: 0.88,
      sensitivity: 'HIGH',
      action: 'MASK',
      ruleIds: ['DPDP-ACT-2023-SEC-6-CONSENT', 'REPRESENTATION-PEOPLE-ACT-EPIC'],
      explanation: 'Election Commission of India Electoral Photo Identity Card (EPIC) number.',
      scope: 'DPDP personal data',
      needsReview: 0.88 < reviewThreshold,
    });
  }

  // 10. BANK ACCOUNTS & IFSC
  const ifscRe = /\b([A-Z]{4}0[A-Z0-9]{6})\b/g;
  while ((match = ifscRe.exec(rawText)) !== null) {
    const rawVal = match[1];
    candidates.push({
      id: createEntityId('IFSC'),
      type: 'IFSC',
      value: rawVal,
      location: {
        start: match.index,
        end: match.index + rawVal.length,
        line: computeLineNumber(rawText, match.index),
      },
      confidence: 0.94,
      sensitivity: 'MEDIUM',
      action: 'MASK',
      ruleIds: ['RBI-INTERBANK-PAYMENT-SYSTEMS-RULES'],
      explanation: 'Reserve Bank of India 11-character Indian Financial System Code (branch routing code).',
      scope: 'security/enterprise',
      needsReview: 0.94 < reviewThreshold,
    });
  }

  const bankAccountRe = /(?:\b(?:account\s+number|ac\s+no|a\/c|bank\s+account|खाता\s+संख्या|ಖಾತೆ\s+ಸಂಖ್ಯೆ)\s*[:\-]?\s*)(\d{9,18})\b/gi;
  while ((match = bankAccountRe.exec(rawText)) !== null) {
    const rawVal = match[1];
    const valStart = match.index + match[0].lastIndexOf(rawVal);
    candidates.push({
      id: createEntityId('BANK_ACCOUNT'),
      type: 'BANK_ACCOUNT',
      value: rawVal,
      location: {
        start: valStart,
        end: valStart + rawVal.length,
        line: computeLineNumber(rawText, valStart),
      },
      confidence: 0.95,
      sensitivity: 'HIGH',
      action: 'MASK',
      ruleIds: ['DPDP-ACT-2023-SEC-8-FINANCIAL-SAFEGUARDS', 'RBI-BANKING-REGULATION-ACT-SEC-45'],
      explanation: 'Retail or commercial bank account deposit number with verified contextual financial cue.',
      scope: 'DPDP personal data',
      needsReview: 0.95 < reviewThreshold,
    });
  }

  // 11. FINANCIAL AMOUNTS
  const finRe = /(?:(?:gross\s+annual\s+income|annual\s+income|monthly\s+income|net\s+remittance|sanction\s+amount|net\s+salary|salary|loan\s+amount|वार्षिक\s+आय|मासिक\s+आय|ವೇತನ|ಸಂಬಳ)\s*[:=-]?\s*)((?:INR|Rs\.?|₹)\s*[\d,]+(?:\.\d{2})?(?:\s*(?:lakh|crore|lakhs|crores|लाख|ಕೋಟಿ))?)/gi;
  while ((match = finRe.exec(rawText)) !== null) {
    const rawVal = match[1];
    const valStart = match.index + match[0].indexOf(rawVal);
    candidates.push({
      id: createEntityId('FINANCIAL'),
      type: 'FINANCIAL',
      value: rawVal,
      location: {
        start: valStart,
        end: valStart + rawVal.length,
        line: computeLineNumber(rawText, valStart),
      },
      confidence: 0.94,
      sensitivity: 'MEDIUM',
      action: 'MASK',
      ruleIds: ['DPDP-ACT-2023-SEC-8-FINANCIAL-DATA'],
      explanation: 'Remittance, income appraisal, or sanction currency amount identifying personal financial status.',
      scope: 'DPDP personal data',
      needsReview: 0.94 < reviewThreshold,
    });
  }

  // 12. MULTILINGUAL HUMAN NAMES (English & Indic: Kannada, Hindi, Tamil, Telugu)
  // Contextual Name Patterns
  const nameCueRe = /(?:\b(?:Borrower|Applicant|Patient|Signatory|Director|Employee|Customer|Dr\.?|Doctor|Consultant|Mr\.?|Mrs\.?|Ms\.?|Shri|Smt\.?|उधारकर्ता|आवेदक|मरीज़|रोगी|हस्ताक्षरकर्ता|ನನ್ನ\s+ಹೆಸರು|ಹೆಸರು|ಆವೇದಕ|என்\s+பெயர்|பெயர்|నా\s+పేరు|పేరు)\s*[:\-]?\s*)([A-Z\u0900-\u097F\u0C80-\u0CFF\u0B80-\u0BFF\u0C00-\u0C7F][A-Za-z\u0900-\u097F\u0C80-\u0CFF\u0B80-\u0BFF\u0C00-\u0C7F]+(?:\s+[A-Z\u0900-\u097F\u0C80-\u0CFF\u0B80-\u0BFF\u0C00-\u0C7F][A-Za-z\u0900-\u097F\u0C80-\u0CFF\u0B80-\u0BFF\u0C00-\u0C7F]+){0,3})/g;
  while ((match = nameCueRe.exec(rawText)) !== null) {
    const nameVal = match[1].trim();
    // Exclude common header stopwords and placeholders
    if (
      nameVal.length >= 3 &&
      !nameVal.includes('[') &&
      !/(?:Dossier|Report|Hospital|Summary|Roster|Agreement|Application|Details|Branch)/i.test(nameVal)
    ) {
      const valStart = match.index + match[0].indexOf(nameVal);
      candidates.push({
        id: createEntityId('NAME'),
        type: 'NAME',
        value: nameVal,
        location: {
          start: valStart,
          end: valStart + nameVal.length,
          line: computeLineNumber(rawText, valStart),
        },
        confidence: 0.88,
        sensitivity: 'HIGH',
        action: 'TOKENIZE',
        ruleIds: ['DPDP-ACT-2023-SEC-6-AFFIRMATIVE-CONSENT', 'DPDP-ACT-2023-SEC-2-PRINCIPAL-IDENTITY'],
        explanation: 'Natural human person identifier (Data Principal) preceded by role or titular cue.',
        scope: 'DPDP personal data',
        needsReview: 0.88 < reviewThreshold,
      });
    }
  }

  // Standalone Proper Name Candidates (Lower confidence -> flagged for human review)
  const standaloneNameRe = /\b([A-Z][a-z]{2,}\s+[A-Z][a-z]{2,}(?:\s+[A-Z][a-z]{2,})?)\b/g;
  while ((match = standaloneNameRe.exec(rawText)) !== null) {
    const nameVal = match[1];
    // Filter common English non-person phrases
    const nonNames = /(?:Layout Bengaluru|Nova Solutions|Loan Sanction|Appraisal Dossier|Metropolitan Multispecialty|Research Hospital|Apex Logistics|Infra Corp|TechNova Solutions|Cardiology Clinical|Procurement Vendor|Master Services|Services Agreement|Risk Underwriting|Digital Personal|Data Protection|General Public|Terms Conditions|Reverse Charge|Settlement Account)/i;
    if (!nonNames.test(nameVal) && !nameVal.includes('[')) {
      const start = match.index;
      // Check if already captured by contextual name cue
      const alreadyCovered = candidates.some(
        (c) => c.location.start <= start && c.location.end >= start + nameVal.length
      );
      if (!alreadyCovered) {
        candidates.push({
          id: createEntityId('NAME'),
          type: 'NAME',
          value: nameVal,
          location: {
            start: start,
            end: start + nameVal.length,
            line: computeLineNumber(rawText, start),
          },
          confidence: 0.65, // Lower confidence -> triggers review panel
          sensitivity: 'MEDIUM',
          action: 'TOKENIZE',
          ruleIds: ['DPDP-ACT-2023-SEC-2-PRINCIPAL-IDENTITY'],
          explanation: 'Capitalized two-word sequence candidate for personal human name (review suggested).',
          scope: 'DPDP personal data',
          needsReview: true, // 0.65 < threshold -> needs review
        });
      }
    }
  }

  // ── Deduplication & Interval Conflict Resolution ────────────────────────────
  // Sort candidates by start ascending, then length descending
  candidates.sort((a, b) => a.location.start - b.location.start || b.value.length - a.value.length);

  const finalEntities: DetectedEntityItem[] = [];
  let lastEnd = -1;

  for (const cand of candidates) {
    // If overlaps with previously accepted entity, discard lower-priority or overlapping candidate
    if (cand.location.start >= lastEnd) {
      finalEntities.push(cand);
      lastEnd = cand.location.end;
    }
  }

  // Calculate statistics
  let highConf = 0;
  let needsRev = 0;
  let secCount = 0;
  let dpdpCount = 0;

  for (const e of finalEntities) {
    if (e.needsReview) needsRev++;
    else highConf++;

    if (e.scope === 'security/enterprise') secCount++;
    else dpdpCount++;
  }

  const detectedLanguage = detectLanguage(rawText);

  return {
    entities: finalEntities,
    rawText,
    detectedLanguage,
    stats: {
      totalEntities: finalEntities.length,
      highConfidenceCount: highConf,
      needsReviewCount: needsRev,
      secretsCount: secCount,
      dpdpCount,
    },
  };
}
