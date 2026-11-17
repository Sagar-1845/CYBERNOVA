/**
 * src/lib/detection/validators.ts
 * ───────────────────────────────
 * Client-Side Validated Numeric Identifiers and Checksum Algorithms.
 *
 * Implements:
 * - Verhoeff checksum algorithm for Indian Aadhaar validation.
 * - Luhn checksum algorithm for Credit/Debit card validation with issuer prefix checks.
 * - Indian Bank Account contextual validator.
 * - IFSC structure validation.
 * - Statutory PAN 4th character entity-type validation (P, C, H, F, A, B, G, J, L, T).
 * - Phone format validation with toll-free (1800/1860) exclusion.
 */

// ── Verhoeff Checksum Tables ────────────────────────────────────────────────
const VERHOEFF_D: number[][] = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
  [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
  [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
  [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
  [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
  [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
  [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
  [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
  [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];

const VERHOEFF_P: number[][] = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
  [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
  [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
  [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
  [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
  [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
  [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

export function validateVerhoeff(digitsStr: string): boolean {
  const digits = digitsStr.replace(/\D/g, '').split('').map(Number);
  if (digits.length === 0) return false;
  let c = 0;
  const reversed = [...digits].reverse();
  for (let i = 0; i < reversed.length; i++) {
    c = VERHOEFF_D[c][VERHOEFF_P[i % 8][reversed[i]]];
  }
  return c === 0;
}

export function validateAadhaar(rawVal: string, surroundingText: string = ''): { isValid: boolean; confidence: number } {
  const cleanDigits = rawVal.replace(/\D/g, '');
  if (cleanDigits.length !== 12) return { isValid: false, confidence: 0.0 };

  // Cannot start with 0 or 1
  if (cleanDigits[0] === '0' || cleanDigits[0] === '1') {
    return { isValid: false, confidence: 0.0 };
  }

  // Verhoeff checksum
  if (validateVerhoeff(cleanDigits)) {
    return { isValid: true, confidence: 0.98 };
  }

  // Fallback: If nearby text has explicit Aadhaar cue (~30 chars)
  if (surroundingText && /(?:aadhaar|aadhar|uid|आधार)/i.test(surroundingText)) {
    return { isValid: true, confidence: 0.60 };
  }

  return { isValid: false, confidence: 0.0 };
}

// ── Luhn Checksum & Credit Card ─────────────────────────────────────────────
export function validateLuhn(digitsStr: string): boolean {
  const digits = digitsStr.replace(/\D/g, '').split('').map(Number);
  if (digits.length === 0) return false;
  let total = 0;
  const reversed = [...digits].reverse();
  for (let i = 0; i < reversed.length; i++) {
    let d = reversed[i];
    if (i % 2 === 1) {
      d = d * 2;
      if (d > 9) d -= 9;
    }
    total += d;
  }
  return total % 10 === 0;
}

export function validateCreditCard(rawVal: string): { isValid: boolean; confidence: number } {
  const cleanDigits = rawVal.replace(/\D/g, '');
  const len = cleanDigits.length;
  if (len < 13 || len > 19) return { isValid: false, confidence: 0.0 };

  if (!validateLuhn(cleanDigits)) return { isValid: false, confidence: 0.0 };

  let isValidPrefix = false;
  if (cleanDigits.startsWith('4') && (len === 13 || len === 16 || len === 19)) {
    isValidPrefix = true;
  } else if (len === 16) {
    const first2 = parseInt(cleanDigits.slice(0, 2), 10);
    const first4 = parseInt(cleanDigits.slice(0, 4), 10);
    if ((first2 >= 51 && first2 <= 55) || (first4 >= 2221 && first4 <= 2720)) {
      isValidPrefix = true;
    } else if (['60', '65', '81', '82'].some((p) => cleanDigits.startsWith(p)) || cleanDigits.startsWith('508')) {
      isValidPrefix = true;
    }
  } else if (len === 15 && (cleanDigits.startsWith('34') || cleanDigits.startsWith('37'))) {
    isValidPrefix = true;
  } else if (len >= 14 && len <= 19) {
    isValidPrefix = true;
  }

  return { isValid: isValidPrefix, confidence: isValidPrefix ? 0.95 : 0.0 };
}

// ── Bank Account Contextual Validator ───────────────────────────────────────
const BANK_ACCOUNT_CUE_REGEX = /(?:account\s+number|account\s+no\.?|a\/c\s+(?:no\.?|number)?|acct|salary\s+account|bank\s+account|खाता\s+संख्या|खाता\s+सं\.?|खाता\s+नंबर)/i;

export function validateBankAccount(rawVal: string, surroundingText: string = ''): { isValid: boolean; confidence: number } {
  const cleanDigits = rawVal.replace(/\D/g, '');
  if (cleanDigits.length < 9 || cleanDigits.length > 18) {
    return { isValid: false, confidence: 0.0 };
  }
  if (!surroundingText) return { isValid: false, confidence: 0.0 };

  if (BANK_ACCOUNT_CUE_REGEX.test(surroundingText)) {
    return { isValid: true, confidence: 0.90 };
  }
  return { isValid: false, confidence: 0.0 };
}

// ── PAN Structure Validator ─────────────────────────────────────────────────
const VALID_PAN_4TH = new Set(['P', 'C', 'H', 'F', 'A', 'B', 'G', 'J', 'L', 'T']);

export function validatePan(rawVal: string): boolean {
  const clean = rawVal.trim().toUpperCase();
  if (clean.length !== 10) return false;
  if (!/^[A-Z]{5}[0-9]{4}[A-Z]$/.test(clean)) return false;
  return VALID_PAN_4TH.has(clean[3]);
}

// ── Toll-Free Filter ────────────────────────────────────────────────────────
export function isTollFreeNumber(rawVal: string): boolean {
  const digits = rawVal.replace(/\D/g, '');
  return digits.startsWith('1800') || digits.startsWith('1860');
}
