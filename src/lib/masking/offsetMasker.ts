/**
 * src/lib/masking/offsetMasker.ts
 * ───────────────────────────────
 * Absolute rawText Offset Masking Engine.
 *
 * Enforces the strict Offset Invariant before any masking operation:
 * 1. rawText.slice(start, end) === entity.value for every entity.
 * 2. Non-overlapping sorted intervals.
 * 3. Refuses to mask and throws OffsetInvariantError if any invariant fails.
 *
 * Ensures:
 * - Paragraphs, line breaks, and whitespace are 100% preserved.
 * - Consistent token mapping: identical sensitive values receive the same token.
 * - Secrets (AWS keys, tokens, passwords) are irreversibly redacted ([REDACTED:SECRET])
 *   and strictly EXCLUDED from the vault mapping.
 */

import { DetectedEntityItem } from '../detection/detector';

export class OffsetInvariantError extends Error {
  constructor(
    message: string,
    public entityId: string,
    public expectedValue: string,
    public actualSlice: string,
    public start: number,
    public end: number
  ) {
    super(message);
    this.name = 'OffsetInvariantError';
  }
}

export interface MaskingResult {
  maskedText: string;
  vaultMapping: Record<string, string>; // Maps placeholder -> original value (EXCLUDING secrets)
  secretsRedacted: {
    entityId: string;
    type: string;
    token: string;
    maskedPreview: string;
  }[];
  appliedTokens: {
    entityId: string;
    type: string;
    token: string;
    start: number;
    end: number;
    line?: number;
  }[];
  invariantVerified: boolean;
  preservedParagraphCount: number;
}

export function maskDocumentByOffsets(
  rawText: string,
  entities: DetectedEntityItem[]
): MaskingResult {
  // 1. Filter only entities with action != 'ALLOW' and not rejected by review
  const activeEntities = entities.filter(
    (e) => e.action !== 'ALLOW' && e.reviewDecision !== 'REJECTED'
  );

  // 2. Sort entities by start offset ascending
  const sorted = [...activeEntities].sort((a, b) => a.location.start - b.location.start);

  // 3. Strict Pre-Masking Invariant Verification
  for (let i = 0; i < sorted.length; i++) {
    const item = sorted[i];
    const { start, end } = item.location;

    // Bounds check
    if (start < 0 || end > rawText.length || start >= end) {
      throw new OffsetInvariantError(
        `Offset boundary violation for entity ${item.id} [${start}, ${end}] in document length ${rawText.length}`,
        item.id,
        item.value,
        '<out-of-bounds>',
        start,
        end
      );
    }

    // Exact string match check
    const actualSlice = rawText.slice(start, end);
    if (actualSlice !== item.value) {
      throw new OffsetInvariantError(
        `Offset invariant failed for entity ${item.id}: expected '${item.value}' but rawText[${start}..${end}] is '${actualSlice}'. Masking aborted to prevent document corruption.`,
        item.id,
        item.value,
        actualSlice,
        start,
        end
      );
    }

    // Overlap check with previous
    if (i > 0) {
      const prev = sorted[i - 1];
      if (prev.location.end > start) {
        throw new OffsetInvariantError(
          `Overlapping offset conflict between ${prev.id} [${prev.location.start}..${prev.location.end}] and ${item.id} [${start}..${end}].`,
          item.id,
          item.value,
          actualSlice,
          start,
          end
        );
      }
    }
  }

  // 4. Generate Consistent Tokens
  // Values that repeat throughout the document receive the exact same placeholder token
  const valueToTokenMap = new Map<string, string>();
  const typeCounters = new Map<string, number>();

  const vaultMapping: Record<string, string> = {};
  const secretsRedacted: MaskingResult['secretsRedacted'] = [];
  const appliedTokens: MaskingResult['appliedTokens'] = [];

  const entitiesWithTokens = sorted.map((item) => {
    let token: string;

    // SECRETS: Irreversible redaction, excluded from vault mapping!
    if (item.type === 'SECRET_KEY' || item.action === 'REDACT' || item.scope === 'security/enterprise') {
      token = '[REDACTED:SECRET]';
      secretsRedacted.push({
        entityId: item.id,
        type: item.type,
        token,
        maskedPreview: item.value.slice(0, 4) + '****' + (item.value.length > 8 ? item.value.slice(-3) : ''),
      });
      // NOTICE: Secrets are NEVER added to vaultMapping!
    } else {
      // DPDP Personal Identifiers: Consistent Tokenization
      const cacheKey = `${item.type}:${item.value}`;
      if (valueToTokenMap.has(cacheKey)) {
        token = valueToTokenMap.get(cacheKey)!;
      } else {
        const count = (typeCounters.get(item.type) || 0) + 1;
        typeCounters.set(item.type, count);
        token = `[${item.type}_${count}]`;
        valueToTokenMap.set(cacheKey, token);
      }
      // Store in vault mapping for restoration
      vaultMapping[token] = item.value;
    }

    appliedTokens.push({
      entityId: item.id,
      type: item.type,
      token,
      start: item.location.start,
      end: item.location.end,
      line: item.location.line,
    });

    return {
      ...item,
      token,
    };
  });

  // 5. Apply Replacements Right-to-Left (Descending Order of Offset)
  // This guarantees all earlier offsets remain perfectly valid throughout the mutation!
  let maskedText = rawText;
  const reversedEntities = [...entitiesWithTokens].reverse();

  for (const item of reversedEntities) {
    const { start, end } = item.location;
    maskedText = maskedText.slice(0, start) + item.token + maskedText.slice(end);
  }

  // Count preserved paragraphs
  const origParagraphs = rawText.split(/\n\s*\n/).length;
  const maskedParagraphs = maskedText.split(/\n\s*\n/).length;

  return {
    maskedText,
    vaultMapping,
    secretsRedacted,
    appliedTokens,
    invariantVerified: true,
    preservedParagraphCount: maskedParagraphs,
  };
}
