/**
 * src/lib/rehearsal/evaluator.ts
 * ──────────────────────────────
 * Benchmark Evaluator for Rehearsal Set.
 *
 * Runs the detection, policy, masking, and independent verification pipeline
 * against all 5 synthetic rehearsal documents and computes real Precision,
 * Recall, F1 score, and documents every single miss honestly.
 */

import { REHEARSAL_DOCUMENTS, RehearsalDocument } from './rehearsalDocuments';
import { detectEntitiesInText, DetectedEntityItem } from '../detection/detector';
import { evaluatePolicyOnEntities } from '../policy/policyEngine';
import { maskDocumentByOffsets, MaskingResult, OffsetInvariantError } from '../masking/offsetMasker';
import { performIndependentVerification, VerificationReport, testOriginalDocumentLeak } from '../verification/independentVerifier';
import { generateComplianceReport, ComplianceReport } from '../compliance/reportGenerator';

export { performIndependentVerification, testOriginalDocumentLeak };
export { maskDocumentByOffsets, OffsetInvariantError };

export interface DocumentEvaluationResult {
  docId: string;
  fileName: string;
  title: string;
  rawTextLength: number;
  detectedCount: number;
  expectedCount: number;
  truePositives: number;
  falsePositives: number;
  falseNegatives: number;
  precision: number;
  recall: number;
  f1Score: number;
  missedExpectedEntities: string[];
  unexpectedDetectedEntities: string[];
  maskingResult: MaskingResult;
  verificationReport: VerificationReport;
  complianceReport: ComplianceReport;
}

export interface RehearsalBenchmarkSummary {
  totalDocuments: number;
  totalExpectedEntities: number;
  totalDetectedEntities: number;
  totalTruePositives: number;
  totalFalsePositives: number;
  totalFalseNegatives: number;
  aggregatePrecision: number;
  aggregateRecall: number;
  aggregateF1Score: number;
  documentResults: DocumentEvaluationResult[];
  limitations: string[];
}

export function evaluateRehearsalDocument(doc: RehearsalDocument): DocumentEvaluationResult {
  // 1. Extraction / Detection
  const detectionResult = detectEntitiesInText(doc.rawText, 0.75);
  const detected = detectionResult.entities;

  // 2. Policy Evaluation
  const policyResult = evaluatePolicyOnEntities(detected, 'DPDP_STATUTORY_STRICT');

  // 3. Masking by Absolute Offsets
  const maskingResult = maskDocumentByOffsets(doc.rawText, policyResult.evaluatedEntities);

  // 4. Independent Verification
  const verificationReport = performIndependentVerification(
    maskingResult.maskedText,
    maskingResult.vaultMapping
  );

  // 5. Compliance Report
  const complianceReport = generateComplianceReport({
    documentId: doc.id,
    fileName: doc.fileName,
    profile: policyResult.profile,
    entities: policyResult.evaluatedEntities,
    verification: verificationReport,
  });

  // 6. Ground Truth Comparison
  const expected = doc.answerKey;
  let tp = 0;
  const matchedExpected = new Set<number>();
  const matchedDetected = new Set<number>();

  // For each detected entity, see if it matches an expected entity
  detected.forEach((det, dIdx) => {
    expected.forEach((exp, eIdx) => {
      if (!matchedExpected.has(eIdx) && !matchedDetected.has(dIdx)) {
        // Match condition: expected substring match
        const valMatch =
          det.value.trim().toLowerCase() === exp.expectedValue.trim().toLowerCase() ||
          det.value.includes(exp.expectedValue) ||
          exp.expectedValue.includes(det.value);

        if (valMatch) {
          tp++;
          matchedExpected.add(eIdx);
          matchedDetected.add(dIdx);
        }
      }
    });
  });

  const fp = detected.length - tp;
  const fn = expected.length - tp;

  const precision = detected.length > 0 ? tp / detected.length : expected.length === 0 ? 1.0 : 0.0;
  const recall = expected.length > 0 ? tp / expected.length : detected.length === 0 ? 1.0 : 0.0;
  const f1Score = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0.0;

  const missedExpectedEntities = expected
    .filter((_, idx) => !matchedExpected.has(idx))
    .map((e) => `[${e.type}] ${e.expectedValue}`);

  const unexpectedDetectedEntities = detected
    .filter((_, idx) => !matchedDetected.has(idx))
    .map((d) => `[${d.type}] ${d.value} (conf: ${(d.confidence * 100).toFixed(0)}%)`);

  return {
    docId: doc.id,
    fileName: doc.fileName,
    title: doc.title,
    rawTextLength: doc.rawText.length,
    detectedCount: detected.length,
    expectedCount: expected.length,
    truePositives: tp,
    falsePositives: fp,
    falseNegatives: fn,
    precision,
    recall,
    f1Score,
    missedExpectedEntities,
    unexpectedDetectedEntities,
    maskingResult,
    verificationReport,
    complianceReport,
  };
}

export function runFullRehearsalBenchmark(): RehearsalBenchmarkSummary {
  const documentResults = REHEARSAL_DOCUMENTS.map(evaluateRehearsalDocument);

  let totalExp = 0;
  let totalDet = 0;
  let totalTp = 0;
  let totalFp = 0;
  let totalFn = 0;

  documentResults.forEach((r) => {
    totalExp += r.expectedCount;
    totalDet += r.detectedCount;
    totalTp += r.truePositives;
    totalFp += r.falsePositives;
    totalFn += r.falseNegatives;
  });

  const aggregatePrecision = totalDet > 0 ? totalTp / totalDet : 1.0;
  const aggregateRecall = totalExp > 0 ? totalTp / totalExp : 1.0;
  const aggregateF1Score =
    aggregatePrecision + aggregateRecall > 0
      ? (2 * aggregatePrecision * aggregateRecall) / (aggregatePrecision + aggregateRecall)
      : 0.0;

  const limitations = [
    'Standalone names without titular prefixes (Mr., Dr., Shri) or contextual cues rely on capitalization heuristics and may require human confirmation in the "Needs review" panel.',
    'Non-standard proprietary database connection strings that do not follow standard URI formatting (postgres://, mysql://) may require custom regex patterns.',
    'Scanned documents with severe OCR artifacts or skewed perspective requires higher image resolution (>300 DPI) for Verhoeff Aadhaar checksum verification.',
    'Strict PAN 4th character validation intentionally rejects random alphanumeric strings matching the 10-digit format if the 4th letter is not in the statutory ABCFGHLJPT category set.',
  ];

  return {
    totalDocuments: documentResults.length,
    totalExpectedEntities: totalExp,
    totalDetectedEntities: totalDet,
    totalTruePositives: totalTp,
    totalFalsePositives: totalFp,
    totalFalseNegatives: totalFn,
    aggregatePrecision,
    aggregateRecall,
    aggregateF1Score,
    documentResults,
    limitations,
  };
}
