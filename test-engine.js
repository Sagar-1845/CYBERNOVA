/**
 * ZeroLeak Engine Verification Test Suite
 * Verifies 61 of 61 sensitive values masked, 19 of 19 look-alikes preserved, leak check passed
 */
import fs from 'fs';
import path from 'path';
import './zeroleak-engine.js';

const ZeroLeak = globalThis.ZeroLeak;

const filePath = process.argv[2] || 'test_hard.txt';
if (!fs.existsSync(filePath)) {
  console.error(`File not found: ${filePath}`);
  process.exit(1);
}

const rawText = fs.readFileSync(filePath, 'utf8');
console.log(`[Test] Processing "${filePath}" (${rawText.length} bytes)...`);

const result = ZeroLeak.process(rawText);

// 1. Verify 61 sensitive values detected and masked
const totalSensitive = result.stats.total;
const totalMasked = result.stats.masked;
console.log(`[Test] Total Entities Detected: ${totalSensitive}`);
console.log(`[Test] Total Entities Masked: ${totalMasked}`);

if (totalSensitive !== 61 || totalMasked !== 61) {
  console.error(`FAILED: Expected 61 sensitive values, got ${totalSensitive} detected, ${totalMasked} masked.`);
  process.exit(1);
}

// 2. Verify 19 look-alikes preserved
const lookalikes = ZeroLeak.PRESERVE_LOOKALIKES;
let preservedCount = 0;
for (const item of lookalikes) {
  if (result.masked.includes(item)) {
    preservedCount++;
  } else {
    console.warn(`[Warning] Missing lookalike: "${item}"`);
  }
}
console.log(`[Test] Look-alike values preserved: ${preservedCount} of ${lookalikes.length}`);
if (preservedCount !== 19) {
  console.error(`FAILED: Expected 19 of 19 look-alikes preserved, got ${preservedCount}.`);
  process.exit(1);
}

// 3. Verify leak check passed
console.log(`[Test] Leak Check Result: ${result.leak.passed ? 'PASSED' : 'FAILED'} (Leaks: ${result.leak.leakCount}, Risk: ${result.leak.riskPct})`);
if (!result.leak.passed || result.leak.leakCount !== 0) {
  console.error(`FAILED: Outbound leak check failed with ${result.leak.leakCount} leaks.`);
  process.exit(1);
}

// 4. Verify critical forbidden values do not appear in outbound
const criticalTokens = [
  "5857-0839-3474", "8763 3606", "7701", "233199498622",
  "dqwpn6120h", "4111 1111 1111 1111", "AKIAIO"
];
for (const token of criticalTokens) {
  if (result.masked.includes(token)) {
    console.error(`FAILED: Outbound payload leaked forbidden token "${token}"`);
    process.exit(1);
  }
}

// 5. Verify local restoration works
const restored = ZeroLeak.restore(result.masked, result.map);
if (restored.length < rawText.length * 0.9) {
  console.error('FAILED: Restored text length significantly differs from original text.');
  process.exit(1);
}

console.log('\nRESULT: ALL TESTS PASSED (61 of 61 sensitive values masked, 19 of 19 look-alike values preserved, leak check passed)');
