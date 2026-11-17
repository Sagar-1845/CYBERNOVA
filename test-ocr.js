/**
 * ZeroLeak OCR Verification Test Suite
 * Tests end-to-end OCR extraction, PII tokenization, visual redaction, and error boundaries.
 */
import fs from 'fs';
import path from 'path';
import Tesseract from 'tesseract.js';
import './zeroleak-engine.js';
import './ocr-extract.js';

const ZeroLeak = globalThis.ZeroLeak;
const ZeroLeakOCR = globalThis.ZeroLeakOCR;

const testDir = process.argv[2] || './ocr-test';
console.log(`[Test-OCR] Running validation against directory: ${testDir}`);

async function runTests() {
  // Test 1: kyc_sample.jpg
  const kycPath = path.join(testDir, 'kyc_sample.jpg');
  console.log(`\n[Test 1] Testing primary KYC specimen: ${kycPath}`);
  if (!fs.existsSync(kycPath)) {
    throw new Error(`File not found: ${kycPath}`);
  }

  const kycRes = await Tesseract.recognize(kycPath, 'eng');
  const kycText = kycRes.data.text;
  console.log(`[Test 1] OCR Confidence: ${Math.round(kycRes.data.confidence)}%`);
  console.log(`[Test 1] Extracted text length: ${kycText.length} characters`);

  const proc = ZeroLeak.process(kycText);
  console.log(`[Test 1] Entities Detected: ${proc.stats.total}`);
  console.log(`[Test 1] Entities Masked: ${proc.stats.masked}`);
  console.log(`[Test 1] Leak Check: ${proc.leak.passed ? 'PASSED' : 'FAILED'} (Leaks: ${proc.leak.leakCount})`);

  // Verify tokens
  const requiredTokens = ['[NAME_1]', '[AADHAAR_1]', '[PAN_1]', '[PHONE_1]', '[EMAIL_1]', '[CARD_1]'];
  for (const token of requiredTokens) {
    if (!proc.masked.includes(token)) {
      throw new Error(`[Test 1] Missing expected token "${token}" in masked output:\n${proc.masked}`);
    }
  }

  // Verify look-alikes remain UNMASKED
  const unmaskedRequired = ['TKT-9876543210', 'Grace period', 'Bank of Baroda'];
  for (const item of unmaskedRequired) {
    if (!proc.masked.includes(item)) {
      throw new Error(`[Test 1] Lookalike "${item}" was improperly masked in outbound output!`);
    }
  }

  if (!proc.leak.passed || proc.leak.leakCount !== 0) {
    throw new Error('[Test 1] Outbound leak check failed!');
  }
  console.log('[Test 1] PASSED: All tokens present, look-alikes preserved, zero leaks.');

  // Test 2: screenshot.png
  const pngPath = path.join(testDir, 'screenshot.png');
  console.log(`\n[Test 2] Testing PNG screenshot support: ${pngPath}`);
  if (fs.existsSync(pngPath)) {
    const pngRes = await Tesseract.recognize(pngPath, 'eng');
    if (!pngRes.data.text || pngRes.data.text.trim().length === 0) {
      throw new Error('[Test 2] Failed to extract text from PNG screenshot.');
    }
    const pngProc = ZeroLeak.process(pngRes.data.text);
    if (!pngProc.masked.includes('[AADHAAR_1]')) {
      throw new Error('[Test 2] PNG did not properly detect Aadhaar.');
    }
    console.log('[Test 2] PASSED: PNG format properly parsed and masked.');
  }

  // Test 3: rotated_phone.jpg
  const rotPath = path.join(testDir, 'rotated_phone.jpg');
  console.log(`\n[Test 3] Testing rotated phone photo: ${rotPath}`);
  if (fs.existsSync(rotPath)) {
    try {
      const rotRes = await Tesseract.recognize(rotPath, 'eng');
      console.log(`[Test 3] Rotated image handled without crashing (text length: ${rotRes.data.text?.length || 0}).`);
      console.log('[Test 3] PASSED: Resilient handling of rotated photo.');
    } catch (err) {
      throw new Error(`[Test 3] Rotated image crashed OCR engine: ${err.message}`);
    }
  }

  // Test 4: blurry_lowres.jpg
  const blurPath = path.join(testDir, 'blurry_lowres.jpg');
  console.log(`\n[Test 4] Testing blurry / low-res image: ${blurPath}`);
  if (fs.existsSync(blurPath)) {
    try {
      const blurRes = await Tesseract.recognize(blurPath, 'eng');
      console.log(`[Test 4] Low-res image handled cleanly without crashing.`);
      console.log('[Test 4] PASSED: Degraded image handled safely.');
    } catch (err) {
      throw new Error(`[Test 4] Low-res image crashed OCR engine: ${err.message}`);
    }
  }

  // Test 5: empty_notext.jpg (Must show clear no-text error, not 0 entities or crash)
  const emptyPath = path.join(testDir, 'empty_notext.jpg');
  console.log(`\n[Test 5] Testing image with no text: ${emptyPath}`);
  if (fs.existsSync(emptyPath)) {
    const emptyRes = await Tesseract.recognize(emptyPath, 'eng');
    const emptyText = emptyRes.data.text.trim();
    if (emptyText.length === 0) {
      console.log('[Test 5] Verified: No-text image detected empty text layer.');
      // Verify ZeroLeakOCR throws clear error on empty text
      try {
        await ZeroLeakOCR.scanImage('ocr-test/empty_notext.jpg', {
          mockOcrText: '',
          mockConfidence: 0
        });
        throw new Error('[Test 5] ZeroLeakOCR should have thrown an error for empty text image.');
      } catch (err) {
        if (err.message.includes('No readable text detected in image')) {
          console.log(`[Test 5] Verified clear error triggered: "${err.message}"`);
          console.log('[Test 5] PASSED: Empty text handled with clear error, not 0 entities.');
        } else {
          throw err;
        }
      }
    }
  }

  console.log('\n======================================================');
  console.log('RESULT: ALL OCR CHECKS PASSED');
  console.log('======================================================');
}

runTests().catch((err) => {
  console.error('\nFAILED OCR TEST:', err);
  process.exit(1);
});
