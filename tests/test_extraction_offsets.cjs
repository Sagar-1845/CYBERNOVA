/**
 * tests/test_extraction_offsets.cjs
 * ──────────────────────────────────
 * Unit and Regression Test Suite for Document Extraction Offsets & Line Numbering.
 *
 * Verifies:
 * 1. For every extractor (TXT, CSV, JSON, XML, DOCX, PDF, OCR, XLSX), every node
 *    satisfies the fundamental invariant: rawText.slice(node.start, node.end) === node.text
 * 2. True 1-based line numbering (including blank lines) and node.line field.
 * 3. Handling of CRLF (\r\n), CR (\r), and UTF-8 BOM (\uFEFF) normalization.
 * 4. Multi-byte Devanagari text offset preservation.
 * 5. Non-BMP emoji surrogate pair character offset preservation.
 * 6. Fixture test against tests/fixtures/zeroleak_unstructured_test_doc.txt:
 *    - Asserts before/after mismatch count (before: 33/34, after: 0/34).
 *    - Asserts 43/43 ground-truth entities in answer key match rawText.slice(start, end).
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const xlsx = require('xlsx');

// ── Canonical Text Normalizer ──────────────────────────────────────────────
function normalizeRawText(content) {
  if (!content) return '';
  let text = content.charCodeAt(0) === 0xfeff ? content.slice(1) : content;
  return text.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
}

// ── TXT Extractor ──────────────────────────────────────────────────────────
function extractTextFromPlainText(content) {
  const rawText = normalizeRawText(content);
  const lines = rawText.split('\n');

  const nodes = [];
  let currentOffset = 0;

  lines.forEach((line, idx) => {
    const lineNum = idx + 1;
    const lineStart = currentOffset;
    currentOffset += line.length + 1; // +1 for '\n'

    const trimmed = line.trim();
    if (!trimmed) return; // Blank lines do not generate nodes, but line number advances

    const leading = line.length - line.trimStart().length;
    const start = lineStart + leading;
    const end = start + trimmed.length;

    nodes.push({
      ref: `txt:line_${lineNum}`,
      line: lineNum,
      text: trimmed,
      start,
      end,
      source: 'digital_text',
    });
  });

  return { nodes, rawText };
}

// ── Spreadsheet / CSV / XLSX Extractor ─────────────────────────────────────
function extractTextFromSpreadsheetData(sheetData, sheetName = 'Sheet1') {
  const nodes = [];
  let rawText = '';
  let currentLine = 1;

  for (let r = 0; r < sheetData.length; r++) {
    const row = sheetData[r];
    if (!row) continue;
    let rowHasCell = false;

    for (let c = 0; c < row.length; c++) {
      const val = row[c];
      if (val !== undefined && val !== null && String(val).trim() !== '') {
        const str = String(val).trim();
        const colLetter = xlsx.utils.encode_col(c);
        const cellRef = `${colLetter}${r + 1}`;

        if (rawText.length > 0) {
          if (rowHasCell) {
            rawText += '\t';
          } else {
            rawText += '\n';
            currentLine++;
          }
        }
        rowHasCell = true;

        const start = rawText.length;
        rawText += str;
        const end = rawText.length;

        nodes.push({
          ref: `sheet:${sheetName}!${cellRef}`,
          line: currentLine,
          text: str,
          start,
          end,
          source: 'table_cell',
        });
      }
    }
  }

  return { nodes, rawText };
}

// ── JSON Extractor ─────────────────────────────────────────────────────────
function extractTextFromJsonContent(jsonContent) {
  const rawText = normalizeRawText(jsonContent);
  const parsed = JSON.parse(rawText);

  const nodes = [];
  let searchOffset = 0;

  function traverse(obj, jsonPath) {
    if (obj === null || obj === undefined) return;

    if (typeof obj === 'string' || typeof obj === 'number' || typeof obj === 'boolean') {
      const strVal = String(obj);
      if (typeof obj === 'string') {
        const needle = JSON.stringify(obj);
        const found = rawText.indexOf(needle, searchOffset);
        if (found !== -1) {
          const start = found + 1; // inside quotes
          const end = found + needle.length - 1;
          searchOffset = found + needle.length;
          const line = rawText.slice(0, start).split('\n').length;
          nodes.push({
            ref: `json:${jsonPath}`,
            line,
            text: rawText.slice(start, end),
            start,
            end,
            source: 'json_value',
          });
          return;
        }
      } else {
        const found = rawText.indexOf(strVal, searchOffset);
        if (found !== -1) {
          const start = found;
          const end = start + strVal.length;
          searchOffset = end;
          const line = rawText.slice(0, start).split('\n').length;
          nodes.push({
            ref: `json:${jsonPath}`,
            line,
            text: strVal,
            start,
            end,
            source: 'json_value',
          });
          return;
        }
      }
    }

    if (Array.isArray(obj)) {
      obj.forEach((item, idx) => traverse(item, `${jsonPath}[${idx}]`));
      return;
    }

    if (typeof obj === 'object') {
      for (const [key, val] of Object.entries(obj)) {
        traverse(val, jsonPath === '$' ? `$.${key}` : `${jsonPath}.${key}`);
      }
    }
  }

  traverse(parsed, '$');
  return { nodes, rawText };
}

// ── XML Extractor ──────────────────────────────────────────────────────────
function extractTextFromXmlContent(xmlContent) {
  const rawText = normalizeRawText(xmlContent);
  const { DOMParser } = require('@xmldom/xmldom');
  const xmlDoc = new DOMParser().parseFromString(rawText, 'application/xml');

  const nodes = [];
  let searchOffset = 0;

  function walk(node, elemPath) {
    if (node.nodeType === 3) { // TEXT_NODE
      const val = node.nodeValue?.trim();
      if (val) {
        const found = rawText.indexOf(val, searchOffset);
        if (found !== -1) {
          const start = found;
          const end = start + val.length;
          searchOffset = end;
          const line = rawText.slice(0, start).split('\n').length;
          nodes.push({
            ref: `xml:${elemPath}`,
            line,
            text: val,
            start,
            end,
            source: 'xml_node',
          });
        }
      }
    } else if (node.nodeType === 1) { // ELEMENT_NODE
      const currentPath = `${elemPath}/${node.tagName}`;

      if (node.attributes) {
        for (let i = 0; i < node.attributes.length; i++) {
          const attr = node.attributes[i];
          const val = attr.value?.trim();
          if (val) {
            const attrPattern = `${attr.name}="${val}"`;
            let found = rawText.indexOf(attrPattern, searchOffset);
            let valStart = -1;
            if (found !== -1) {
              valStart = found + attr.name.length + 2;
            } else {
              const singlePattern = `${attr.name}='${val}'`;
              found = rawText.indexOf(singlePattern, searchOffset);
              if (found !== -1) {
                valStart = found + attr.name.length + 2;
              } else {
                found = rawText.indexOf(val, searchOffset);
                if (found !== -1) valStart = found;
              }
            }
            if (valStart !== -1) {
              const start = valStart;
              const end = start + val.length;
              searchOffset = end;
              const line = rawText.slice(0, start).split('\n').length;
              nodes.push({
                ref: `xml:${currentPath}[@${attr.name}]`,
                line,
                text: val,
                start,
                end,
                source: 'xml_node',
              });
            }
          }
        }
      }

      if (node.childNodes) {
        for (let i = 0; i < node.childNodes.length; i++) {
          walk(node.childNodes[i], currentPath);
        }
      }
    }
  }

  walk(xmlDoc.documentElement, '');
  return { nodes, rawText };
}

// ── DOCX Extractor ─────────────────────────────────────────────────────────
function extractTextFromDocxRaw(docxRawValue) {
  const rawText = normalizeRawText(docxRawValue);
  const lines = rawText.split('\n');
  const nodes = [];
  let currentOffset = 0;
  let paraIdx = 0;

  lines.forEach((line, idx) => {
    const lineNum = idx + 1;
    const lineStart = currentOffset;
    currentOffset += line.length + 1;

    const trimmed = line.trim();
    if (!trimmed) return;

    const leading = line.length - line.trimStart().length;
    const start = lineStart + leading;
    const end = start + trimmed.length;
    paraIdx++;

    nodes.push({
      ref: `docx:paragraph_${paraIdx}`,
      line: lineNum,
      text: trimmed,
      start,
      end,
      source: 'digital_text',
    });
  });

  return { nodes, rawText };
}

// ── PDF Layout Extractor ───────────────────────────────────────────────────
function extractTextFromPdfPageItems(pageItems) {
  const nodes = [];
  let rawText = '';
  let currentLine = 1;

  pageItems.forEach(({ pageNum, items }) => {
    let pageHasText = false;
    items.forEach((str) => {
      const trimmed = str.trim();
      if (!trimmed) return;

      if (rawText.length > 0) {
        if (pageHasText) {
          rawText += ' ';
        } else {
          rawText += '\n\n';
          currentLine += 2;
        }
      }
      pageHasText = true;

      const start = rawText.length;
      rawText += trimmed;
      const end = rawText.length;

      nodes.push({
        ref: `pdf:page_${pageNum}:item_${nodes.length + 1}`,
        page: pageNum,
        line: currentLine,
        text: trimmed,
        start,
        end,
        source: 'digital_text',
      });
    });
  });

  return { nodes, rawText };
}

// ── OCR Extractor ──────────────────────────────────────────────────────────
function extractTextFromOcrBlocks(paragraphsList) {
  const nodes = [];
  let rawText = '';
  let currentLine = 1;

  paragraphsList.forEach((text, idx) => {
    const trimmed = text.trim();
    if (!trimmed) return;

    if (rawText.length > 0) {
      rawText += '\n\n';
      currentLine += 2;
    }
    const start = rawText.length;
    rawText += trimmed;
    const end = rawText.length;

    nodes.push({
      ref: `image:ocr_block_${idx + 1}`,
      line: currentLine,
      text: trimmed,
      start,
      end,
      source: 'ocr',
    });
  });

  return { nodes, rawText };
}

// ── Test Runner ────────────────────────────────────────────────────────────
async function runAllTests() {
  console.log('─────────────────────────────────────────────────────────────────');
  console.log('  ZEROLEAK AI // EXTRACTION OFFSETS & SLICE INVARIANT TEST SUITE');
  console.log('─────────────────────────────────────────────────────────────────\n');

  let passed = 0;
  let failed = 0;

  function assertSliceInvariant(nodes, rawText, context = '') {
    nodes.forEach((n, idx) => {
      const sliced = rawText.slice(n.start, n.end);
      assert.strictEqual(
        sliced,
        n.text,
        `Slice invariant failed in ${context} at node [${idx}] (${n.ref}): expected ${JSON.stringify(n.text)}, got ${JSON.stringify(sliced)} at [${n.start}:${n.end}]`
      );
    });
  }

  function test(desc, fn) {
    try {
      fn();
      console.log(`  ✓ [PASS] ${desc}`);
      passed++;
    } catch (err) {
      console.error(`  ✗ [FAIL] ${desc}: ${err.message}`);
      failed++;
    }
  }

  // ── TEST 1: TXT Extractor with Blank Lines & True Line Numbers ───────────
  test('TXT: Blank lines preserved in line count, offsets match slice', () => {
    const content = 'First Line\n\n\nFourth Line with info\n  Fifth Line indented\n\nSeventh Line final';
    const { nodes, rawText } = extractTextFromPlainText(content);

    assert.strictEqual(nodes.length, 4);
    assertSliceInvariant(nodes, rawText, 'TXT Blank Lines');

    // Verify true 1-based line numbers
    assert.strictEqual(nodes[0].ref, 'txt:line_1');
    assert.strictEqual(nodes[0].line, 1);
    assert.strictEqual(nodes[0].text, 'First Line');

    assert.strictEqual(nodes[1].ref, 'txt:line_4');
    assert.strictEqual(nodes[1].line, 4);
    assert.strictEqual(nodes[1].text, 'Fourth Line with info');

    assert.strictEqual(nodes[2].ref, 'txt:line_5');
    assert.strictEqual(nodes[2].line, 5);
    assert.strictEqual(nodes[2].text, 'Fifth Line indented');

    assert.strictEqual(nodes[3].ref, 'txt:line_7');
    assert.strictEqual(nodes[3].line, 7);
    assert.strictEqual(nodes[3].text, 'Seventh Line final');
  });

  // ── TEST 2: TXT Extractor with CRLF (\r\n) and UTF-8 BOM ─────────────────
  test('TXT: CRLF (\\r\\n) and UTF-8 BOM are normalized, offsets match slice', () => {
    const crlfContent = '\uFEFFHeader Row\r\n\r\nBorrower: Rohan Sharma\r\nIncome: INR 18,50,000\r\n';
    const { nodes, rawText } = extractTextFromPlainText(crlfContent);

    assert.strictEqual(rawText.charCodeAt(0) !== 0xfeff, true, 'BOM must be stripped');
    assert.strictEqual(rawText.includes('\r'), false, 'CR must be stripped');
    assertSliceInvariant(nodes, rawText, 'TXT CRLF + BOM');

    assert.strictEqual(nodes[0].text, 'Header Row');
    assert.strictEqual(nodes[0].line, 1);

    assert.strictEqual(nodes[1].text, 'Borrower: Rohan Sharma');
    assert.strictEqual(nodes[1].line, 3);

    assert.strictEqual(nodes[2].text, 'Income: INR 18,50,000');
    assert.strictEqual(nodes[2].line, 4);
  });

  // ── TEST 3: TXT Extractor with Devanagari Multi-byte Unicode ─────────────
  test('TXT: Devanagari multi-byte characters preserve exact slice positions', () => {
    const devanagariContent = 'उधारकर्ता: सरिता वर्मा\nआधार संख्या: 3456 7890 1238\nवार्षिक आय: ₹ 12,00,000\nग्राहकों की सूची संलग्न है।';
    const { nodes, rawText } = extractTextFromPlainText(devanagariContent);

    assert.strictEqual(nodes.length, 4);
    assertSliceInvariant(nodes, rawText, 'TXT Devanagari');

    assert.strictEqual(nodes[0].text, 'उधारकर्ता: सरिता वर्मा');
    assert.strictEqual(nodes[1].text, 'आधार संख्या: 3456 7890 1238');
    assert.strictEqual(nodes[2].text, 'वार्षिक आय: ₹ 12,00,000');
    assert.strictEqual(nodes[3].text, 'ग्राहकों की सूची संलग्न है।');
  });

  // ── TEST 4: TXT Extractor with Emoji (Non-BMP Surrogate Pairs) ───────────
  test('TXT: Non-BMP characters (Emoji surrogate pairs) preserve exact slice positions', () => {
    const emojiContent = '🛡️ ZEROLEAK AI ENCLAVE 🚀\nPatient: John Doe 👤\nKey: 🔑-99482';
    const { nodes, rawText } = extractTextFromPlainText(emojiContent);

    assert.strictEqual(nodes.length, 3);
    assertSliceInvariant(nodes, rawText, 'TXT Non-BMP Emoji');

    assert.strictEqual(nodes[0].text, '🛡️ ZEROLEAK AI ENCLAVE 🚀');
    assert.strictEqual(nodes[1].text, 'Patient: John Doe 👤');
    assert.strictEqual(nodes[2].text, 'Key: 🔑-99482');
  });

  // ── TEST 5: CSV / Spreadsheet Extractor ──────────────────────────────────
  test('CSV/XLSX: Cell references, row line numbers, and slice invariant', () => {
    const sheetData = [
      ['Vendor', 'GSTIN', 'Amount'],
      ['Apex LLP', '29ABCDE1234F1Z5', '145000'],
      [],
      ['Zenith Corp', '36FGHIJ5678K2Z8', '290000']
    ];
    const { nodes, rawText } = extractTextFromSpreadsheetData(sheetData, 'Invoices');

    assert.strictEqual(nodes.length, 9);
    assertSliceInvariant(nodes, rawText, 'Spreadsheet Cells');

    assert.strictEqual(nodes[0].ref, 'sheet:Invoices!A1');
    assert.strictEqual(nodes[0].text, 'Vendor');
    assert.strictEqual(nodes[0].line, 1);

    assert.strictEqual(nodes[4].ref, 'sheet:Invoices!B2');
    assert.strictEqual(nodes[4].text, '29ABCDE1234F1Z5');
    assert.strictEqual(nodes[4].line, 2);

    assert.strictEqual(nodes[6].ref, 'sheet:Invoices!A4');
    assert.strictEqual(nodes[6].text, 'Zenith Corp');
    assert.strictEqual(nodes[6].line, 3);
  });

  // ── TEST 6: JSON Extractor ───────────────────────────────────────────────
  test('JSON: Keypath references, line numbering, and slice invariant', () => {
    const jsonStr = JSON.stringify({
      hospital: 'Metro Hospital',
      patient: {
        name: 'सरिता वर्मा',
        income: 1850000,
        active: true,
        emoji_tag: '🛡️ Enclave'
      },
      tags: ['kyc', 'verified']
    }, null, 2);

    const { nodes, rawText } = extractTextFromJsonContent(jsonStr);

    assert.strictEqual(nodes.length, 7);
    assertSliceInvariant(nodes, rawText, 'JSON Nodes');

    assert.strictEqual(nodes[0].ref, 'json:$.hospital');
    assert.strictEqual(nodes[0].text, 'Metro Hospital');

    assert.strictEqual(nodes[1].ref, 'json:$.patient.name');
    assert.strictEqual(nodes[1].text, 'सरिता वर्मा');

    assert.strictEqual(nodes[2].ref, 'json:$.patient.income');
    assert.strictEqual(nodes[2].text, '1850000');

    assert.strictEqual(nodes[4].ref, 'json:$.patient.emoji_tag');
    assert.strictEqual(nodes[4].text, '🛡️ Enclave');
  });

  // ── TEST 7: XML Extractor ────────────────────────────────────────────────
  test('XML: Tag paths, attribute references, and slice invariant', () => {
    const xmlContent = `<?xml version="1.0" encoding="UTF-8"?>
<application id="APP-9988">
  <borrower name="सरिता वर्मा" role="primary">
    <aadhaar>3456 7890 1238</aadhaar>
    <note>Verified 🛡️</note>
  </borrower>
</application>`;

    const { nodes, rawText } = extractTextFromXmlContent(xmlContent);

    assertSliceInvariant(nodes, rawText, 'XML Elements & Attributes');

    const attrNode = nodes.find((n) => n.ref === 'xml:/application/borrower[@name]');
    assert.strictEqual(attrNode.text, 'सरिता वर्मा');

    const textNode = nodes.find((n) => n.ref === 'xml:/application/borrower/aadhaar');
    assert.strictEqual(textNode.text, '3456 7890 1238');

    const emojiNode = nodes.find((n) => n.ref === 'xml:/application/borrower/note');
    assert.strictEqual(emojiNode.text, 'Verified 🛡️');
  });

  // ── TEST 8: DOCX Extractor ───────────────────────────────────────────────
  test('DOCX: Paragraph nodes and slice invariant', () => {
    const docxValue = 'Evaluation Report\n\nConfidential KYC details attached.\n\nBorrower: Meenakshi Iyer\nLoan Amount: 35,00,000';
    const { nodes, rawText } = extractTextFromDocxRaw(docxValue);

    assert.strictEqual(nodes.length, 4);
    assertSliceInvariant(nodes, rawText, 'DOCX Paragraphs');

    assert.strictEqual(nodes[0].ref, 'docx:paragraph_1');
    assert.strictEqual(nodes[0].line, 1);
    assert.strictEqual(nodes[0].text, 'Evaluation Report');

    assert.strictEqual(nodes[2].ref, 'docx:paragraph_3');
    assert.strictEqual(nodes[2].line, 5);
    assert.strictEqual(nodes[2].text, 'Borrower: Meenakshi Iyer');
  });

  // ── TEST 9: PDF Layout Extractor ─────────────────────────────────────────
  test('PDF: Multi-page item layout and slice invariant', () => {
    const pageItems = [
      { pageNum: 1, items: ['ZEROLEAK AI', 'Loan Application', 'Applicant: Sunil Kumar'] },
      { pageNum: 2, items: ['Income Verification', 'Gross: INR 12,00,000'] }
    ];
    const { nodes, rawText } = extractTextFromPdfPageItems(pageItems);

    assert.strictEqual(nodes.length, 5);
    assertSliceInvariant(nodes, rawText, 'PDF Layout');

    assert.strictEqual(nodes[0].ref, 'pdf:page_1:item_1');
    assert.strictEqual(nodes[0].page, 1);
    assert.strictEqual(nodes[0].text, 'ZEROLEAK AI');

    assert.strictEqual(nodes[3].ref, 'pdf:page_2:item_4');
    assert.strictEqual(nodes[3].page, 2);
    assert.strictEqual(nodes[3].text, 'Income Verification');
  });

  // ── TEST 10: OCR Block Extractor ─────────────────────────────────────────
  test('OCR: Multi-block paragraph text and slice invariant', () => {
    const ocrBlocks = [
      'Government of India / Unique Identification Authority of India',
      'सरिता वर्मा / Sarita Verma',
      '3456 7890 1238'
    ];
    const { nodes, rawText } = extractTextFromOcrBlocks(ocrBlocks);

    assert.strictEqual(nodes.length, 3);
    assertSliceInvariant(nodes, rawText, 'OCR Blocks');

    assert.strictEqual(nodes[0].ref, 'image:ocr_block_1');
    assert.strictEqual(nodes[0].text, 'Government of India / Unique Identification Authority of India');

    assert.strictEqual(nodes[1].ref, 'image:ocr_block_2');
    assert.strictEqual(nodes[1].text, 'सरिता वर्मा / Sarita Verma');

    assert.strictEqual(nodes[2].ref, 'image:ocr_block_3');
    assert.strictEqual(nodes[2].text, '3456 7890 1238');
  });

  // ── TEST 11: Benchmark Fixture Regression & Before/After Mismatches ──────
  test('Regression Benchmark: zeroleak_unstructured_test_doc.txt (was 33/34, must be 0/34)', () => {
    const fixturePath = path.join(__dirname, 'fixtures', 'zeroleak_unstructured_test_doc.txt');
    const answerKeyPath = path.join(__dirname, 'fixtures', 'zeroleak_unstructured_test_answer_key.json');

    const fileContent = fs.readFileSync(fixturePath, 'utf8');
    const answerKey = JSON.parse(fs.readFileSync(answerKeyPath, 'utf8'));

    // A. REPRODUCE OLD BROKEN BEHAVIOR (Before Fix)
    const oldLines = fileContent.split(/\r?\n/).filter((l) => l.trim().length > 0);
    const oldNodes = [];
    let oldOffset = 0;
    oldLines.forEach((line, idx) => {
      const text = line.trim();
      const start = oldOffset;
      const end = start + text.length;
      oldOffset = end + 1;
      oldNodes.push({ ref: `txt:line_${idx + 1}`, text, start, end });
    });

    let oldMismatched = 0;
    oldNodes.forEach((n) => {
      if (fileContent.slice(n.start, n.end) !== n.text) {
        oldMismatched++;
      }
    });

    console.log(`\n      [BEFORE FIX] Mismatched nodes on test document: ${oldMismatched}/${oldNodes.length} (error on node 2: slice=${JSON.stringify(fileContent.slice(oldNodes[1].start, oldNodes[1].end))}, text=${JSON.stringify(oldNodes[1].text)})`);
    assert.strictEqual(oldMismatched, 33, 'Before fix, exactly 33 of 34 nodes must mismatch');

    // B. VERIFY NEW FIXED BEHAVIOR (After Fix)
    const { nodes: newNodes, rawText } = extractTextFromPlainText(fileContent);

    let newMismatched = 0;
    newNodes.forEach((n) => {
      const sliced = rawText.slice(n.start, n.end);
      if (sliced !== n.text) {
        newMismatched++;
      }
    });

    console.log(`      [AFTER FIX]  Mismatched nodes on test document: ${newMismatched}/${newNodes.length} (node 2: slice=${JSON.stringify(rawText.slice(newNodes[1].start, newNodes[1].end))}, ref=${newNodes[1].ref}, line=${newNodes[1].line})`);
    assert.strictEqual(newMismatched, 0, 'After fix, exactly 0 of 34 nodes must mismatch');
    assert.strictEqual(newNodes.length, 34);
    assert.strictEqual(newNodes[1].ref, 'txt:line_3', 'txt:line_2 in old is now correctly txt:line_3');
    assert.strictEqual(newNodes[1].line, 3);
    assert.strictEqual(newNodes[1].text, 'hi team,');
    assert.strictEqual(rawText.slice(newNodes[1].start, newNodes[1].end), 'hi team,');

    // C. VERIFY GROUND-TRUTH ANSWER KEY SPANS (43/43 expected)
    const allExpected = [...answerKey.tier_1_entities, ...answerKey.tier_2_entities];
    assert.strictEqual(allExpected.length, 43, 'Answer key must have 43 expected entities (22 T1 + 21 T2)');

    let keySpansMatched = 0;
    allExpected.forEach((ent) => {
      const sliced = rawText.slice(ent.start, ent.end);
      if (sliced === ent.value) {
        keySpansMatched++;
      } else {
        console.error(`      Mismatch in answer key: expected ${JSON.stringify(ent.value)}, got ${JSON.stringify(sliced)} at [${ent.start}:${ent.end}]`);
      }
    });

    console.log(`      [ANSWER KEY] Exact span verification: ${keySpansMatched}/${allExpected.length} entities matched directly in rawText`);
    assert.strictEqual(keySpansMatched, 43, 'All 43 expected entities must match rawText.slice(start, end) perfectly');
  });

  console.log('\n─────────────────────────────────────────────────────────────────');
  console.log(`  RESULTS: ${passed} PASSED | ${failed} FAILED across ${passed + failed} test cases.`);
  console.log('─────────────────────────────────────────────────────────────────\n');

  if (failed > 0) process.exit(1);
}

runAllTests().catch((err) => {
  console.error(err);
  process.exit(1);
});
