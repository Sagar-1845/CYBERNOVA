/**
 * src/lib/document/extractors.ts
 * ──────────────────────────────
 * Unified multi-format document extraction engine for ZeroLeak AI.
 * Extracts paragraphs, headings, tables, metadata, spreadsheet cells,
 * JSON/XML structures, and image text via OCR into a unified DocumentNode structure.
 *
 * ── Offsets & Character Encoding Specification ──────────────────────────────
 * 1. Offsets (start, end) are 0-based absolute slice boundaries into rawText.
 * 2. Invariant: For EVERY extracted node across ALL formats (TXT, CSV, JSON, XML,
 *    DOCX, PDF, OCR, XLSX), rawText.slice(node.start, node.end) === node.text.
 * 3. Units: JavaScript UTF-16 code units (as returned by String.prototype.length
 *    and indexed by String.prototype.slice).
 * 4. Python Mapping:
 *    - For all Basic Multilingual Plane (BMP, U+0000 to U+FFFF) characters (including
 *      ASCII, Latin, Devanagari, Cyrillic, CJK, and standard punctuation),
 *      1 UTF-16 code unit equals exactly 1 Unicode code point (Python str index).
 *    - For Supplementary Plane characters (e.g., Emoji U+10000+, represented as surrogate
 *      pairs in UTF-16), JavaScript counts 2 UTF-16 code units per character while
 *      Python's len() counts 1 Unicode code point.
 * 5. Normalization:
 *    - rawText is canonically normalized upon ingestion:
 *      (a) Leading UTF-8 BOM (\uFEFF) is stripped.
 *      (b) All line breaks (\r\n and \r) are normalized to standard LF (\n).
 *    - All node offsets and true 1-based line numbers are computed directly against
 *      this normalized rawText.
 */

import * as XLSX from 'xlsx';
import * as mammoth from 'mammoth';
import * as pdfjsLib from 'pdfjs-dist/build/pdf.mjs';
import pdfWorker from 'pdfjs-dist/build/pdf.worker.min.mjs?url';
import { createWorker } from 'tesseract.js';
import {
  DocumentNode,
  ExtractedDocument,
  DEFAULT_EXTRACTION_LIMITS,
  ExtractionLimits,
} from './types';
import { validateFileMagicBytes, sanitizeFileName } from './magicBytes';

// Configure PDF.js worker
if (typeof window !== 'undefined' && pdfjsLib.GlobalWorkerOptions) {
  pdfjsLib.GlobalWorkerOptions.workerSrc = pdfWorker;
}

/**
 * Canonically normalizes text: strips leading UTF-8 BOM and normalizes \r\n and \r to \n.
 */
export function normalizeRawText(content: string): string {
  if (!content) return '';
  let text = content.charCodeAt(0) === 0xfeff ? content.slice(1) : content;
  return text.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
}

/**
 * Extracts digital text and layout nodes from PDF documents.
 * Falls back to OCR if the document contains scanned raster pages.
 */
export async function extractTextFromPdf(
  file: File,
  limits: ExtractionLimits = DEFAULT_EXTRACTION_LIMITS,
  onProgress?: (pct: number) => void
): Promise<{ nodes: DocumentNode[]; rawText: string; pageCount: number; ocrPerformed: boolean; ocrConfidence?: number }> {
  const arrayBuffer = await file.arrayBuffer();
  const loadingTask = pdfjsLib.getDocument({ data: arrayBuffer });
  const pdf = await loadingTask.promise;

  const pageCount = Math.min(pdf.numPages, limits.maxPdfPages);
  const nodes: DocumentNode[] = [];
  let rawText = '';
  let currentLine = 1;

  for (let pageNum = 1; pageNum <= pageCount; pageNum++) {
    if (onProgress) onProgress(Math.round((pageNum / pageCount) * 80));

    const page = await pdf.getPage(pageNum);
    const content = await page.getTextContent();
    let pageHasText = false;

    for (const item of content.items as any[]) {
      if (item.str && item.str.trim()) {
        const str = item.str.trim();

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
        rawText += str;
        const end = rawText.length;

        nodes.push({
          ref: `pdf:page_${pageNum}:item_${nodes.length + 1}`,
          page: pageNum,
          line: currentLine,
          text: str,
          start,
          end,
          source: 'digital_text',
        });
      }
    }
  }

  // Check if PDF is a scanned image (almost zero digital text extracted)
  if (rawText.length < 25 && pageCount > 0) {
    if (onProgress) onProgress(85);

    try {
      const page = await pdf.getPage(1);
      const viewport = page.getViewport({ scale: 1.5 });
      const canvas = document.createElement('canvas');
      canvas.width = viewport.width;
      canvas.height = viewport.height;
      const ctx = canvas.getContext('2d');

      if (ctx) {
        await (page.render as any)({ canvasContext: ctx, viewport, canvas }).promise;
        const blob = await new Promise<Blob | null>((resolve) => canvas.toBlob(resolve, 'image/png'));
        if (blob) {
          const ocrFile = new File([blob], 'scanned_page_1.png', { type: 'image/png' });
          const ocrResult = await extractTextFromImage(ocrFile, limits);

          return {
            nodes: ocrResult.nodes.map((n) => ({ ...n, page: 1 })),
            rawText: ocrResult.rawText,
            pageCount,
            ocrPerformed: true,
            ocrConfidence: ocrResult.confidence,
          };
        }
      }
    } catch (_) {
      // OCR fallback error, return digital text
    }
  }

  return { nodes, rawText, pageCount, ocrPerformed: false };
}

/**
 * Extracts text from PNG / JPEG images using Tesseract.js (English + Hindi models).
 */
export async function extractTextFromImage(
  file: File,
  limits: ExtractionLimits = DEFAULT_EXTRACTION_LIMITS,
  onProgress?: (pct: number) => void
): Promise<{ nodes: DocumentNode[]; rawText: string; confidence: number }> {
  const workerPromise = (async () => {
    const worker = await createWorker('eng+hin', 1, {
      logger: (m) => {
        if (m.status === 'recognizing text' && onProgress) {
          onProgress(Math.round(m.progress * 90));
        }
      },
    });

    const ret = await worker.recognize(file);
    await worker.terminate();
    return ret;
  })();

  const timeoutPromise = new Promise<never>((_, reject) =>
    setTimeout(() => reject(new Error(`OCR processing timed out after ${limits.ocrTimeoutMs / 1000}s`)), limits.ocrTimeoutMs)
  );

  const ret = await Promise.race([workerPromise, timeoutPromise]);
  const nodes: DocumentNode[] = [];
  let rawText = '';
  let currentLine = 1;

  for (const block of ret.data.blocks || []) {
    for (const paragraph of block.paragraphs || []) {
      const text = paragraph.text?.trim();
      if (text) {
        if (rawText.length > 0) {
          rawText += '\n\n';
          currentLine += 2;
        }
        const start = rawText.length;
        rawText += text;
        const end = rawText.length;

        nodes.push({
          ref: `image:ocr_block_${nodes.length + 1}`,
          line: currentLine,
          text,
          start,
          end,
          source: 'ocr',
          confidence: Math.round(paragraph.confidence) / 100,
        });
      }
    }
  }

  if (nodes.length === 0 && ret.data.text && ret.data.text.trim()) {
    const text = ret.data.text.trim();
    rawText = text;
    nodes.push({
      ref: 'image:ocr_block_1',
      line: 1,
      text,
      start: 0,
      end: text.length,
      source: 'ocr',
      confidence: Math.round(ret.data.confidence) / 100,
    });
  }

  return {
    nodes,
    rawText,
    confidence: Math.round(ret.data.confidence) / 100,
  };
}

/**
 * Extracts paragraphs and tables from Microsoft Word (.docx) documents.
 */
export async function extractTextFromDocx(
  file: File
): Promise<{ nodes: DocumentNode[]; rawText: string }> {
  const arrayBuffer = await file.arrayBuffer();
  const result = await mammoth.extractRawText({ arrayBuffer });
  const rawText = normalizeRawText(result.value);

  const lines = rawText.split('\n');
  const nodes: DocumentNode[] = [];
  let currentOffset = 0;
  let paraIdx = 0;

  lines.forEach((line, idx) => {
    const lineNum = idx + 1;
    const lineStart = currentOffset;
    currentOffset += line.length + 1; // +1 for '\n'

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

/**
 * Extracts tabular data and cell coordinates from XLSX and CSV files.
 */
export async function extractTextFromSpreadsheet(
  file: File
): Promise<{
  nodes: DocumentNode[];
  rawText: string;
  sheetNames: string[];
  tableHeaders: string[];
  tableRows: string[][];
}> {
  const arrayBuffer = await file.arrayBuffer();
  const workbook = XLSX.read(arrayBuffer, { type: 'array' });

  const nodes: DocumentNode[] = [];
  let rawText = '';
  let firstSheetHeaders: string[] = [];
  const firstSheetRows: string[][] = [];
  let currentLine = 1;

  for (const sheetName of workbook.SheetNames) {
    const sheet = workbook.Sheets[sheetName];
    if (!sheet) continue;

    const sheetData: any[][] = XLSX.utils.sheet_to_json(sheet, { header: 1 });
    if (sheetData.length === 0) continue;

    if (firstSheetHeaders.length === 0 && sheetData[0]) {
      firstSheetHeaders = sheetData[0].map((h) => String(h || ''));
      for (let r = 1; r < Math.min(sheetData.length, 12); r++) {
        if (sheetData[r]) {
          firstSheetRows.push(sheetData[r].map((c) => String(c ?? '')));
        }
      }
    }

    for (let r = 0; r < sheetData.length; r++) {
      const row = sheetData[r];
      if (!row) continue;
      let rowHasCell = false;

      for (let c = 0; c < row.length; c++) {
        const val = row[c];
        if (val !== undefined && val !== null && String(val).trim() !== '') {
          const str = String(val).trim();
          const colLetter = XLSX.utils.encode_col(c);
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
  }

  return {
    nodes,
    rawText,
    sheetNames: workbook.SheetNames,
    tableHeaders: firstSheetHeaders,
    tableRows: firstSheetRows,
  };
}

/**
 * Extracts recursive key-value tree nodes from JSON documents.
 */
export async function extractTextFromJson(
  file: File
): Promise<{ nodes: DocumentNode[]; rawText: string }> {
  const content = await file.text();
  const rawText = normalizeRawText(content);
  const parsed = JSON.parse(rawText);

  const nodes: DocumentNode[] = [];
  let searchOffset = 0;

  function traverse(obj: any, path: string) {
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
            ref: `json:${path}`,
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
            ref: `json:${path}`,
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
      obj.forEach((item, idx) => traverse(item, `${path}[${idx}]`));
      return;
    }

    if (typeof obj === 'object') {
      for (const [key, val] of Object.entries(obj)) {
        traverse(val, path === '$' ? `$.${key}` : `${path}.${key}`);
      }
    }
  }

  traverse(parsed, '$');
  return { nodes, rawText };
}

/**
 * Extracts XML element nodes safely with external entity resolution disabled.
 */
export async function extractTextFromXml(
  file: File
): Promise<{ nodes: DocumentNode[]; rawText: string }> {
  const content = await file.text();
  const rawText = normalizeRawText(content);
  const parser = new DOMParser();
  const xmlDoc = parser.parseFromString(rawText, 'application/xml');

  const parserError = xmlDoc.querySelector('parsererror');
  if (parserError) {
    throw new Error('XML parsing failed: malformed document syntax.');
  }

  const nodes: DocumentNode[] = [];
  let searchOffset = 0;

  function walk(node: Node, path: string) {
    if (node.nodeType === Node.TEXT_NODE) {
      const val = node.nodeValue?.trim();
      if (val) {
        const found = rawText.indexOf(val, searchOffset);
        if (found !== -1) {
          const start = found;
          const end = start + val.length;
          searchOffset = end;
          const line = rawText.slice(0, start).split('\n').length;
          nodes.push({
            ref: `xml:${path}`,
            line,
            text: val,
            start,
            end,
            source: 'xml_node',
          });
        }
      }
    } else if (node.nodeType === Node.ELEMENT_NODE) {
      const elem = node as Element;
      const elemPath = `${path}/${elem.tagName}`;

      for (let i = 0; i < elem.attributes.length; i++) {
        const attr = elem.attributes[i];
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
              ref: `xml:${elemPath}[@${attr.name}]`,
              line,
              text: val,
              start,
              end,
              source: 'xml_node',
            });
          }
        }
      }

      node.childNodes.forEach((child) => walk(child, elemPath));
    }
  }

  walk(xmlDoc.documentElement, '');
  return { nodes, rawText };
}

/**
 * Extracts plain text line-by-line with true 1-based line numbering and exact slice preservation.
 */
export async function extractTextFromPlainText(
  file: File
): Promise<{ nodes: DocumentNode[]; rawText: string }> {
  const content = await file.text();
  const rawText = normalizeRawText(content);
  const lines = rawText.split('\n');

  const nodes: DocumentNode[] = [];
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

/**
 * Universal Extraction Dispatcher:
 * Validates, dispatches to the corresponding extractor, and formats preview data.
 */
export async function extractUnifiedDocument(
  file: File,
  limits: ExtractionLimits = DEFAULT_EXTRACTION_LIMITS,
  onProgress?: (pct: number) => void
): Promise<ExtractedDocument> {
  const startTime = performance.now();
  const sanitizedName = sanitizeFileName(file.name);

  // 1. Magic bytes validation
  const validation = await validateFileMagicBytes(file, limits.maxFileSize);
  if (!validation.valid) {
    throw new Error(validation.error || 'File validation failed.');
  }

  const format = validation.detectedFormat;
  let nodes: DocumentNode[] = [];
  let rawText = '';
  let pageCount: number | undefined;
  let sheetNames: string[] | undefined;
  let ocrPerformed = false;
  let ocrConfidence: number | undefined;
  let previewData: ExtractedDocument['previewData'];

  if (format === 'pdf') {
    const pdfRes = await extractTextFromPdf(file, limits, onProgress);
    nodes = pdfRes.nodes;
    rawText = pdfRes.rawText;
    pageCount = pdfRes.pageCount;
    ocrPerformed = pdfRes.ocrPerformed;
    ocrConfidence = pdfRes.ocrConfidence;
    previewData = {
      type: 'pdf',
      textSample: rawText.slice(0, 1200),
      pdfPageSample: `Page 1 of ${pageCount}`,
    };
  } else if (format === 'image') {
    const imgRes = await extractTextFromImage(file, limits, onProgress);
    nodes = imgRes.nodes;
    rawText = imgRes.rawText;
    ocrPerformed = true;
    ocrConfidence = imgRes.confidence;
    previewData = {
      type: 'image',
      textSample: rawText.slice(0, 800),
      imageUrl: URL.createObjectURL(file),
    };
  } else if (format === 'docx') {
    const docxRes = await extractTextFromDocx(file);
    nodes = docxRes.nodes;
    rawText = docxRes.rawText;
    previewData = {
      type: 'text',
      textSample: rawText.slice(0, 1500),
    };
  } else if (format === 'spreadsheet') {
    const sheetRes = await extractTextFromSpreadsheet(file);
    nodes = sheetRes.nodes;
    rawText = sheetRes.rawText;
    sheetNames = sheetRes.sheetNames;
    previewData = {
      type: 'table',
      tableHeaders: sheetRes.tableHeaders,
      tableRows: sheetRes.tableRows,
    };
  } else if (format === 'json') {
    const jsonRes = await extractTextFromJson(file);
    nodes = jsonRes.nodes;
    rawText = jsonRes.rawText;
    previewData = {
      type: 'text',
      textSample: rawText.slice(0, 1500),
    };
  } else if (format === 'xml') {
    const xmlRes = await extractTextFromXml(file);
    nodes = xmlRes.nodes;
    rawText = xmlRes.rawText;
    previewData = {
      type: 'text',
      textSample: rawText.slice(0, 1500),
    };
  } else {
    // Plain text / CSV fallback
    const txtRes = await extractTextFromPlainText(file);
    nodes = txtRes.nodes;
    rawText = txtRes.rawText;
    previewData = {
      type: 'text',
      textSample: rawText.slice(0, 1500),
    };
  }

  const elapsed = Math.round(performance.now() - startTime);
  const words = rawText.trim().split(/\s+/).filter(Boolean).length;

  return {
    docId: 'doc_' + Math.random().toString(36).substring(2, 10),
    fileName: file.name,
    fileType: file.type || 'text/plain',
    fileSize: file.size,
    mimeType: file.type || 'application/octet-stream',
    nodes,
    rawText,
    metadata: {
      pageCount,
      sheetNames,
      wordCount: words,
      extractionTimeMs: elapsed,
      ocrPerformed,
      ocrConfidence,
      createdAt: new Date().toISOString(),
    },
    previewData,
  };
}
