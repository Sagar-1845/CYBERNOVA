/**
 * ZeroLeak IO - Client-Side Document Ingestion & PDF Parser
 * Integrates Mozilla pdf.js (cdnjs) and standard text readers.
 */
(function (root, factory) {
  const lib = factory();
  if (typeof module === 'object' && module && module.exports) {
    module.exports = lib;
  }
  if (root) {
    root.ZeroLeakIO = lib;
  }
})(typeof globalThis !== 'undefined' ? globalThis : typeof window !== 'undefined' ? window : this, function () {

  /**
   * Reads and extracts text from supported document types (.pdf, .txt, .json, .csv, .log, .md).
   * Throws an error for scanned PDFs that contain no digital text layer.
   */
  async function readDocument(file) {
    if (!file) {
      throw new Error('No document file provided.');
    }

    const name = file.name || 'document.txt';
    const ext = name.toLowerCase().split('.').pop() || '';

    // Handle PDF files
    if (ext === 'pdf' || file.type === 'application/pdf') {
      const pdfjs = (typeof window !== 'undefined' && window.pdfjsLib) || (typeof globalThis !== 'undefined' && globalThis.pdfjsLib);
      if (!pdfjs) {
        throw new Error('PDF.js library is not loaded. Please ensure pdf.js script is included.');
      }

      // Configure standard worker if not configured
      if (!pdfjs.GlobalWorkerOptions.workerSrc) {
        pdfjs.GlobalWorkerOptions.workerSrc = 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js';
      }

      const arrayBuffer = await file.arrayBuffer();
      const loadingTask = pdfjs.getDocument({ data: arrayBuffer });
      const pdf = await loadingTask.promise;
      const numPages = pdf.numPages;

      let extractedText = '';
      for (let i = 1; i <= numPages; i++) {
        const page = await pdf.getPage(i);
        const textContent = await page.getTextContent();
        const pageText = textContent.items.map((item) => item.str).join(' ');
        extractedText += (i > 1 ? '\n\n' : '') + pageText;
      }

      const trimmed = extractedText.trim();
      if (!trimmed || trimmed.length === 0) {
        const err = new Error('scanned PDF, OCR required');
        err.name = 'ScannedPdfError';
        err.isScanned = true;
        throw err;
      }

      return {
        text: extractedText,
        fileName: name,
        fileSize: `${(file.size / 1024).toFixed(1)} KB`,
        pageCount: numPages,
        isPdf: true
      };
    }

    // Handle Plaintext, JSON, CSV, Log, Markdown
    const allowedExts = ['txt', 'json', 'csv', 'log', 'md'];
    if (allowedExts.includes(ext) || file.type.startsWith('text/')) {
      const text = await new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = (e) => resolve(e.target.result);
        reader.onerror = () => reject(new Error(`Failed to read file ${name}`));
        reader.readAsText(file);
      });

      return {
        text: text || '',
        fileName: name,
        fileSize: `${(file.size / 1024).toFixed(1)} KB`,
        pageCount: 1,
        isPdf: false
      };
    }

    throw new Error(`Unsupported document format: .${ext}. Supported formats: .pdf, .txt, .json, .csv, .log, .md`);
  }

  /**
   * Example pipeline run: Ingestion -> ZeroLeak De-Identification
   */
  async function runPipeline(file) {
    const doc = await readDocument(file);
    const zl = (typeof window !== 'undefined' && window.ZeroLeak) || (typeof globalThis !== 'undefined' && globalThis.ZeroLeak);
    if (!zl) {
      throw new Error('ZeroLeak engine not loaded.');
    }
    const result = zl.process(doc.text);
    return {
      doc,
      result
    };
  }

  return {
    readDocument,
    runPipeline
  };
});
