/**
 * ZeroLeak OCR - Client-Side Image Ingestion, OCR & Visual Redaction
 * Powered by Tesseract.js (WebAssembly) & HTML5 Canvas.
 * Zero-upload, zero-retention Sovereign Enclave execution.
 */
(function (root, factory) {
  const lib = factory();
  if (typeof module === 'object' && module && module.exports) {
    module.exports = lib;
  }
  if (root) {
    root.ZeroLeakOCR = lib;
  }
})(typeof globalThis !== 'undefined' ? globalThis : typeof window !== 'undefined' ? window : this, function () {

  /**
   * Checks whether a file or filename represents a supported image (.jpg, .jpeg, .png).
   */
  function isImage(file) {
    if (!file) return false;
    if (typeof file === 'string') {
      return /\.(jpe?g|png)$/i.test(file);
    }
    const type = file.type || '';
    const name = file.name || '';
    return type === 'image/jpeg' || type === 'image/png' || /\.(jpe?g|png)$/i.test(name);
  }

  /**
   * Loads an image into an Image element asynchronously.
   */
  function readImage(file) {
    return new Promise((resolve, reject) => {
      if (typeof window === 'undefined' || typeof Image === 'undefined') {
        resolve({ width: 900, height: 600 });
        return;
      }
      const img = new Image();
      const url = typeof file === 'string' ? file : URL.createObjectURL(file);
      img.onload = () => {
        if (typeof file !== 'string') URL.revokeObjectURL(url);
        resolve(img);
      };
      img.onerror = () => {
        if (typeof file !== 'string') URL.revokeObjectURL(url);
        reject(new Error('Failed to load image element.'));
      };
      img.src = url;
    });
  }

  /**
   * Draws solid black redact boxes over sensitive regions on canvas and returns a JPEG Blob / Object URL.
   */
  async function redactImage(imageInput, boxes = []) {
    if (typeof document === 'undefined') {
      // Node fallback for testing
      return {
        redactedUrl: 'blob:simulated-redacted-image',
        blob: null
      };
    }

    let imgElement;
    if (imageInput instanceof HTMLImageElement) {
      imgElement = imageInput;
    } else {
      imgElement = await readImage(imageInput);
    }

    const canvas = document.createElement('canvas');
    canvas.width = imgElement.naturalWidth || imgElement.width || 900;
    canvas.height = imgElement.naturalHeight || imgElement.height || 600;
    const ctx = canvas.getContext('2d');

    // 1. Draw base image
    ctx.drawImage(imgElement, 0, 0);

    // 2. Overlay black boxes for every sensitive detected word/box
    ctx.fillStyle = '#000000';
    for (const b of boxes) {
      const x0 = b.x0 ?? b.x ?? 0;
      const y0 = b.y0 ?? b.y ?? 0;
      const x1 = b.x1 ?? (x0 + (b.width || b.w || 0));
      const y1 = b.y1 ?? (y0 + (b.height || b.h || 0));

      const padX = 3;
      const padY = 3;
      const rx = Math.max(0, x0 - padX);
      const ry = Math.max(0, y0 - padY);
      const rw = (x1 - x0) + padX * 2;
      const rh = (y1 - y0) + padY * 2;

      ctx.fillRect(rx, ry, rw, rh);
    }

    // 3. Export as JPEG blob
    return new Promise((resolve) => {
      canvas.toBlob(
        (blob) => {
          if (!blob) {
            resolve({ redactedUrl: '', blob: null });
            return;
          }
          const redactedUrl = URL.createObjectURL(blob);
          resolve({ redactedUrl, blob });
        },
        'image/jpeg',
        0.92
      );
    });
  }

  /**
   * Scans an image end-to-end:
   * OCR extraction -> ZeroLeak.process -> Visual Bounding-box Redaction -> Metrics & Redacted URL
   */
  async function scanImage(file, options = {}) {
    console.log('[ZeroLeakOCR] scanImage called for:', file?.name, 'type:', file?.type, 'size:', file?.size);
    if (!isImage(file)) {
      throw new Error('Unsupported image format. ZeroLeak OCR supports JPEG (.jpg, .jpeg) and PNG (.png) files.');
    }

    let ocrText = '';
    let confidence = 0;
    let words = [];

    // Check Tesseract availability or mock options
    const Tesseract = (typeof window !== 'undefined' && window.Tesseract) || (typeof globalThis !== 'undefined' && globalThis.Tesseract);
    
    if (typeof options.mockOcrText === 'string') {
      // Testing hook
      ocrText = options.mockOcrText;
      confidence = options.mockConfidence || 0;
      words = options.mockWords || [];
    } else if (Tesseract && Tesseract.recognize) {
      const isBrowser = typeof window !== 'undefined';
      const ocrOptions = {
        logger: options.onProgress || (() => {})
      };
      if (isBrowser) {
        ocrOptions.workerPath = '/worker.min.js';
        ocrOptions.corePath = '/tesseract-core.wasm.js';
        ocrOptions.langPath = '/';
      }
      try {
        console.log('[ZeroLeakOCR] calling Tesseract.recognize...');
        res = await Tesseract.recognize(file, 'eng', {
          logger: (m) => {
            console.log('[Tesseract Logger]:', m?.status, m?.progress);
            if (options.onProgress) options.onProgress(m);
          }
        });
        console.log('[ZeroLeakOCR] Tesseract.recognize resolved successfully!');
      } catch (workerErr) {
        console.error('[ZeroLeakOCR] Tesseract.recognize error:', workerErr);
        throw workerErr;
      }
      ocrText = res.data?.text || '';
      confidence = res.data?.confidence || 0;
      words = res.data?.words || [];
    } else {
      throw new Error('Tesseract.js OCR engine is not loaded. Please ensure tesseract.min.js script is included.');
    }

    const trimmed = ocrText.trim();
    if (!trimmed || trimmed.length === 0) {
      throw new Error('No readable text detected in image. OCR requires clear, high-contrast text.');
    }

    // Get ZeroLeak engine
    const ZeroLeak = (typeof window !== 'undefined' && window.ZeroLeak) || (typeof globalThis !== 'undefined' && globalThis.ZeroLeak);
    if (!ZeroLeak || !ZeroLeak.process) {
      throw new Error('ZeroLeak engine is not loaded.');
    }

    // Process through ZeroLeak PII firewall
    const processResult = ZeroLeak.process(ocrText);

    // Map sensitive detected spans to word bounding boxes
    const sensitiveBoxes = [];
    if (words && words.length > 0 && processResult.spans) {
      for (const span of processResult.spans) {
        if (!span.value) continue;
        const spanWords = span.value.toLowerCase().split(/\s+/).filter(Boolean);
        for (const w of words) {
          const wText = (w.text || '').toLowerCase().replace(/[^a-z0-9]/g, '');
          for (const sw of spanWords) {
            const cleanSw = sw.replace(/[^a-z0-9]/g, '');
            if (cleanSw.length >= 3 && (wText.includes(cleanSw) || cleanSw.includes(wText))) {
              if (w.bbox) {
                sensitiveBoxes.push(w.bbox);
              }
              break;
            }
          }
        }
      }
    }

    // Produce visually redacted JPEG
    const { redactedUrl, blob } = await redactImage(file, sensitiveBoxes);

    return {
      text: ocrText,
      ocrConfidence: `${Math.round(confidence)}%`,
      process: processResult,
      redactedUrl,
      redactedBlob: blob,
      boxes: sensitiveBoxes
    };
  }

  return {
    isImage,
    readImage,
    redactImage,
    scanImage
  };
});
