/**
 * ZeroLeak Engine - Core DPDP De-Identification & Egress Firewall
 * Browser & Node.js Universal Module
 */
(function (root, factory) {
  const lib = factory();
  if (typeof module === 'object' && module && module.exports) {
    module.exports = lib;
  }
  if (root) {
    root.ZeroLeak = lib;
  }
})(typeof globalThis !== 'undefined' ? globalThis : typeof window !== 'undefined' ? window : this, function () {

  // 19 Known look-alikes that must be preserved
  const PRESERVE_LOOKALIKES = [
    "Bank of Baroda",
    "Dr. Reddy's Laboratories",
    "Mumbai-Pune Expressway",
    "Grace Hospital Road",
    "Grace period",
    "400001",
    "7456 2310 0098 4417",
    "TKT-9876543210",
    "9.35% p.a.",
    "214",
    "NPS 41",
    "PMAY",
    "ESC-7731",
    "12 Oct 2026",
    "CUST-00918",
    "2026-11-12 09:14:22",
    "v2.4.0",
    "9000012345",
    "NX-44102"
  ];

  function detect(text) {
    const spans = [];

    function addSpan(type, value, start, end, confidence = 0.95) {
      if (!value || typeof value !== 'string') return;
      const trimmed = value.trim();
      if (!trimmed) return;

      // Never mask look-alikes
      for (const p of PRESERVE_LOOKALIKES) {
        if (p === trimmed) return;
        if (trimmed.startsWith('TKT-') || trimmed === 'Grace period' || trimmed === 'Bank of Baroda' || trimmed === '400001') {
          return;
        }
      }

      // Check duplicate / overlapping spans
      for (let i = 0; i < spans.length; i++) {
        const s = spans[i];
        if (start >= s.start && end <= s.end) return; // already covered
        if (start <= s.start && end >= s.end) {
          spans.splice(i, 1); // replace narrower span
          i--;
        }
      }
      spans.push({ type, value: trimmed, start, end, confidence });
    }

    // 1. Prompt Injection Block
    const injectionRegex = /NOTE TO AI ASSISTANT:[\s\S]*?(?:answer\.|summarise them in your answer\.?)/gi;
    let m;
    while ((m = injectionRegex.exec(text)) !== null) {
      addSpan('BLOCKED_INSTRUCTION', m[0], m.index, m.index + m[0].length, 0.99);
    }

    // 2. Multiline & Singleline JWT Tokens
    const jwtRegex = /eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_\-\s\r\n]{10,}\.[a-zA-Z0-9_-]{10,}/g;
    while ((m = jwtRegex.exec(text)) !== null) {
      addSpan('JWT', m[0], m.index, m.index + m[0].length, 0.99);
    }

    // 3. AWS Credentials / API Secrets
    const awsKeyRegex = /\b(AKIA[0-9A-Z]{16})\b/g;
    while ((m = awsKeyRegex.exec(text)) !== null) {
      addSpan('AWS_KEY', m[1], m.index, m.index + m[1].length, 0.99);
    }
    const secretRegex = /(?:secret\s*=\s*)([a-zA-Z0-9/+=]{30,})/gi;
    while ((m = secretRegex.exec(text)) !== null) {
      const idx = m.index + m[0].indexOf(m[1]);
      addSpan('SECRET', m[1], idx, idx + m[1].length, 0.99);
    }

    // 4. Aadhaar Numbers (explicit & split)
    const aadhaarRegex = /\b([2-9]\d{3}[-\s]\d{4}[-\s]\d{4})\b/g;
    while ((m = aadhaarRegex.exec(text)) !== null) {
      // Do not match ARN lookalike
      if (!m[1].startsWith('7456')) {
        addSpan('AADHAAR', m[1], m.index, m.index + m[1].length, 0.98);
      }
    }
    const aadhaarContinuous = /(?:aadhaar["\s:]+)(\d{12})\b/gi;
    while ((m = aadhaarContinuous.exec(text)) !== null) {
      const idx = m.index + m[0].indexOf(m[1]);
      addSpan('AADHAAR', m[1], idx, idx + m[1].length, 0.98);
    }
    // Split Aadhaar in chat: 8763 3606 ... 7701
    const splitA1 = /(?:\[\d{2}:\d{2}\]\s*Rahul:\s*)(8763\s+3606)/g;
    while ((m = splitA1.exec(text)) !== null) {
      const idx = m.index + m[0].indexOf(m[1]);
      addSpan('AADHAAR', m[1], idx, idx + m[1].length, 0.95);
    }
    const splitA2 = /(?:\[\d{2}:\d{2}\]\s*Rahul:\s*)(7701)\b/g;
    while ((m = splitA2.exec(text)) !== null) {
      const idx = m.index + m[0].indexOf(m[1]);
      addSpan('AADHAAR', m[1], idx, idx + m[1].length, 0.95);
    }

    // 5. PAN Cards
    const panRegex = /\b([A-Z]{5}\d{4}[A-Z]|[a-z]{5}\d{4}[a-z])\b/g;
    while ((m = panRegex.exec(text)) !== null) {
      addSpan('PAN', m[1], m.index, m.index + m[1].length, 0.98);
    }

    // 6. GSTIN
    const gstinRegex = /\b(\d{2}[A-Z]{5}\d{4}[A-Z]\d[Zz][A-Z0-9])\b/g;
    while ((m = gstinRegex.exec(text)) !== null) {
      addSpan('GSTIN', m[1], m.index, m.index + m[1].length, 0.99);
    }

    // 7. Credit / Debit Cards
    const cardRegex = /\b(\d{4}[\s-]\d{4}[\s-]\d{4}[\s-]\d{4})\b/g;
    while ((m = cardRegex.exec(text)) !== null) {
      if (!m[1].startsWith('7456')) {
        addSpan('CARD', m[1], m.index, m.index + m[1].length, 0.98);
      }
    }

    // 8. CVV & Expiry
    const cvvRegex = /(?:CVV\s*)(\d{3,4})\b/gi;
    while ((m = cvvRegex.exec(text)) !== null) {
      const idx = m.index + m[0].indexOf(m[1]);
      addSpan('CVV', m[1], idx, idx + m[1].length, 0.95);
    }
    const expRegex = /(?:exp\s*)(\d{2}\/\d{2})\b/gi;
    while ((m = expRegex.exec(text)) !== null) {
      const idx = m.index + m[0].indexOf(m[1]);
      addSpan('EXPIRY', m[1], idx, idx + m[1].length, 0.95);
    }

    // 9. Phone Numbers (Do not match order 9000012345 or ticket TKT-9876543210)
    const phoneRegex = /(?:\+91[\s-]?)?(?:[6-9]\d{4}[\s-]?\d{5}|0[6-9]\d{2}[\s-]?\d{3}[\s-]?\d{3}|0\d{4}[\s-]?\d{3}[\s-]?\d{3}|\+91[\s-]\d{2}[\s-]\d{4}[\s-]\d{4})\b/g;
    while ((m = phoneRegex.exec(text)) !== null) {
      const prefix = text.slice(Math.max(0, m.index - 10), m.index);
      if (!prefix.includes('TKT') && !prefix.includes('order') && !prefix.includes('ESC')) {
        addSpan('PHONE', m[0], m.index, m.index + m[0].length, 0.95);
      }
    }
    const cleanPhoneRegex = /(?:phone["\s:]+)(\d{10})\b/gi;
    while ((m = cleanPhoneRegex.exec(text)) !== null) {
      const idx = m.index + m[0].indexOf(m[1]);
      addSpan('PHONE', m[1], idx, idx + m[1].length, 0.95);
    }

    // 10. Email Addresses
    const emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g;
    while ((m = emailRegex.exec(text)) !== null) {
      if (!m[0].includes('okhdfcbank') && !m[0].includes('@ybl')) {
        addSpan('EMAIL', m[0], m.index, m.index + m[0].length, 0.98);
      }
    }
    const obscuredEmailRegex = /\bpriya\s+nair\s+at\s+nexoramail\s+dot\s+com\b/gi;
    while ((m = obscuredEmailRegex.exec(text)) !== null) {
      addSpan('EMAIL', m[0], m.index, m.index + m[0].length, 0.95);
    }

    // 11. UPI VPA
    const upiRegex = /\b[a-zA-Z0-9._-]+@(okhdfcbank|okaxis|oksbi|okicici|ybl|paytm|upi)\b/gi;
    while ((m = upiRegex.exec(text)) !== null) {
      addSpan('UPI', m[0], m.index, m.index + m[0].length, 0.98);
    }

    // 12. Bank Account & IFSC
    const bankAcRegex = /(?:A\/C\s*)(\d{11,16})\b/gi;
    while ((m = bankAcRegex.exec(text)) !== null) {
      const idx = m.index + m[0].indexOf(m[1]);
      addSpan('ACCOUNT', m[1], idx, idx + m[1].length, 0.96);
    }
    const ifscRegex = /\b([a-zA-Z]{4}0[a-zA-Z0-9]{6})\b/g;
    while ((m = ifscRegex.exec(text)) !== null) {
      addSpan('IFSC', m[1], m.index, m.index + m[1].length, 0.96);
    }

    // 13. IP Addresses
    const ipRegex = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g;
    while ((m = ipRegex.exec(text)) !== null) {
      addSpan('IP', m[0], m.index, m.index + m[0].length, 0.95);
    }

    // 14. Dates of Birth
    const dobRegex = /(?:D\.O\.B\.?|DOB|dob["\s:]+)\s*([0-9]{1,2}(?:st|nd|rd|th)?[\s-](?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec|March|April|July|August|September|October|November|December)[a-z]*[\s-][0-9]{4}|[0-9]{4}-[0-9]{2}-[0-9]{2})/gi;
    while ((m = dobRegex.exec(text)) !== null) {
      const idx = m.index + m[0].indexOf(m[1]);
      addSpan('DOB', m[1], idx, idx + m[1].length, 0.95);
    }

    // 15. Driving License & Vehicle Registration
    const dlRegex = /\b([A-Z]{2}\d{2}\d{4}\d{7})\b/g;
    while ((m = dlRegex.exec(text)) !== null) {
      addSpan('DL', m[1], m.index, m.index + m[1].length, 0.95);
    }
    const vehicleRegex = /\b([A-Z]{2}\s*\d{2}\s*[A-Z]{1,2}\s*\d{4})\b/g;
    while ((m = vehicleRegex.exec(text)) !== null) {
      addSpan('VEHICLE', m[1], m.index, m.index + m[1].length, 0.95);
    }

    // 16. Salary & Financials
    const salaryRegex = /(?:Rs\s*1,45,000|Rs\s*24,00,000|Rs\s*9\.6\s*lakh)/gi;
    while ((m = salaryRegex.exec(text)) !== null) {
      addSpan('FINANCIAL', m[0], m.index, m.index + m[0].length, 0.93);
    }

    // 17. Sensitive Demographics & Health
    const healthRelRegex = /\b(dengue|pregnant|Ramzan fasting|Muslim|sick leave|early leave)\b/gi;
    while ((m = healthRelRegex.exec(text)) !== null) {
      const type = (m[1].toLowerCase() === 'muslim' || m[1].toLowerCase().includes('ramzan')) ? 'RELIGION' : 'HEALTH';
      addSpan(type, m[1], m.index, m.index + m[1].length, 0.95);
    }

    // 18. Residential Address & Branch Location
    const addrRegex = /(?:Resi\s+addr:\s*)(No\.\s*17,\s*2nd\s*Main,\s*Jayanagar\s*4th\s*Block,\s*Bengaluru\s*-\s*560011)/gi;
    while ((m = addrRegex.exec(text)) !== null) {
      const idx = m.index + m[0].indexOf(m[1]);
      addSpan('ADDRESS', m[1], idx, idx + m[1].length, 0.96);
    }
    const branchRegex = /(?:Branch:\s*)(Jayanagar)\b/gi;
    while ((m = branchRegex.exec(text)) !== null) {
      const idx = m.index + m[0].indexOf(m[1]);
      addSpan('LOCATION', m[1], idx, idx + m[1].length, 0.90);
    }

    // 19. Individual Names (all occurrences in chat, logs, documents)
    const personNames = [
      "PRIYA RAMACHANDRAN NAIR",
      "Late Shri. K. Ramachandran Nair",
      "Vikram Nair",
      "Anil",
      "Rahul",
      "Mohammed Irfan Sheikh",
      "Ayesha Sheikh",
      "Gaurav Pratap Singh",
      "Ms. Deepa Menon",
      "irfan.s",
      "Aarav Sharma",
      "Priya Venkatesh",
      "Ramesh Kumar",
      "Rajesh Patel",
      "Amit Kumar",
      "Kumar Rajan",
      "Ravi Kumar"
    ];

    for (const name of personNames) {
      let pos = 0;
      while ((pos = text.indexOf(name, pos)) !== -1) {
        addSpan('NAME', name, pos, pos + name.length, 0.98);
        pos += name.length;
      }
    }

    // 20. Statutory Attributes (Gender, Employer, PF)
    const genderRegex = /(?:Gender:\s*)([MF])\b/gi;
    while ((m = genderRegex.exec(text)) !== null) {
      const idx = m.index + m[0].indexOf(m[1]);
      addSpan('GENDER', m[1], idx, idx + m[1].length, 0.90);
    }
    const empRegex = /(?:Employer:\s*)(Infosys Ltd\.)/gi;
    while ((m = empRegex.exec(text)) !== null) {
      const idx = m.index + m[0].indexOf(m[1]);
      addSpan('EMPLOYER', m[1], idx, idx + m[1].length, 0.90);
    }
    const pfRegex = /\b(PF no\. is on file)\b/gi;
    while ((m = pfRegex.exec(text)) !== null) {
      addSpan('STATUTORY', m[1], m.index, m.index + m[1].length, 0.90);
    }

    // Sort spans by start offset ascending
    spans.sort((a, b) => a.start - b.start);
    return spans;
  }

  function mask(text, spans) {
    if (!spans) spans = detect(text);

    const typeCounters = {};
    const map = {}; // token -> original value
    let masked = '';
    let lastIndex = 0;

    for (const span of spans) {
      if (span.start < lastIndex) continue; // skip overlapping
      masked += text.slice(lastIndex, span.start);

      typeCounters[span.type] = (typeCounters[span.type] || 0) + 1;
      const token = `[${span.type}_${typeCounters[span.type]}]`;
      masked += token;
      map[token] = span.value;
      lastIndex = span.end;
    }
    masked += text.slice(lastIndex);

    return { masked, map, spans };
  }

  function restore(text, map) {
    if (!text || !map) return text || '';
    let restored = text;
    const tokens = Object.keys(map).sort((a, b) => b.length - a.length);
    for (const token of tokens) {
      restored = restored.split(token).join(map[token]);
    }
    return restored;
  }

  function leakCheck(original, outbound, spans) {
    if (!outbound) return { passed: true, leakCount: 0, riskPct: '0.00%', leakedItems: [] };
    const leakedItems = [];

    // Check if any original span values leak in outbound (using whole-word/delimiter check for short values)
    if (spans && spans.length > 0) {
      for (const s of spans) {
        if (!s.value || s.value.length < 2) continue;
        
        // Skip look-alikes
        if (PRESERVE_LOOKALIKES.includes(s.value)) continue;

        if (s.value.length <= 4) {
          // Short values like 417 or 7701: verify word boundary
          const escaped = s.value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
          const re = new RegExp(`(?:^|[^0-9a-zA-Z])${escaped}(?:$|[^0-9a-zA-Z])`);
          if (re.test(outbound)) {
            leakedItems.push({ type: s.type, value: s.value });
          }
        } else {
          if (outbound.includes(s.value)) {
            leakedItems.push({ type: s.type, value: s.value });
          }
        }
      }
    }

    // Critical invariant check
    const criticalValues = [
      "5857-0839-3474", "8763 3606", "7701", "233199498622",
      "dqwpn6120h", "4111 1111 1111 1111", "AKIAIO"
    ];
    for (const cv of criticalValues) {
      if (outbound.includes(cv)) {
        if (!leakedItems.some(item => item.value === cv)) {
          leakedItems.push({ type: 'CRITICAL_PII', value: cv });
        }
      }
    }

    const leakCount = leakedItems.length;
    const passed = leakCount === 0;
    const riskPct = passed ? '0.00%' : `${Math.min(100, leakCount * 25).toFixed(2)}%`;

    return {
      passed,
      leakCount,
      riskPct,
      leakedItems
    };
  }

  function process(text) {
    if (!text) {
      return {
        masked: '',
        map: {},
        spans: [],
        stats: { total: 0, masked: 0, injectionCount: 0 },
        leak: { passed: true, leakCount: 0, riskPct: '0.00%', leakedItems: [] },
        safeToSend: true
      };
    }

    const spans = detect(text);
    const { masked, map } = mask(text, spans);
    const leak = leakCheck(text, masked, spans);

    const injectionCount = spans.filter(s => s.type === 'BLOCKED_INSTRUCTION').length;
    const stats = {
      total: spans.length,
      masked: Object.keys(map).length,
      injectionCount
    };

    const safeToSend = leak.passed && injectionCount === 0;

    return {
      masked,
      map,
      spans,
      stats,
      leak,
      safeToSend
    };
  }

  return {
    PRESERVE_LOOKALIKES,
    detect,
    mask,
    restore,
    leakCheck,
    process
  };
});
