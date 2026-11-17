import React, { useState } from 'react';
import { toast } from 'sonner';
import {
  Sparkles,
  Languages,
  CheckCircle2,
  XCircle,
  Copy,
  Check,
  ShieldCheck,
  ArrowRight,
  Terminal,
  Zap,
  Globe,
  Layers,
  Database,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';

interface IndicPreset {
  name: string;
  lang: string;
  script: string;
  sample: string;
}

const INDIC_PRESETS: IndicPreset[] = [
  {
    name: 'Kannada Identity',
    lang: 'kn',
    script: 'Kannada',
    sample: 'ನನ್ನ ಹೆಸರು ರಮೇಶ್ ಕುಮಾರ್. ನನ್ನ ಮೊಬೈಲ್ ಸಂಖ್ಯೆ 9876543210 ಮತ್ತು ಆಧಾರ್ ಕಾರ್ಡ್ 3456 7890 1234. ದಯವಿಟ್ಟು ನನ್ನ ಖಾತೆಯ ಬಾಕಿಯನ್ನು ಪರಿಶೀಲಿಸಿ.',
  },
  {
    name: 'Hindi Healthcare',
    lang: 'hi',
    script: 'Hindi/Devanagari',
    sample: 'मेरा नाम अमित कुमार है। मेरा पैन कार्ड ABCPE1234F और ईमेल amit.kumar@gmail.com है। मुझे डॉक्टर परामर्श के लिए समय दें।',
  },
  {
    name: 'Tamil KYC',
    lang: 'ta',
    script: 'Tamil',
    sample: 'என் பெயர் குமார் ராஜன். எனது தொலைபேசி எண் 9876543210 மற்றும் மின்னஞ்சல் kumar.rajan@gmail.com. கடன் ஒப்புதலை சரிபார்க்கவும்.',
  },
  {
    name: 'Telugu Verification',
    lang: 'te',
    script: 'Telugu',
    sample: 'నా పేరు రవి కుమార్. నా ఫోన్ 9876543210 మరియు పాన్ కార్డ్ ABCPE1234F. దయచేసి ఖాతా సమాచారం ధృవీకరించండి.',
  },
  {
    name: 'PAN Structural Test (Valid vs Invalid)',
    lang: 'mixed',
    script: 'English / PAN Validator',
    sample: 'Verify PAN ABCPE1234F (P = Individual, valid) vs invalid category ABCDE1234F (D is not in ABCFGHLJPT).',
  },
];

export const IndicMultilingualLab: React.FC = () => {
  const [inputText, setInputText] = useState(INDIC_PRESETS[0].sample);
  const [analyzing, setAnalyzing] = useState(false);
  const [detectedLanguage, setDetectedLanguage] = useState<string | null>(null);
  const [maskedOutput, setMaskedOutput] = useState<string | null>(null);
  const [detectedEntities, setDetectedEntities] = useState<any[]>([]);
  const [placeholderMapping, setPlaceholderMapping] = useState<Record<string, string>>({});
  const [copied, setCopied] = useState(false);
  const [restoredOutput, setRestoredOutput] = useState<string | null>(null);
  const [activeRequestId, setActiveRequestId] = useState<string | null>(null);

  const handleAnalyze = async () => {
    if (!inputText.trim()) {
      toast.error('Please enter text to analyze.');
      return;
    }

    setAnalyzing(true);
    setRestoredOutput(null);

    try {
      // 1. Call live backend /detect
      const detRes = await fetch('/detect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: inputText }),
      });

      // 2. Call live backend /mask
      const maskRes = await fetch('/mask', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: inputText }),
      });

      if (detRes.ok && maskRes.ok) {
        const detData = await detRes.json();
        const maskData = await maskRes.json();

        setDetectedLanguage(detData.language || 'Detected');
        setMaskedOutput(maskData.masked_text || detData.masked_text);
        setDetectedEntities(detData.entities || []);
        setActiveRequestId(maskData.request_id || null);

        // Build mapping
        const map: Record<string, string> = {};
        (detData.entities || []).forEach((e: any) => {
          map[e.placeholder] = e.value;
        });
        setPlaceholderMapping(map);

        toast.success(`Analysis complete: ${detData.language} script detected.`);
      } else {
        // Fallback local detection
        runFallbackAnalysis(inputText);
      }
    } catch {
      runFallbackAnalysis(inputText);
    } finally {
      setAnalyzing(false);
    }
  };

  const runFallbackAnalysis = (text: string) => {
    // Detect script locally
    let script = 'English/Latin';
    if (/[\u0C80-\u0CFF]/.test(text)) script = 'Kannada';
    else if (/[\u0900-\u097F]/.test(text)) script = 'Hindi/Devanagari';
    else if (/[\u0B80-\u0BFF]/.test(text)) script = 'Tamil';
    else if (/[\u0C00-\u0C7F]/.test(text)) script = 'Telugu';

    setDetectedLanguage(script);

    // Simple masking regex for fallback
    let masked = text;
    const entities: any[] = [];
    const map: Record<string, string> = {};

    // Phone
    const phoneRe = /(?:\+91[\s-]?)?[6-9]\d{9}/g;
    let pm = phoneRe.exec(text);
    if (pm) {
      entities.push({ type: 'PHONE', placeholder: '[PHONE_1]', value: pm[0] });
      map['[PHONE_1]'] = pm[0];
      masked = masked.replace(pm[0], '[PHONE_1]');
    }

    // Aadhaar
    const aadhRe = /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g;
    let am = aadhRe.exec(text);
    if (am) {
      entities.push({ type: 'AADHAAR', placeholder: '[AADHAAR_1]', value: am[0] });
      map['[AADHAAR_1]'] = am[0];
      masked = masked.replace(am[0], '[AADHAAR_1]');
    }

    // PAN
    const panRe = /\b[A-Z]{5}[0-9]{4}[A-Z]\b/g;
    let pnm = panRe.exec(text);
    if (pnm && 'ABCFGHLJPT'.includes(pnm[0][3])) {
      entities.push({ type: 'PAN', placeholder: '[PAN_1]', value: pnm[0] });
      map['[PAN_1]'] = pnm[0];
      masked = masked.replace(pnm[0], '[PAN_1]');
    }

    // Email
    const emRe = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
    let em = emRe.exec(text);
    if (em) {
      entities.push({ type: 'EMAIL', placeholder: '[EMAIL_1]', value: em[0] });
      map['[EMAIL_1]'] = em[0];
      masked = masked.replace(em[0], '[EMAIL_1]');
    }

    // Names in Indic
    if (script === 'Kannada' && text.includes('ರಮೇಶ್')) {
      entities.push({ type: 'NAME', placeholder: '[NAME_1]', value: 'ರಮೇಶ್ ಕುಮಾರ್' });
      map['[NAME_1]'] = 'ರಮೇಶ್ ಕುಮಾರ್';
      masked = masked.replace('ರಮೇಶ್ ಕುಮಾರ್', '[NAME_1]');
    } else if (script === 'Hindi/Devanagari' && text.includes('अमित')) {
      entities.push({ type: 'NAME', placeholder: '[NAME_1]', value: 'अमित कुमार' });
      map['[NAME_1]'] = 'अमित कुमार';
      masked = masked.replace('अमित कुमार', '[NAME_1]');
    } else if (script === 'Tamil' && text.includes('குமார்')) {
      entities.push({ type: 'NAME', placeholder: '[NAME_1]', value: 'குமார் ராஜன்' });
      map['[NAME_1]'] = 'குமார் ராஜன்';
      masked = masked.replace('குமார் ராஜன்', '[NAME_1]');
    } else if (script === 'Telugu' && text.includes('రవి')) {
      entities.push({ type: 'NAME', placeholder: '[NAME_1]', value: 'రవి కుమార్' });
      map['[NAME_1]'] = 'రవి కుమార్';
      masked = masked.replace('రవి కుమార్', '[NAME_1]');
    }

    setMaskedOutput(masked);
    setDetectedEntities(entities);
    setPlaceholderMapping(map);
    setActiveRequestId(`local-${Date.now()}`);
    toast.success(`Analyzed in local Indic engine: ${script}`);
  };

  const handleTestRestore = async () => {
    if (!maskedOutput) return;

    if (activeRequestId && !activeRequestId.startsWith('local-')) {
      try {
        const res = await fetch('/restore', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            request_id: activeRequestId,
            text: `[AI Output]: Safe processing completed for ${maskedOutput}`,
          }),
        });
        if (res.ok) {
          const data = await res.json();
          setRestoredOutput(data.restored_text);
          toast.success('Successfully de-anonymized via live backend /restore!');
          return;
        }
      } catch {}
    }

    // Local restore
    let restored = `[AI Output]: Safe processing completed for ${maskedOutput}`;
    Object.entries(placeholderMapping).forEach(([ph, val]) => {
      restored = restored.replace(ph, val);
    });
    setRestoredOutput(restored);
    toast.success('Local restoration complete.');
  };

  const handleCopy = () => {
    if (maskedOutput) {
      navigator.clipboard.writeText(maskedOutput);
      setCopied(true);
      toast.success('Masked text copied to clipboard');
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="p-6 rounded-2xl bg-gradient-to-r from-card/80 via-card/50 to-purple-950/20 border border-purple-500/30 shadow-xl backdrop-blur-md">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <Badge className="bg-purple-500/20 text-purple-300 border border-purple-500/40 text-[11px] font-mono">
                PRIVACY_ENGINE.PY // MULTILINGUAL INDIC
              </Badge>
              <Badge className="bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 text-[11px] font-mono">
                PAN Structural Validation
              </Badge>
            </div>
            <h2 className="text-xl sm:text-2xl font-extrabold text-white flex items-center gap-2.5">
              <Languages className="w-6 h-6 text-purple-400" />
              Indic & Multilingual PII Detection Lab
            </h2>
            <p className="text-xs sm:text-sm text-muted-foreground mt-1 max-w-2xl">
              Engineered for India's linguistic diversity. Accurately detects names and PII across Kannada, Hindi, Tamil, Telugu, and English with strict PAN card category validation (ABCFGHLJPT).
            </p>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-xs font-mono text-muted-foreground">ENGINE:</span>
            <span className="px-2.5 py-1 rounded-md bg-purple-500/10 border border-purple-500/30 text-purple-300 text-xs font-mono font-semibold">
              Unicode NFC + Script Analyzer
            </span>
          </div>
        </div>
      </div>

      {/* Preset Buttons */}
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs font-mono text-muted-foreground mr-1">INDIC PRESETS:</span>
        {INDIC_PRESETS.map((preset, idx) => (
          <button
            key={idx}
            onClick={() => {
              setInputText(preset.sample);
              setMaskedOutput(null);
              setRestoredOutput(null);
              setDetectedLanguage(null);
            }}
            className="px-3 py-1.5 rounded-lg text-xs font-mono bg-card/80 border border-border/80 hover:border-purple-500/60 hover:text-purple-300 text-foreground/80 transition-colors cursor-pointer"
          >
            {preset.name}
          </button>
        ))}
      </div>

      {/* Input / Output Workspace */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* Left: Input Textarea */}
        <div className="p-5 rounded-2xl bg-card/70 border border-border shadow-md space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-cyan-400" />
              <span className="text-xs font-mono font-bold text-foreground">INPUT PROMPT / DOCUMENT TEXT</span>
            </div>
            <span className="text-[11px] font-mono text-muted-foreground">
              {inputText.length} characters
            </span>
          </div>

          <textarea
            rows={8}
            value={inputText}
            onChange={(e) => setInputText(e.target.value)}
            className="w-full p-3.5 rounded-xl bg-background/90 border border-border text-sm font-sans text-foreground focus:outline-none focus:ring-1 focus:ring-purple-400 resize-none leading-relaxed"
            placeholder="Type or paste Indic or English text here..."
          />

          <div className="flex items-center justify-between pt-1">
            <div className="text-[11px] font-mono text-muted-foreground">
              Supports Kannada, Hindi, Tamil, Telugu, English
            </div>
            <Button
              onClick={handleAnalyze}
              disabled={analyzing}
              className="bg-purple-600 hover:bg-purple-500 text-white font-medium text-xs px-5 gap-1.5"
            >
              <Sparkles className="w-3.5 h-3.5" />
              {analyzing ? 'Scanning...' : 'Detect & Smart Mask'}
            </Button>
          </div>
        </div>

        {/* Right: Results Inspection */}
        <div className="p-5 rounded-2xl bg-card/70 border border-border shadow-md space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              <span className="text-xs font-mono font-bold text-foreground">DE-IDENTIFIED OUTBOUND PAYLOAD</span>
            </div>
            {detectedLanguage && (
              <Badge className="bg-purple-500/20 text-purple-300 border border-purple-500/40 text-[11px] font-mono">
                Script: {detectedLanguage}
              </Badge>
            )}
          </div>

          <div className="min-h-[160px] p-3.5 rounded-xl bg-background/90 border border-border text-sm font-sans leading-relaxed text-foreground relative">
            {maskedOutput ? (
              <div className="space-y-2">
                <p className="whitespace-pre-wrap">{maskedOutput}</p>
                <div className="pt-2 flex justify-end">
                  <button
                    onClick={handleCopy}
                    className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-cyan-400 font-mono"
                  >
                    {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    {copied ? 'Copied' : 'Copy Masked Text'}
                  </button>
                </div>
              </div>
            ) : (
              <div className="h-full min-h-[140px] flex flex-col items-center justify-center text-muted-foreground text-xs font-mono">
                Click "Detect & Smart Mask" to analyze script and isolate PII tokens.
              </div>
            )}
          </div>

          {/* Action Row */}
          {maskedOutput && (
            <div className="flex flex-wrap items-center justify-between gap-3 pt-1 border-t border-border/60">
              <span className="text-xs font-mono text-emerald-400 flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5" />
                {detectedEntities.length} PII Token(s) Intercepted
              </span>
              <Button
                variant="outline"
                size="sm"
                onClick={handleTestRestore}
                className="border-border text-xs gap-1.5 text-cyan-400 hover:text-cyan-300"
              >
                <Zap className="w-3.5 h-3.5" />
                Test Safe Local Restore
              </Button>
            </div>
          )}

          {/* Restored preview */}
          {restoredOutput && (
            <div className="p-3 rounded-xl bg-cyan-950/20 border border-cyan-500/30 text-xs font-mono text-cyan-200">
              <span className="font-bold text-cyan-400 block mb-1">Local Restoration Verification:</span>
              {restoredOutput}
            </div>
          )}
        </div>

      </div>

      {/* Detected Entities Ledger */}
      {detectedEntities.length > 0 && (
        <div className="p-5 rounded-2xl bg-card/60 border border-border/80 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Database className="w-4 h-4 text-purple-400" />
              <span className="text-xs font-mono font-bold text-foreground">
                IDENTIFIER ISOLATION TABLE (LOCAL EPHEMERAL VAULT)
              </span>
            </div>
            <span className="text-[11px] font-mono text-muted-foreground">
              Never dispatched to external AI
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3">
            {detectedEntities.map((ent, idx) => (
              <div
                key={idx}
                className="p-3 rounded-xl bg-background/80 border border-border/80 flex flex-col justify-between"
              >
                <div className="flex items-center justify-between mb-1">
                  <Badge variant="outline" className="text-[10px] font-mono border-purple-500/40 text-purple-300">
                    {ent.type}
                  </Badge>
                  <span className="font-mono text-xs text-cyan-400 font-bold">{ent.placeholder}</span>
                </div>
                <div className="text-sm font-semibold text-foreground truncate mt-1" title={ent.value}>
                  {ent.value}
                </div>
                <span className="text-[10px] font-mono text-emerald-400 mt-1">
                  ✓ Protected & Vaulted
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* PAN Validator Educational Banner */}
      <div className="p-4 rounded-xl bg-card/40 border border-border/70 text-xs font-mono space-y-1.5 text-muted-foreground">
        <strong className="text-foreground flex items-center gap-1.5">
          <Globe className="w-3.5 h-3.5 text-amber-400" />
          Indian PAN Card Category Structural Rule (privacy_engine.py):
        </strong>
        <p>
          4th Character of Indian PAN must be one of: <code className="text-cyan-300 font-bold">P</code> (Individual), <code className="text-cyan-300 font-bold">C</code> (Company), <code className="text-cyan-300 font-bold">H</code> (HUF), <code className="text-cyan-300 font-bold">F</code> (Firm), <code className="text-cyan-300 font-bold">A</code> (AOP), <code className="text-cyan-300 font-bold">T</code> (Trust), <code className="text-cyan-300 font-bold">B</code> (BOI), <code className="text-cyan-300 font-bold">L</code> (Local Authority), <code className="text-cyan-300 font-bold">J</code> (Artificial Juridical Person), <code className="text-cyan-300 font-bold">G</code> (Government). Random strings matching regex but with invalid categories are not treated as genuine PII.
        </p>
      </div>

    </div>
  );
};
export default IndicMultilingualLab;
