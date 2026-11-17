"""
app/privacy/detector.py
───────────────────────
ZeroLeak AI — PII Detection Engine (Stage A + B)
─────────────────────────────────────────────────
Detects sensitive PII and financial entities using validated numeric algorithms,
contextual cue extractors, and strict boundary rules.

Supported entity types:
  AADHAAR, PAN, GSTIN, PASSPORT, VOTER_ID, PHONE, EMAIL,
  NAME, ADDRESS, DATE_OF_BIRTH, CREDIT_CARD, BANK_ACCOUNT, IFSC, FINANCIAL
"""

from __future__ import annotations

import re
import logging
from dataclasses import dataclass
from typing import List, Tuple, Optional

from app.privacy.validators import (
    validate_verhoeff,
    validate_aadhaar,
    validate_luhn,
    validate_credit_card,
    validate_bank_account,
    validate_pan,
    is_toll_free_number,
)

logger = logging.getLogger(__name__)

class EntityType:
    AADHAAR       = "AADHAAR"
    PAN           = "PAN"
    GSTIN         = "GSTIN"
    PASSPORT      = "PASSPORT"
    VOTER_ID      = "VOTER_ID"
    PHONE         = "PHONE"
    EMAIL         = "EMAIL"
    NAME          = "NAME"
    ADDRESS       = "ADDRESS"
    DATE_OF_BIRTH = "DATE_OF_BIRTH"
    CREDIT_CARD   = "CREDIT_CARD"
    BANK_ACCOUNT  = "BANK_ACCOUNT"
    IFSC          = "IFSC"
    FINANCIAL     = "FINANCIAL"


@dataclass
class DetectedEntity:
    entity_type: str
    value: str
    start: int
    end: int
    confidence: float = 1.0
    validated: bool = False


ALWAYS_MASK: frozenset[str] = frozenset({
    EntityType.AADHAAR,
    EntityType.PAN,
    EntityType.GSTIN,
    EntityType.PASSPORT,
    EntityType.VOTER_ID,
    EntityType.CREDIT_CARD,
    EntityType.BANK_ACCOUNT,
    EntityType.NAME,
    EntityType.FINANCIAL,
    EntityType.IFSC,
})

# ─────────────────────────────────────────────────────────────────────────────
# Stopwords & Dictionary Filters for Person Extraction
# ─────────────────────────────────────────────────────────────────────────────
_STOPWORDS = frozenset({
    "is", "are", "was", "were", "be", "been", "being", "have", "has", "had", "do", "does", "did",
    "will", "would", "shall", "should", "can", "could", "may", "might", "must",
    "a", "an", "the", "and", "or", "but", "if", "because", "as", "until", "while",
    "of", "at", "by", "for", "with", "about", "between", "into", "through", "during",
    "before", "after", "to", "from", "in", "out", "on", "off", "over", "under",
    "then", "once", "here", "there", "when", "where", "why", "how",
    "all", "any", "both", "each", "few", "more", "most", "other", "some", "such",
    "no", "nor", "not", "only", "own", "same", "so", "than", "too", "very", "just", "now",
    "she", "he", "they", "them", "her", "his", "it", "its", "we", "us", "our",
    "support", "notes", "details", "database", "portal", "care", "service", "services",
    "record", "records", "status", "profile", "form", "forms", "information", "data",
    "history", "list", "user", "users", "client", "clients", "request", "requests",
    "report", "reports", "invoice", "invoices", "help", "team", "center", "centre",
    "desk", "account", "accounts", "query", "queries", "terms", "conditions", "id",
    "number", "verification", "verified", "available", "attached", "review", "sanction",
    "document", "documents", "wants", "wanted", "requires", "required", "apply", "applies",
    "eligible", "eligibility", "sent", "wishes", "told", "said", "asked", "approved",
    "database", "portal", "system", "cibil", "score", "utility", "bill", "deed",
    "pan", "aadhaar", "gstin", "passport", "voter", "card", "redacted", "credit", "debit", "bank"
})

_HINDI_STOPWORDS = frozenset({
    "है", "हैं", "था", "थी", "थे", "होगा", "होगी", "होंगे",
    "का", "की", "के", "को", "में", "से", "पर", "और", "या", "लेकिन", "अगर", "तो",
    "चाहता", "चाहती", "चाहते", "लागू", "विवरण", "सहायता", "स्थिति", "ऋण", "खाता",
    "दस्तावेज़", "आईडी", "उपलब्ध", "संलग्न", "ने", "आयु", "सूची", "इतिहास", "सेवा", "सेवाएँ",
    "फ़ाइल", "फाइल", "आज", "मदद", "रिकॉर्ड", "फॉर्म", "जांच", "डेटाबेस"
})

_PERSON_CUE_RE = re.compile(
    r"(?i)(?:\b(?:borrower|applicant|customer|patient|account\s+holder|father['’]?s\s+name|guarantor|officer|name|mr\.?|mrs\.?|ms\.?|shri|smt\.?|dr\.?)\b|"
    r"(?:उधारकर्ता|आवेदक|ग्राहक|मरीज़|मरीज|रोगी|नाम|खाता\s+धारक|पिता\s+का\s+नाम|श्री|श्रीमती|डॉक्टर|डाॅ\.?)(?=[\s:=-]|$))",
    re.UNICODE,
)

_WORD_TOKEN_RE = re.compile(r"([a-zA-Z\u0900-\u0963\u0970-\u097F]+)", re.UNICODE)

# ─────────────────────────────────────────────────────────────────────────────
# Regex Patterns
# ─────────────────────────────────────────────────────────────────────────────
_CARD_CANDIDATE_RE = re.compile(r"\b(?:\d[ -]?){12,18}\d\b")
_BANK_ACCOUNT_RE = re.compile(r"\b\d{9,18}\b")
# Aadhaar boundary: cannot be preceded or followed by digits or spaced digit groups
_AADHAAR_CANDIDATE_RE = re.compile(r"(?<!\d)(?<!\d\s)(?<!\d-)(?:\d{4}[ -]\d{4}[ -]\d{4}|\d{12})(?![\s-]?\d)")
_PAN_CANDIDATE_RE = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")
_IFSC_RE = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")
_PHONE_RE = re.compile(r"(?<!\d)(?:(?:\+?91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}|(?:\+?91[\s-]?)?[6-9]\d{9})(?!\d)")
_GSTIN_RE = re.compile(r"\b\d{2}[A-Z]{5}\d{4}[A-Z]\d[Z][A-Z0-9]\b")
_PASSPORT_RE = re.compile(r"(?i)(?:(?:foreign\s+)?passport(?:\s+no\.?|\s+number)?[:\s]+)?\b([A-Za-z][1-9]\d{6})\b")
_VOTER_ID_RE = re.compile(r"\b[A-Z]{3}[0-9]{7}\b")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")

# Contextual Financial Amount: Group 1 captures ONLY the amount
_FINANCIAL_CUE_RE = re.compile(
    r"(?i)(?:(?:gross\s+annual\s+income|annual\s+income|reported\s+annual\s+salary|monthly\s+income|gross\s+salary|net\s+salary|net\s+pay|ctc|salary|income|loan(?:\s+(?:amount|requirement|request|sanction))?|gross|वार्षिक\s+आय|मासिक\s+आय|सकल\s+आय|वेतन|आय|ऋण\s+राशि|ऋण)(?:\s*[:=-]|\s+is|\s+of|\s+was)?[\s:=-]+)"
    r"((?:(?:INR|Rs\.?|₹)\s*)?(?:\d{1,3}(?:,\d{2})+,\d{3}|\d{1,3}(?:,\d{3})+(?:,\d{3})*|\d{4,10})(?:\.\d{1,2})?(?!\d)(?:\s*(?:lakh|crore|lakhs|crores|लाख|करोड़))?)",
    re.UNICODE
)

_DOB_CUE_RE = re.compile(
    r"(?i)(?:(?:date\s+of\s+birth|dob|birth\s+date|born\s+on|जन्म\s+तिथि|जन्म\s+दिनांक)(?:\s*[:=-]|\s+is|\s+was)?[\s:=-]+)"
    r"((?:0?[1-9]|[12]\d|3[01])[\/\-\.](?:0?[1-9]|1[0-2])[\/\-\.](?:19|20)\d{2})",
    re.UNICODE
)

_ADDRESS_RE = re.compile(
    r"(?:(?:Flat|Apartment|Plot|Door|House|H\.No|No\.)\s*[\#\-]?\s*\d+[A-Za-z]?[,\s]+)?"
    r"(?:[A-Za-z0-9\s\,\.\-]+(?:Road|Street|Lane|Nagar|Colony|Layout|Extension|Phase|Sector|Block|Village|Town|District|Taluk|Mandal|State|Pin|Pincode)\b[A-Za-z0-9\s\,\.\-]{0,80})",
    re.UNICODE
)


def detect_pii(text: str) -> List[DetectedEntity]:
    """
    Detect PII entities in the given text with rigorous numeric checksum validation,
    contextual cues, and overlap resolution.
    """
    if not text or not text.strip():
        return []

    candidates: List[DetectedEntity] = []

    # 1. CREDIT / DEBIT CARDS (Luhn Checksum + MII prefix check) - Run BEFORE Aadhaar
    for m in _CARD_CANDIDATE_RE.finditer(text):
        raw_val = m.group(0)
        is_valid, etype, conf = validate_credit_card(raw_val)
        if is_valid:
            candidates.append(DetectedEntity(
                entity_type=EntityType.CREDIT_CARD,
                value=raw_val,
                start=m.start(),
                end=m.end(),
                confidence=conf,
                validated=True,
            ))

    # 2. BANK ACCOUNTS (Contextual Cue + 9-18 digits)
    bank_spans: set[tuple[int, int]] = set()
    for m in _BANK_ACCOUNT_RE.finditer(text):
        raw_val = m.group(0)
        ctx_start = max(0, m.start() - 40)
        ctx_end = min(len(text), m.end() + 20)
        surrounding = text[ctx_start:ctx_end]
        is_valid, etype, conf = validate_bank_account(raw_val, surrounding)
        if is_valid:
            candidates.append(DetectedEntity(
                entity_type=EntityType.BANK_ACCOUNT,
                value=raw_val,
                start=m.start(),
                end=m.end(),
                confidence=conf,
                validated=True,
            ))
            bank_spans.add((m.start(), m.end()))

    # 3. AADHAAR (12 digits, first digit 2-9, Verhoeff checksum)
    for m in _AADHAAR_CANDIDATE_RE.finditer(text):
        raw_val = m.group(0)
        # If this exact span was already identified as a contextual bank account, skip
        if (m.start(), m.end()) in bank_spans:
            continue
        ctx_start = max(0, m.start() - 35)
        ctx_end = min(len(text), m.end() + 20)
        surrounding = text[ctx_start:ctx_end]
        is_valid, etype, conf = validate_aadhaar(raw_val, surrounding)
        if is_valid:
            clean_digits = re.sub(r"\D", "", raw_val)
            has_verhoeff = validate_verhoeff(clean_digits)
            candidates.append(DetectedEntity(
                entity_type=EntityType.AADHAAR,
                value=raw_val,
                start=m.start(),
                end=m.end(),
                confidence=conf,
                validated=has_verhoeff,
            ))

    # 4. PAN (Statutory 4th character entity-type validation)
    for m in _PAN_CANDIDATE_RE.finditer(text):
        raw_val = m.group(0)
        if validate_pan(raw_val):
            candidates.append(DetectedEntity(
                entity_type=EntityType.PAN,
                value=raw_val,
                start=m.start(),
                end=m.end(),
                confidence=0.98,
                validated=True,
            ))

    # 5. IFSC Code
    for m in _IFSC_RE.finditer(text):
        candidates.append(DetectedEntity(
            entity_type=EntityType.IFSC,
            value=m.group(0),
            start=m.start(),
            end=m.end(),
            confidence=0.95,
            validated=True,
        ))

    # 6. PHONE (Indian Mobile with strict boundaries, excluding toll-free 1800/1860)
    for m in _PHONE_RE.finditer(text):
        raw_val = m.group(0)
        if not is_toll_free_number(raw_val):
            candidates.append(DetectedEntity(
                entity_type=EntityType.PHONE,
                value=raw_val,
                start=m.start(),
                end=m.end(),
                confidence=0.92,
                validated=True,
            ))

    # 7. GSTIN
    for m in _GSTIN_RE.finditer(text):
        candidates.append(DetectedEntity(
            entity_type=EntityType.GSTIN,
            value=m.group(0),
            start=m.start(),
            end=m.end(),
            confidence=0.95,
            validated=True,
        ))

    # 8. PASSPORT
    for m in _PASSPORT_RE.finditer(text):
        val = m.group(1) if m.lastindex and m.group(1) else m.group(0)
        s = m.start(1) if m.lastindex and m.group(1) else m.start(0)
        e = m.end(1) if m.lastindex and m.group(1) else m.end(0)
        candidates.append(DetectedEntity(
            entity_type=EntityType.PASSPORT,
            value=val,
            start=s,
            end=e,
            confidence=0.92,
            validated=True,
        ))

    # 9. VOTER ID
    for m in _VOTER_ID_RE.finditer(text):
        candidates.append(DetectedEntity(
            entity_type=EntityType.VOTER_ID,
            value=m.group(0),
            start=m.start(),
            end=m.end(),
            confidence=0.88,
            validated=True,
        ))

    # 10. EMAIL
    for m in _EMAIL_RE.finditer(text):
        candidates.append(DetectedEntity(
            entity_type=EntityType.EMAIL,
            value=m.group(0),
            start=m.start(),
            end=m.end(),
            confidence=0.98,
            validated=True,
        ))

    # 11. FINANCIAL AMOUNTS (Contextual Cues, Group 1 only)
    for m in _FINANCIAL_CUE_RE.finditer(text):
        if m.lastindex and m.group(1):
            candidates.append(DetectedEntity(
                entity_type=EntityType.FINANCIAL,
                value=m.group(1),
                start=m.start(1),
                end=m.end(1),
                confidence=0.95,
                validated=True,
            ))

    # 12. CONTEXTUAL PERSON NAMES (Latin & Devanagari cue extractors)
    for cue_m in _PERSON_CUE_RE.finditer(text):
        cue_end = cue_m.end()
        remainder = text[cue_end:]
        sep_m = re.match(r"^(?:\s+(?:is|was|named|called|of))?[\s:=-]+", remainder)
        if not sep_m:
            continue
        after_sep = cue_end + sep_m.end()
        cand = text[after_sep:]
        tokens: list[tuple[str, int, int]] = []
        last_end = 0
        for wm in _WORD_TOKEN_RE.finditer(cand):
            inter = cand[last_end:wm.start()]
            if tokens and re.search(r"[()[\]{},;.!?:\/\-]", inter):
                break
            w = wm.group(1)
            # Latin tokens must be capitalized
            if w.isascii() and not w[0].isupper():
                break
            if w.lower() in _STOPWORDS or w in _HINDI_STOPWORDS:
                break
            tokens.append((w, after_sep + wm.start(), after_sep + wm.end()))
            last_end = wm.end()
            if len(tokens) == 3:
                break
        if tokens:
            name_start = tokens[0][1]
            name_end = tokens[-1][2]
            candidates.append(DetectedEntity(
                entity_type=EntityType.NAME,
                value=text[name_start:name_end],
                start=name_start,
                end=name_end,
                confidence=0.92,
                validated=True,
            ))

    # 13. DATE OF BIRTH (Contextual DOB with explicit cues only)
    for m in _DOB_CUE_RE.finditer(text):
        if m.lastindex and m.group(1):
            candidates.append(DetectedEntity(
                entity_type=EntityType.DATE_OF_BIRTH,
                value=m.group(1),
                start=m.start(1),
                end=m.end(1),
                confidence=0.90,
                validated=True,
            ))

    # 14. ADDRESS (Heuristic)
    for m in _ADDRESS_RE.finditer(text):
        candidates.append(DetectedEntity(
            entity_type=EntityType.ADDRESS,
            value=m.group(0),
            start=m.start(),
            end=m.end(),
            confidence=0.70,
            validated=False,
        ))

    # 15. RESOLVE OVERLAPPING ENTITIES
    # Priority:
    # 1. Earliest start position
    # 2. Validated (True before False)
    # 3. Longer span length descending
    # 4. Contextual bank accounts take priority over un-cued aadhaar
    # 5. Higher confidence descending
    def sort_key(e: DetectedEntity):
        # Type priority: BANK_ACCOUNT (if validated) > AADHAAR
        type_prio = 0
        if e.entity_type == EntityType.BANK_ACCOUNT:
            type_prio = -2
        elif e.entity_type == EntityType.CREDIT_CARD:
            type_prio = -3
        elif e.validated:
            type_prio = -1

        return (e.start, type_prio, -(e.end - e.start), -e.confidence)

    candidates.sort(key=sort_key)

    resolved: List[DetectedEntity] = []
    for cand in candidates:
        overlap = False
        for accepted in resolved:
            if not (cand.end <= accepted.start or cand.start >= accepted.end):
                overlap = True
                break
        if not overlap:
            resolved.append(cand)

    resolved.sort(key=lambda e: e.start)
    logger.debug("Detected %d PII entities", len(resolved))
    return resolved
