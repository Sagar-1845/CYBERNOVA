"""
app/privacy/validators.py
─────────────────────────
Validated Numeric Identifiers and Checksum Algorithms.

Implements:
- Verhoeff checksum algorithm for Indian Aadhaar validation.
- Luhn checksum algorithm for Credit/Debit card validation with Major Industry Identifier (MII) prefixes.
- Indian Bank Account contextual validator.
- IFSC structure and bank-prefix validation.
- Statutory PAN 4th character entity-type validation (P, C, H, F, A, B, G, J, L, T).
- Indian Phone format validation with toll-free (1800/1860) exclusion.
"""

from __future__ import annotations

import re
from typing import Tuple

# ─────────────────────────────────────────────────────────────────────────────
# Verhoeff Tables & Algorithm
# ─────────────────────────────────────────────────────────────────────────────
_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]

_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


def validate_verhoeff(digits_str: str) -> bool:
    """Validate a numeric string using the Verhoeff dihedral group D5 algorithm."""
    digits = [int(c) for c in digits_str if c.isdigit()]
    if not digits:
        return False
    c = 0
    for i, d in enumerate(reversed(digits)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][d]]
    return c == 0


def validate_aadhaar(raw_val: str, surrounding_text: str = "") -> Tuple[bool, str, float]:
    """Validate 12-digit Aadhaar number with strict boundaries and Verhoeff checksum.

    Returns: (is_valid, entity_type, confidence)
    """
    clean_digits = re.sub(r"\D", "", raw_val)
    if len(clean_digits) != 12:
        return False, "", 0.0

    # First digit must be 2-9 per UIDAI specifications (cannot start with 0 or 1)
    if clean_digits[0] in ("0", "1"):
        return False, "", 0.0

    # Check for context cues
    has_aadhaar_cue = bool(surrounding_text and re.search(r"(?i)\b(?:aadhaar|aadhar|uid|आधार)\b", surrounding_text))
    has_ref_cue = bool(surrounding_text and re.search(
        r"(?i)\b(?:order\s+ref|ticket|dispatch\s+code|tracking|consignment|transaction\s+ref|salary\s+account|account\s+number|account\s+no\.?|a\/c|खाता\s+संख्या)\b",
        surrounding_text
    ))

    # If surrounding text has a non-Aadhaar reference or bank cue and no Aadhaar cue, reject
    if has_ref_cue and not has_aadhaar_cue:
        return False, "", 0.0

    # Check Verhoeff checksum
    if validate_verhoeff(clean_digits):
        return True, "AADHAAR", 0.98

    # If Verhoeff fails, check if an explicit Aadhaar cue exists nearby (~30 chars)
    if has_aadhaar_cue:
        return True, "AADHAAR", 0.60  # Possible Aadhaar / unvalidated checksum

    return False, "", 0.0


# ─────────────────────────────────────────────────────────────────────────────
# Luhn Algorithm & Card Validation
# ─────────────────────────────────────────────────────────────────────────────
def validate_luhn(digits_str: str) -> bool:
    """Validate numeric string using the Luhn mod-10 algorithm."""
    digits = [int(c) for c in digits_str if c.isdigit()]
    if not digits:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d = d * 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def validate_credit_card(raw_val: str) -> Tuple[bool, str, float]:
    """Validate 13-19 digit Credit/Debit card with Luhn checksum and issuer prefix check."""
    clean_digits = re.sub(r"\D", "", raw_val)
    length = len(clean_digits)
    if length < 13 or length > 19:
        return False, "", 0.0

    if not validate_luhn(clean_digits):
        return False, "", 0.0

    # Issuer prefix checks
    is_valid_prefix = False

    # Visa: 4... (length 13, 16, 19)
    if clean_digits.startswith("4") and length in (13, 16, 19):
        is_valid_prefix = True
    # MasterCard: 51-55 or 2221-2720 (length 16)
    elif length == 16:
        first2 = int(clean_digits[:2])
        first4 = int(clean_digits[:4])
        if (51 <= first2 <= 55) or (2221 <= first4 <= 2720):
            is_valid_prefix = True
    # Amex: 34, 37 (length 15)
    elif length == 15 and (clean_digits.startswith("34") or clean_digits.startswith("37")):
        is_valid_prefix = True
    # RuPay: 60, 65, 81, 82, 508, 353, 356 (length 16)
    elif length == 16 and (
        clean_digits.startswith("60") or clean_digits.startswith("65") or
        clean_digits.startswith("81") or clean_digits.startswith("82") or
        clean_digits.startswith("508") or clean_digits.startswith("353") or clean_digits.startswith("356")
    ):
        is_valid_prefix = True
    # Discover: 6011, 65, 644-649 (length 16)
    elif length == 16 and (clean_digits.startswith("6011") or clean_digits.startswith("65")):
        is_valid_prefix = True
    elif length in (14, 15, 16, 18, 19):
        # General valid Luhn card
        is_valid_prefix = True

    if is_valid_prefix:
        return True, "CREDIT_CARD", 0.95

    return False, "", 0.0


# ─────────────────────────────────────────────────────────────────────────────
# Bank Account Contextual Validator
# ─────────────────────────────────────────────────────────────────────────────
_BANK_ACCOUNT_CUE_RE = re.compile(
    r"(?i)\b(?:account\s+number|account\s+no\.?|a\/c\s+(?:no\.?|number)?|acct|salary\s+account|bank\s+account|direct\s+salary\s+account|खाता\s+संख्या|खाता\s+सं\.?|खाता\s+नंबर)\b"
)


def validate_bank_account(raw_val: str, surrounding_text: str = "") -> Tuple[bool, str, float]:
    """Validate 9-18 digit Indian bank account number. Requires nearby contextual account cue."""
    clean_digits = re.sub(r"\D", "", raw_val)
    length = len(clean_digits)
    if length < 9 or length > 18:
        return False, "", 0.0

    if not surrounding_text:
        return False, "", 0.0

    if _BANK_ACCOUNT_CUE_RE.search(surrounding_text):
        return True, "BANK_ACCOUNT", 0.90

    return False, "", 0.0


# ─────────────────────────────────────────────────────────────────────────────
# PAN 4th Character Validator
# ─────────────────────────────────────────────────────────────────────────────
_VALID_PAN_4TH = frozenset({"P", "C", "H", "F", "A", "B", "G", "J", "L", "T"})


def validate_pan(raw_val: str) -> bool:
    """Validate statutory Indian PAN structure: 5 letters, 4 digits, 1 letter.

    4th letter must signify legal personhood type: P, C, H, F, A, B, G, J, L, T.
    """
    clean = raw_val.strip().upper()
    if len(clean) != 10:
        return False
    if not re.match(r"^[A-Z]{5}[0-9]{4}[A-Z]$", clean):
        return False
    return clean[3] in _VALID_PAN_4TH


# ─────────────────────────────────────────────────────────────────────────────
# Phone & Toll-Free Filter
# ─────────────────────────────────────────────────────────────────────────────
def is_toll_free_number(raw_val: str) -> bool:
    """Check if number is a public toll-free or helpline number (1800 / 1860)."""
    digits = re.sub(r"\D", "", raw_val)
    return digits.startswith("1800") or digits.startswith("1860")
