"""
PromptWAF Input Normalization Layer — De-obfuscation engine.

Resolves adversarial text manipulation techniques:
  1. Unicode NFKC normalization (homoglyph collapse)
  2. Invisible / zero-width character stripping
  3. Embedded Base64 / Hex payload decoding
"""

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass
from typing import Optional

from app.core.config import INVISIBLE_CHARS


@dataclass(frozen=True)
class NormalizationResult:
    """Immutable result of prompt normalization."""
    original: str
    normalized: str
    deobfuscated_payloads: list  # List of (encoded_string, decoded_string) tuples

    @property
    def was_modified(self) -> bool:
        return self.original != self.normalized


# ---------------------------------------------------------------------------
# Step 1 — Unicode NFKC Normalization
# ---------------------------------------------------------------------------

def normalize_unicode(text: str) -> str:
    """
    Apply Unicode NFKC normalization to collapse homoglyphs.

    Examples:
        - Fullwidth chars:  "Ｉｇｎｏｒｅ" → "Ignore"
        - Roman numerals:   "Ⅰgnore"      → "Ignore"
        - Cyrillic 'а':     "аll"          → "all"  (when NFKC maps it)
        - Ligatures:        "ﬁnd"          → "find"
    """
    return unicodedata.normalize("NFKC", text)


# ---------------------------------------------------------------------------
# Step 2 — Strip Invisible / Zero-Width Characters
# ---------------------------------------------------------------------------

def strip_invisible(text: str) -> str:
    """
    Remove zero-width joiners, soft hyphens, BOM markers, and all
    Unicode category 'Cf' (format) characters.
    """
    result = []
    for ch in text:
        # Skip characters in our explicit deny-list
        if ch in INVISIBLE_CHARS:
            continue
        # Also strip any Unicode Format character we haven't listed
        if unicodedata.category(ch) == "Cf":
            continue
        result.append(ch)
    return "".join(result)


# ---------------------------------------------------------------------------
# Step 3 — Decode Embedded Base64 / Hex Payloads
# ---------------------------------------------------------------------------

# Match potential Base64 strings (min 20 chars, valid charset, optional padding)
_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{20,}={0,3}")

# Match potential hex strings (min 20 hex chars, optional 0x prefix)
_HEX_RE = re.compile(r"(?:0x)?([0-9a-fA-F]{20,})")


def _try_base64_decode(s: str) -> Optional[str]:
    """Attempt Base64 decode; return decoded UTF-8 text or None."""
    try:
        # Add padding if missing
        padded = s + "=" * (-len(s) % 4)
        decoded = base64.b64decode(padded, validate=True)
        text = decoded.decode("utf-8")
        # Heuristic: decoded text should be mostly printable
        if sum(c.isprintable() or c.isspace() for c in text) / max(len(text), 1) > 0.8:
            return text
    except (binascii.Error, UnicodeDecodeError, ValueError):
        pass
    return None


def _try_hex_decode(hex_str: str) -> Optional[str]:
    """Attempt hex decode; return decoded UTF-8 text or None."""
    try:
        if len(hex_str) % 2 != 0:
            return None
        decoded = bytes.fromhex(hex_str)
        text = decoded.decode("utf-8")
        if sum(c.isprintable() or c.isspace() for c in text) / max(len(text), 1) > 0.8:
            return text
    except (ValueError, UnicodeDecodeError):
        pass
    return None


def decode_embedded_payloads(text: str) -> tuple:
    """
    Scan for Base64 and hex-encoded substrings, decode them, and replace
    inline so downstream detection sees the real content.

    Returns:
        (decoded_text, [(encoded, decoded), ...])
    """
    decoded_pairs = []

    # --- Base64 ---
    def _replace_b64(match: re.Match) -> str:
        encoded = match.group(0)
        decoded = _try_base64_decode(encoded)
        if decoded:
            decoded_pairs.append((encoded, decoded))
            return decoded
        return encoded

    text = _BASE64_RE.sub(_replace_b64, text)

    # --- Hex ---
    def _replace_hex(match: re.Match) -> str:
        hex_part = match.group(1)
        decoded = _try_hex_decode(hex_part)
        if decoded:
            decoded_pairs.append((match.group(0), decoded))
            return decoded
        return match.group(0)

    text = _HEX_RE.sub(_replace_hex, text)

    return text, decoded_pairs


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def normalize_prompt(text: str) -> NormalizationResult:
    """
    Full normalization pipeline:
        1. Unicode NFKC normalization
        2. Invisible character stripping
        3. Embedded payload decoding

    Returns a NormalizationResult with original, normalized, and decoded payloads.
    """
    original = text

    # Step 1: NFKC
    text = normalize_unicode(text)

    # Step 2: Strip invisible
    text = strip_invisible(text)

    # Step 3: Decode embedded payloads
    text, decoded_payloads = decode_embedded_payloads(text)

    return NormalizationResult(
        original=original,
        normalized=text,
        deobfuscated_payloads=decoded_payloads,
    )
