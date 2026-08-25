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

from app.core.config import INVISIBLE_CHARS, MAX_NORMALIZATION_DEPTH, ENABLE_NORMALIZATION

# Match potential Base64 strings (min 4 chars to match test cases, valid charset, optional padding)
_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{4,}={0,3}")

# Match potential hex strings (min 8 hex chars to match test cases, optional 0x prefix)
_HEX_RE = re.compile(r"(?:0x)?([0-9a-fA-F]{8,})")


@dataclass(frozen=True)
class NormalizationResult:
    """Immutable result of prompt normalization."""
    original_text: str
    normalized_text: str
    decoded_base64: bool
    decoded_hex: bool
    zero_width_removed: bool
    normalization_depth: int

    @property
    def was_modified(self) -> bool:
        return self.original_text != self.normalized_text


class Normalizer:
    """Class-based normalizer engine for de-obfuscating payloads."""

    def __init__(self, max_depth: int = MAX_NORMALIZATION_DEPTH, enabled: bool = ENABLE_NORMALIZATION):
        self.max_depth = max_depth
        self.enabled = enabled
        self.decoded_base64 = False
        self.decoded_hex = False
        self.zero_width_removed = False
        self.normalization_depth = 0

    def _normalize_unicode(self, text: str) -> str:
        """Apply Unicode NFKC normalization to collapse homoglyphs."""
        text = unicodedata.normalize("NFKC", text)
        
        # NFKC handles fullwidth and ligatures, but cross-script homoglyphs 
        # (like Cyrillic 'і' U+0456) require manual mapping
        homoglyph_map = {
            '\u0456': 'i',  # Cyrillic i
            '\u0430': 'a',  # Cyrillic a
            '\u0435': 'e',  # Cyrillic e
            '\u043E': 'o',  # Cyrillic o
            '\u0441': 'c',  # Cyrillic c
            '\u0440': 'p',  # Cyrillic p
            '\u0445': 'x',  # Cyrillic x
            '\u0443': 'y',  # Cyrillic y
        }
        for k, v in homoglyph_map.items():
            text = text.replace(k, v)
            
        return text

    def _strip_zero_width(self, text: str) -> str:
        """Remove invisible characters (zero-width, format chars, etc)."""
        result = []
        for ch in text:
            if ch in INVISIBLE_CHARS:
                continue
            if unicodedata.category(ch) == "Cf":
                continue
            result.append(ch)
        return "".join(result)

    def _decode_base64(self, text: str) -> Optional[str]:
        """Detect and decode Base64 strings."""
        try:
            # Add padding if missing
            padded = text + "=" * (-len(text) % 4)
            decoded = base64.b64decode(padded, validate=True)
            decoded_text = decoded.decode("utf-8")
            # Ensure it's mostly printable to avoid false positives
            if sum(c.isprintable() or c.isspace() for c in decoded_text) / max(len(decoded_text), 1) > 0.8:
                return decoded_text
        except (binascii.Error, UnicodeDecodeError, ValueError):
            pass
        return None

    def _decode_hex(self, text: str) -> Optional[str]:
        """Detect and decode hex strings."""
        try:
            if text.startswith("0x") or text.startswith("0X"):
                text = text[2:]
            if len(text) % 2 != 0:
                return None
            decoded = bytes.fromhex(text)
            decoded_text = decoded.decode("utf-8")
            if sum(c.isprintable() or c.isspace() for c in decoded_text) / max(len(decoded_text), 1) > 0.8:
                return decoded_text
        except (ValueError, UnicodeDecodeError):
            pass
        return None

    def _normalize_recursive(self, text: str, max_depth: int = 3) -> str:
        """Handle nested obfuscation iteratively up to max_depth."""
        for depth in range(max_depth):
            self.normalization_depth = depth + 1
            original_iteration_text = text
            
            # 1. NFKC
            text = self._normalize_unicode(text)
            
            # 2. Zero-width
            new_text = self._strip_zero_width(text)
            if new_text != text:
                self.zero_width_removed = True
                text = new_text
            
            changed_in_iteration = (text != original_iteration_text)

            # 3. Base64 Replacement
            def replace_b64(match: re.Match) -> str:
                nonlocal changed_in_iteration
                encoded = match.group(0)
                decoded = self._decode_base64(encoded)
                if decoded and decoded != encoded:
                    self.decoded_base64 = True
                    changed_in_iteration = True
                    return decoded
                return encoded

            text = _BASE64_RE.sub(replace_b64, text)

            # 4. Hex Replacement
            def replace_hex(match: re.Match) -> str:
                nonlocal changed_in_iteration
                encoded = match.group(0)
                decoded = self._decode_hex(encoded)
                if decoded and decoded != encoded:
                    self.decoded_hex = True
                    changed_in_iteration = True
                    return decoded
                return encoded

            text = _HEX_RE.sub(replace_hex, text)

            if not changed_in_iteration:
                break
                
        return text

    def normalize(self, text: str) -> str:
        """Main entry point for de-obfuscating a text payload."""
        if not self.enabled:
            return text
            
        return self._normalize_recursive(text, max_depth=self.max_depth)


# ---------------------------------------------------------------------------
# Backward Compatibility Wrappers
# ---------------------------------------------------------------------------

def normalize_prompt(text: str) -> NormalizationResult:
    """
    Wrapper for backward compatibility with existing codebase components.
    Instantiates Normalizer and returns a NormalizationResult.
    """
    normalizer = Normalizer()
    normalized_text = normalizer.normalize(text)
    
    return NormalizationResult(
        original_text=text,
        normalized_text=normalized_text,
        decoded_base64=normalizer.decoded_base64,
        decoded_hex=normalizer.decoded_hex,
        zero_width_removed=normalizer.zero_width_removed,
        normalization_depth=normalizer.normalization_depth,
    )
