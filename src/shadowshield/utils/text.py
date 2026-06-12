"""Text normalisation and decoding helpers.

Many prompt-injection evasions rely on the *rendering* of text differing from
its *bytes*: zero-width characters splitting keywords, homoglyphs, bidirectional
overrides, fullwidth Unicode, or payloads hidden in base64/hex. The detectors
operate on a normalised view produced here so a single attack can't dodge every
detector by changing its surface form.

Nothing in this module *decides* anything — it only exposes the hidden surface.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass

# Characters used to hide / split / reorder text. Stripping these collapses many
# obfuscation tricks back to their visible meaning.
INVISIBLE_CHARS = (
    "​‌‍‎‏"  # zero-width space/joiners, LRM/RLM
    "‪‫‬‭‮"  # bidirectional embeddings/overrides
    "⁠⁡⁢⁣⁤"  # word joiner / invisible operators
    "⁦⁧⁨⁩"  # isolates
    "﻿"  # BOM / zero-width no-break space
)
_INVISIBLE_RE = re.compile(f"[{re.escape(INVISIBLE_CHARS)}]")

# Homoglyph confusables -> ASCII. Small, high-value subset (Cyrillic/Greek
# look-alikes commonly used to spell "ignore", "system", etc.).
_CONFUSABLES = {
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "х": "x",
    "у": "y",
    "і": "i",
    "ѕ": "s",
    "Ѕ": "s",
    "ј": "j",
    "ԁ": "d",
    "ո": "n",
    "ⅼ": "l",
    "ɡ": "g",
    "һ": "h",
    "Α": "A",
    "Β": "B",
    "Ε": "E",
    "Ζ": "Z",
    "Η": "H",
    "Ι": "I",
    "Κ": "K",
    "Μ": "M",
    "Ν": "N",
    "Ο": "O",
    "Ρ": "P",
    "Τ": "T",
    "Υ": "Y",
    "Χ": "X",
}

# Lookarounds (not \b) so trailing '=' padding is captured — '=' is a non-word
# char, so \b after it would drop the padding and break the length check.
_B64_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])")
_HEX_RE = re.compile(r"\b(?:0x)?[0-9a-fA-F]{16,}\b")


@dataclass(slots=True)
class NormalizedText:
    """The result of :func:`normalize`.

    Attributes:
        original: The text exactly as received.
        normalized: Lower-noise view — invisibles stripped, NFKC-folded,
            confusables mapped, whitespace collapsed. Detectors match on this.
        had_invisible: Whether any invisible/bidi control chars were present
            (a signal in its own right).
        had_confusables: Whether any homoglyph substitution happened.
    """

    original: str
    normalized: str
    had_invisible: bool
    had_confusables: bool


def normalize(text: str) -> NormalizedText:
    """Produce a normalised, de-obfuscated view of ``text``.

    Order matters: strip invisibles first (so they can't survive folding), then
    NFKC-normalise (collapses fullwidth/compatibility forms), then map known
    confusables, then collapse runs of whitespace.
    """
    had_invisible = bool(_INVISIBLE_RE.search(text))
    stripped = _INVISIBLE_RE.sub("", text)

    folded = unicodedata.normalize("NFKC", stripped)

    had_confusables = any(ch in _CONFUSABLES for ch in folded)
    if had_confusables:
        folded = "".join(_CONFUSABLES.get(ch, ch) for ch in folded)

    collapsed = re.sub(r"\s+", " ", folded).strip()
    return NormalizedText(
        original=text,
        normalized=collapsed,
        had_invisible=had_invisible,
        had_confusables=had_confusables,
    )


@dataclass(slots=True)
class DecodedSegment:
    """A successfully decoded hidden segment found inside text."""

    encoding: str  # "base64" | "hex"
    source: str  # the encoded substring
    decoded: str  # the decoded, printable text
    span: tuple[int, int]


def _is_mostly_printable(data: bytes, threshold: float = 0.85) -> bool:
    if not data:
        return False
    printable = sum(1 for b in data if 0x09 <= b <= 0x7E)
    return printable / len(data) >= threshold


def extract_encoded_segments(text: str, *, min_decoded_len: int = 6) -> list[DecodedSegment]:
    """Find and decode base64/hex blobs that resolve to readable text.

    Only segments that decode to *mostly printable* ASCII are returned — random
    high-entropy strings (hashes, ids) decode to noise and are ignored, which
    keeps the false-positive rate low.
    """
    out: list[DecodedSegment] = []

    for m in _B64_RE.finditer(text):
        token = m.group(0)
        # base64 length must be a multiple of 4 to be valid
        if len(token) % 4 != 0:
            continue
        try:
            raw = base64.b64decode(token, validate=True)
        except (binascii.Error, ValueError):
            continue
        if _is_mostly_printable(raw):
            decoded = raw.decode("ascii", errors="replace")
            if len(decoded.strip()) >= min_decoded_len:
                out.append(DecodedSegment("base64", token, decoded, m.span()))

    for m in _HEX_RE.finditer(text):
        token = m.group(0).removeprefix("0x")
        if len(token) % 2 != 0:
            continue
        try:
            raw = bytes.fromhex(token)
        except ValueError:
            continue
        if _is_mostly_printable(raw):
            decoded = raw.decode("ascii", errors="replace")
            if len(decoded.strip()) >= min_decoded_len:
                out.append(DecodedSegment("hex", m.group(0), decoded, m.span()))

    return out


def truncate(text: str, limit: int = 120) -> str:
    """Shorten text for log lines without leaking the whole payload."""
    text = text.replace("\n", "\\n")
    return text if len(text) <= limit else text[: limit - 1] + "…"
