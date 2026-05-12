"""Deterministic scanner. Catches real-looking PII, executable payload
signatures, and the adversarial-output channels documented in
W3_THREAT_RESEARCH (§5.3 zero-width, §5.4 homoglyphs, §2.7 NFKC).
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

# Common PII patterns (US SSN, credit-card, MRN-shaped digit runs).
SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
CC_PATTERN = re.compile(r"\b(?:\d[ -]?){13,19}\b")
MRN_PATTERN = re.compile(r"\bMRN[-:]?\s?\d{6,10}\b", re.IGNORECASE)

# Executable payload signatures.
BASE64_ELF_PATTERN = re.compile(r"\bf0VMRg\w+", re.IGNORECASE)  # base64 of ELF magic
POWERSHELL_DOWNLOAD = re.compile(
    r"(?:powershell|pwsh).{0,40}(?:DownloadString|Invoke-WebRequest)",
    re.IGNORECASE,
)

# Zero-width and bidi/format characters used to smuggle adversarial content.
ZERO_WIDTH_CHARS = re.compile(r"[​-‏‪-‮﻿]")


@dataclass(frozen=True)
class RegexScanResult:
    verdict: str  # "safe" | "attack_payload" | "dangerous"
    reason: str
    normalized: str


def scan_text(text: str) -> RegexScanResult:
    """Scan a string. The default verdict is `safe`; `dangerous` is reserved
    for content that must be quarantined regardless of context (real PII,
    executable payloads). `attack_payload` is reserved for things the
    LLM-classifier layer (TODO) can promote to."""
    normalized = unicodedata.normalize("NFKC", text)
    normalized = ZERO_WIDTH_CHARS.sub("", normalized)

    if SSN_PATTERN.search(normalized):
        return RegexScanResult("dangerous", "ssn_match", normalized)
    if MRN_PATTERN.search(normalized):
        return RegexScanResult("dangerous", "mrn_match", normalized)
    if CC_PATTERN.search(normalized):
        return RegexScanResult("dangerous", "credit_card_match", normalized)
    if BASE64_ELF_PATTERN.search(normalized):
        return RegexScanResult("dangerous", "base64_elf_signature", normalized)
    if POWERSHELL_DOWNLOAD.search(normalized):
        return RegexScanResult("dangerous", "powershell_download_cradle", normalized)

    return RegexScanResult("safe", "", normalized)
