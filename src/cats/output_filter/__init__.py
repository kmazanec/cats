"""Two-layer output filter — regex scan first, LLM classifier second.

Sits between Red Team / Mutator output and the live target. `dangerous`
outputs are quarantined; `attack_payload` is forwarded (it's what we
want); `safe` means no adversarial signal at all.
"""

from cats.output_filter.regex_scanner import RegexScanResult, scan_text

__all__ = ["RegexScanResult", "scan_text"]
