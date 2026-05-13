"""Docx attack synthesis library.

Builds `.docx` files that look ordinary to a clinician but carry a
hidden adversarial instruction the AI extractor will surface to the
model. The library implements the W3_THREAT_RESEARCH §5 technique
catalogue except for the ones that need network artifacts (§5.7 OLE /
remote template), the multi-stage chain (§5.10 EchoLeak), the indexing
behavior (§5.11 RAG persistence), and the separate-codepath PDF
parallels (§5.12).

Zero runtime dependencies — `.docx` is a zip of OOXML XML parts, and
the library builds those parts from scratch. ``python-docx`` is only
used by the R5 validity test bench to confirm each generated file
parses cleanly.

Used as a building block by:

- The R5 ``indirect_injection`` category plugin (deterministic check
  looks for the canary in the target's response).
- The post-R4 specialist + ``TargetClient.upload_attack`` follow-up
  that actually fires uploads against the target.
- A future post-R4 EchoLeak-chain composer (§5.10) that combines a
  docx technique with the exfil marker protocol from R6.
"""

from cats.docx_attacks.builder import DocxAttack, build_docx
from cats.docx_attacks.techniques import (
    Technique,
    new_canary,
)

__all__ = [
    "DocxAttack",
    "Technique",
    "build_docx",
    "new_canary",
]
