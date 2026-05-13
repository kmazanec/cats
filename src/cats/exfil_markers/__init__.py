"""Exfil marker (canary) protocol.

PHI exfiltration attacks succeed when patient data crosses an authorization
boundary the platform should be enforcing. The marker protocol lets CATS
*plant* synthetic, distinctive tokens in target charts the attacker should
not be able to reach, then *detect* whether any planted marker surfaces in
a response, tool-call argument, or other channel.

The detector understands the obfuscation channels W3_THREAT_RESEARCH §2.4,
§2.5, §2.7, §2.8 catalogues: percent-encoding, base64, hex, markdown image
URLs, zero-width steganography. Plain ``in`` is insufficient.

Used as a building block by the exfil category's deterministic check and
the cross-patient probe. R6 keeps the registry in-process — R7+ may
promote it to Postgres if regression runs need durability.
"""

from cats.exfil_markers.cross_patient import (
    CrossPatientProbeResult,
    CrossPatientQuery,
    run_cross_patient_probe,
)
from cats.exfil_markers.detector import MarkerHit, detect_markers
from cats.exfil_markers.registry import (
    MarkerRecord,
    MarkerRegistry,
    get_default_registry,
)
from cats.exfil_markers.tokens import (
    MARKER_PREFIX,
    is_marker,
    new_marker,
)

__all__ = [
    "MARKER_PREFIX",
    "CrossPatientProbeResult",
    "CrossPatientQuery",
    "MarkerHit",
    "MarkerRecord",
    "MarkerRegistry",
    "detect_markers",
    "get_default_registry",
    "is_marker",
    "new_marker",
    "run_cross_patient_probe",
]
