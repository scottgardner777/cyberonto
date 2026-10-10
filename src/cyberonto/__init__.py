"""cyberonto — a small, dependency-free toolkit for working with security data.

Two complementary parts:

* **indicators** — extract IOCs from text, classify an arbitrary string (the OSINT "selector type"),
  defang/refang, normalize and validate.
* **frameworks** — an offline model of the open security frameworks (ATT&CK tactics, D3FEND, the
  Cyber Kill Chain, the Diamond Model, the Pyramid of Pain, STIX 2.1, NIST CSF) and the documented
  mappings between them.

Everything is built on public standards and ships offline, with no runtime dependencies.
"""
from __future__ import annotations

from . import frameworks
from .indicators import (
    ASN, ATTACK_ID, BTC, CAPEC, CVE, CWE, DOMAIN, EMAIL, ETH, HASH_TYPES, IPV4, IPV6,
    MAC, MD5, SHA1, SHA256, SHA512, UNKNOWN, URL, USERNAME,
    classify, defang, detect_selector, extract, normalize, pyramid_level, refang, validate,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "frameworks",
    # indicators API
    "extract", "classify", "detect_selector", "defang", "refang", "normalize", "validate",
    "pyramid_level",
    # indicator type constants
    "IPV4", "IPV6", "DOMAIN", "URL", "EMAIL", "MD5", "SHA1", "SHA256", "SHA512", "CVE",
    "BTC", "ETH", "ASN", "MAC", "ATTACK_ID", "CWE", "CAPEC", "USERNAME", "UNKNOWN", "HASH_TYPES",
]
