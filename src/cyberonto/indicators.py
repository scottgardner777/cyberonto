"""Indicator extraction, classification, defanging and normalization.

The utilities every CTI/OSINT developer ends up re-writing: pull indicators of compromise out of
free text, work out what an arbitrary string *is* (the "selector type"), make indicators safe to
share (defang) and put them back (refang), normalize them, and validate them. Pure standard library
— no runtime dependencies.

    >>> from cyberonto import extract, classify, defang
    >>> classify("8.8.8.8")
    'ipv4'
    >>> defang("http://evil.example.com/x")
    'hxxp://evil[.]example[.]com/x'
    >>> extract("c2 at 203.0.113.5 and hxxps://bad[.]site, CVE-2024-1234")["cve"]
    ['CVE-2024-1234']
"""
from __future__ import annotations

import ipaddress
import re
from typing import Dict, List, Optional

# ── indicator type constants ──────────────────────────────────────────────────
IPV4 = "ipv4"
IPV6 = "ipv6"
DOMAIN = "domain"
URL = "url"
EMAIL = "email"
MD5 = "md5"
SHA1 = "sha1"
SHA256 = "sha256"
SHA512 = "sha512"
CVE = "cve"
BTC = "btc"
ETH = "eth"
ASN = "asn"
MAC = "mac"
ATTACK_ID = "attack_id"
CWE = "cwe"
CAPEC = "capec"
USERNAME = "username"
UNKNOWN = "unknown"

HASH_TYPES = (MD5, SHA1, SHA256, SHA512)

# A domain: one or more labels, final label alphabetic (so "1.2.3.4" is never a domain).
_DOMAIN = r"(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)\.)+[a-zA-Z]{2,63}"

# Patterns used for extraction from free text. Order matters for extraction (see extract()).
_PATTERNS: Dict[str, re.Pattern] = {
    URL: re.compile(r"(?:https?|ftp)://[^\s<>\"'\]\)]+", re.IGNORECASE),
    EMAIL: re.compile(r"[a-zA-Z0-9._%+-]+@" + _DOMAIN),
    SHA512: re.compile(r"\b[a-fA-F0-9]{128}\b"),
    SHA256: re.compile(r"\b[a-fA-F0-9]{64}\b"),
    SHA1: re.compile(r"\b[a-fA-F0-9]{40}\b"),
    MD5: re.compile(r"\b[a-fA-F0-9]{32}\b"),
    ETH: re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
    IPV4: re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    IPV6: re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b"),
    CVE: re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    ATTACK_ID: re.compile(r"\bT\d{4}(?:\.\d{3})?\b"),
    CWE: re.compile(r"\bCWE-\d{1,6}\b", re.IGNORECASE),
    CAPEC: re.compile(r"\bCAPEC-\d{1,6}\b", re.IGNORECASE),
    ASN: re.compile(r"\bAS\d{1,10}\b", re.IGNORECASE),
    MAC: re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"),
    BTC: re.compile(r"\b(?:bc1[ac-hj-np-z02-9]{11,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"),
    DOMAIN: re.compile(r"\b" + _DOMAIN + r"\b"),
}

_USERNAME_RE = re.compile(r"^@?[a-zA-Z0-9][a-zA-Z0-9._-]{1,38}$")


def _domain_of(value: str) -> Optional[str]:
    m = re.search(_DOMAIN, value)
    return m.group(0) if m else None


def extract(text: str, *, refang_first: bool = True) -> Dict[str, List[str]]:
    """Extract all indicators from free text, grouped by type, de-duplicated and order-preserving.

    By default the text is refanged first, so defanged IOCs (``hxxp://evil[.]com``) are caught.
    URLs and emails are matched before bare domains, and the domains they contain are not also
    reported as standalone domains.
    """
    if refang_first:
        text = refang(text)
    found: Dict[str, List[str]] = {}
    claimed_domains = set()
    consumed_spans: List[tuple] = []

    def _overlaps(a: int, b: int) -> bool:
        return any(a < e and s < b for s, e in consumed_spans)

    for itype, pat in _PATTERNS.items():
        for m in pat.finditer(text):
            s, e = m.span()
            # a hash/ip/etc already consumed by a URL/email match is part of that URL — skip
            if itype in (DOMAIN,) and _overlaps(s, e):
                continue
            val = m.group(0)
            if itype in (URL, DOMAIN, EMAIL):
                val = val.rstrip(".,;:!?)'\"]}>")  # drop trailing sentence punctuation
            if itype == DOMAIN and val.lower() in claimed_domains:
                continue
            found.setdefault(itype, [])
            if val not in found[itype]:
                found[itype].append(val)
            if itype in (URL, EMAIL):
                consumed_spans.append((s, e))
                d = _domain_of(val)
                if d:
                    claimed_domains.add(d.lower())
    return found


def classify(value: str) -> str:
    """Return the single most specific indicator type for ``value`` (``'unknown'`` if none fits)."""
    v = value.strip()
    if not v:
        return UNKNOWN
    try:
        return IPV4 if ipaddress.ip_address(v).version == 4 else IPV6
    except ValueError:
        pass
    ordered = (CVE, ATTACK_ID, CWE, CAPEC, SHA512, SHA256, SHA1, MD5, ETH, URL,
               EMAIL, MAC, ASN, BTC, DOMAIN)
    for itype in ordered:
        if _PATTERNS[itype].fullmatch(v):
            return itype
    return UNKNOWN


def detect_selector(value: str) -> str:
    """Like :func:`classify`, but falls back to ``'username'`` for a plausible handle.

    Built for OSINT pivoting: "is this string an email, a domain, an IP, a hash — or a username?"
    """
    t = classify(value)
    if t != UNKNOWN:
        return t
    return USERNAME if _USERNAME_RE.match(value.strip()) else UNKNOWN


def validate(value: str, itype: Optional[str] = None) -> bool:
    """True if ``value`` is a well-formed indicator. If ``itype`` is given, check that exact type."""
    if itype is None:
        return classify(value) != UNKNOWN
    if itype in (IPV4, IPV6):
        try:
            ip = ipaddress.ip_address(value.strip())
            return (ip.version == 4) == (itype == IPV4)
        except ValueError:
            return False
    pat = _PATTERNS.get(itype)
    return bool(pat and pat.fullmatch(value.strip()))


# ── defang / refang ───────────────────────────────────────────────────────────
_DEFANG = [("http", "hxxp"), ("://", "[://]"), (".", "[.]"), ("@", "[@]")]


def defang(value: str) -> str:
    """Make a URL / domain / email / IP safe to paste into docs and tickets."""
    out = value
    out = re.sub(r"(?i)\bhttp", "hxxp", out)
    out = out.replace("://", "[://]").replace(".", "[.]").replace("@", "[@]")
    return out


def refang(value: str) -> str:
    """Reverse :func:`defang` (and the common variants seen in the wild)."""
    out = value
    out = out.replace("[://]", "://").replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    out = out.replace("[dot]", ".").replace("(dot)", ".").replace(" dot ", ".")
    out = out.replace("[@]", "@").replace("(at)", "@").replace("[at]", "@").replace(" at ", "@")
    out = out.replace("[:]", ":")
    out = re.sub(r"(?i)\bhxxp", "http", out)
    out = re.sub(r"(?i)\bfxp", "ftp", out)
    return out


def normalize(value: str, itype: Optional[str] = None) -> str:
    """Canonicalize an indicator (lowercase hosts and hashes, strip, refang)."""
    v = refang(value).strip()
    t = itype or classify(v)
    if t in HASH_TYPES or t in (DOMAIN, EMAIL, IPV6, MAC, ETH):
        return v.lower()
    if t == URL:
        m = re.match(r"(?i)^([a-z]+://)([^/]+)(.*)$", v)
        if m:
            return m.group(1).lower() + m.group(2).lower() + m.group(3)
    return v


# ── Pyramid of Pain (David Bianco) ─────────────────────────────────────────────
_PYRAMID = {
    MD5: "Hash Values", SHA1: "Hash Values", SHA256: "Hash Values", SHA512: "Hash Values",
    IPV4: "IP Addresses", IPV6: "IP Addresses", ASN: "IP Addresses",
    BTC: "IP Addresses", ETH: "IP Addresses",
    DOMAIN: "Domain Names", URL: "Domain Names", EMAIL: "Domain Names",
    MAC: "Host Artifacts",
    ATTACK_ID: "TTPs",
}


def pyramid_level(itype: str) -> Optional[str]:
    """The Pyramid of Pain tier for an indicator type (how painful it is for an adversary to change)."""
    return _PYRAMID.get(itype)
