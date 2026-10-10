"""A lightweight, offline model of the OPEN security frameworks and the documented mappings between
them — the "cyber ontology" layer.

Built only on public standards: MITRE ATT&CK (tactics), MITRE D3FEND, the Lockheed Martin Cyber Kill
Chain, the Diamond Model, David Bianco's Pyramid of Pain, OASIS STIX 2.1, and the NIST CSF. The full
technique / CWE / CAPEC catalogs are intentionally *not* bundled (they change often and are large);
what ships here are the stable enumerations and the cross-walks developers actually need offline.

    >>> from cyberonto import frameworks as fw
    >>> fw.kill_chain_to_attack("Delivery")
    [{'id': 'TA0001', 'name': 'Initial Access'}]
    >>> fw.tactic("TA0003")["name"]
    'Persistence'
    >>> [t["name"] for t in fw.pyramid()][:2]
    ['Hash Values', 'IP Addresses']
"""
from __future__ import annotations

import json
from functools import lru_cache
from typing import Dict, List, Optional

try:  # py3.9+: importlib.resources.files
    from importlib.resources import files as _files

    def _load() -> dict:
        return json.loads((_files("cyberonto.data") / "frameworks.json").read_text("utf-8"))
except Exception:  # pragma: no cover - very old importlib
    import os

    def _load() -> dict:
        here = os.path.join(os.path.dirname(__file__), "data", "frameworks.json")
        with open(here, encoding="utf-8") as fh:
            return json.load(fh)


@lru_cache(maxsize=1)
def _data() -> dict:
    return _load()


# ── ATT&CK tactics ─────────────────────────────────────────────────────────────
def tactics() -> List[Dict[str, str]]:
    """All 14 MITRE ATT&CK Enterprise tactics, in kill-chain order."""
    return list(_data()["attack_tactics"])


def tactic(id_or_name: str) -> Optional[Dict[str, str]]:
    """Look up a tactic by ID (``TA0003``) or name (case-insensitive, ``persistence``)."""
    q = id_or_name.strip().lower()
    for t in _data()["attack_tactics"]:
        if t["id"].lower() == q or t["name"].lower() == q:
            return dict(t)
    return None


# ── Cyber Kill Chain ───────────────────────────────────────────────────────────
def kill_chain() -> List[Dict]:
    """The 7 Lockheed Martin Cyber Kill Chain phases, in order."""
    return list(_data()["kill_chain"])


def kill_chain_to_attack(phase: str) -> List[Dict[str, str]]:
    """The ATT&CK tactic(s) a kill-chain phase maps to (a phase can map to several)."""
    ids = _data()["kill_chain_to_attack"].get(_canon_phase(phase), [])
    return [t for t in (tactic(i) for i in ids) if t]


def attack_to_kill_chain(tactic_id_or_name: str) -> List[str]:
    """The kill-chain phase(s) an ATT&CK tactic appears in."""
    t = tactic(tactic_id_or_name)
    if not t:
        return []
    return [phase for phase, ids in _data()["kill_chain_to_attack"].items() if t["id"] in ids]


def _canon_phase(phase: str) -> str:
    q = phase.strip().lower().replace("c2", "command & control").replace(" and ", " & ")
    for p in _data()["kill_chain"]:
        if p["name"].lower() == q:
            return p["name"]
    return phase


# ── Other models ───────────────────────────────────────────────────────────────
def diamond() -> List[Dict[str, str]]:
    """The four core features (vertices) of the Diamond Model."""
    return list(_data()["diamond"])


def pyramid() -> List[Dict]:
    """The Pyramid of Pain tiers, bottom (trivial) to top (tough)."""
    return list(_data()["pyramid_of_pain"])


def stix_types(kind: str = "all") -> List[str]:
    """STIX 2.1 object types. ``kind`` is ``'sdo'``, ``'sro'`` or ``'all'``."""
    d = _data()
    if kind == "sdo":
        return list(d["stix_sdo"])
    if kind == "sro":
        return list(d["stix_sro"])
    return list(d["stix_sdo"]) + list(d["stix_sro"])


def nist_csf() -> List[Dict]:
    """The NIST Cybersecurity Framework functions (6, including Govern from CSF 2.0)."""
    return list(_data()["nist_csf"])


def d3fend_tactics() -> List[str]:
    """MITRE D3FEND top-level defensive tactics."""
    return list(_data()["d3fend_tactics"])


def frameworks() -> List[Dict[str, str]]:
    """Metadata for every framework modelled here (name, kind, ID shape)."""
    return list(_data()["frameworks"])
