# cyberonto

A small, **dependency-free** Python toolkit for working with security data — the kind of plumbing every
CTI/OSINT/detection project ends up re-writing, plus an offline model of the open security frameworks.

Two parts:

1. **Indicators** — pull IOCs out of free text, work out what an arbitrary string *is* (the OSINT
   "selector type"), defang/refang, normalize, and validate.
2. **Frameworks** — an offline model of the open security frameworks (MITRE ATT&CK tactics, D3FEND, the
   Lockheed Martin Cyber Kill Chain, the Diamond Model, David Bianco's Pyramid of Pain, OASIS STIX 2.1,
   NIST CSF) and the **documented mappings between them**.

Everything is built on public standards, ships offline, and has **no runtime dependencies**. Python 3.9+.

```bash
pip install cyberonto
```

## Indicators

```python
import cyberonto as co

co.classify("8.8.8.8")                      # 'ipv4'
co.classify("evil.example.com")             # 'domain'
co.classify("d41d8cd98f00b204e9800998ecf8427e")  # 'md5'
co.classify("CVE-2024-1234")                # 'cve'
co.classify("T1566.001")                    # 'attack_id'

# OSINT selector detection — "is this an email, a domain, an IP, a hash... or a username?"
co.detect_selector("john_doe")              # 'username'
co.detect_selector("abuse@example.org")     # 'email'

# Defang for safe sharing, refang to use again
co.defang("https://evil.example.com/x")     # 'hxxp://evil[.]example[.]com/x'
co.refang("bad[.]site and user[at]x[.]com") # 'bad.site and user@x.com'

# Extract everything from a report (refangs first, de-dupes, groups by type)
co.extract("beacon to 203.0.113.5, hxxps://bad[.]site, drop "
           "d41d8cd98f00b204e9800998ecf8427e, see CVE-2024-1234 and T1059")
# {'ipv4': ['203.0.113.5'], 'url': ['https://bad.site'],
#  'md5': ['d41d8cd98f00b204e9800998ecf8427e'], 'cve': ['CVE-2024-1234'],
#  'attack_id': ['T1059']}

co.normalize("EVIL.Example.COM")            # 'evil.example.com'
co.validate("8.8.8.8", "ipv4")              # True
co.pyramid_level("md5")                     # 'Hash Values'  (Pyramid of Pain tier)
```

Recognised types: `ipv4`, `ipv6`, `domain`, `url`, `email`, `md5`, `sha1`, `sha256`, `sha512`, `cve`,
`btc`, `eth`, `asn`, `mac`, `attack_id`, `cwe`, `capec`, `username`.

## Frameworks

```python
from cyberonto import frameworks as fw

fw.tactics()                       # the 14 MITRE ATT&CK Enterprise tactics, in order
fw.tactic("TA0003")["name"]        # 'Persistence'

fw.kill_chain()                    # the 7 Cyber Kill Chain phases
fw.kill_chain_to_attack("Delivery")      # [{'id': 'TA0001', 'name': 'Initial Access'}]
fw.attack_to_kill_chain("TA0011")        # ['Command & Control']

fw.pyramid()                       # Pyramid of Pain tiers (Hash Values -> TTPs)
fw.diamond()                       # the 4 Diamond Model vertices
fw.stix_types("sdo")               # STIX 2.1 domain object types
fw.nist_csf()                      # the 6 NIST CSF 2.0 functions (incl. Govern)
fw.d3fend_tactics()                # MITRE D3FEND defensive tactics
fw.frameworks()                    # metadata for every framework modelled here
```

### Scope, honestly

This ships the **stable enumerations and cross-walks** — ATT&CK *tactics* (not the full technique
catalog), the kill chain, Diamond, the Pyramid of Pain, STIX types, NIST CSF functions, D3FEND tactics,
and the documented mappings between them. The full ATT&CK technique / CWE / CAPEC catalogs are large and
change often, so they're intentionally **not** bundled — `cyberonto` detects and validates their ID
formats (`T####`, `CWE-###`, `CAPEC-###`) and gives you the model to hang them on, but is not a mirror of
those catalogs. If you need the full catalogs, pull them from their official sources and map onto this.

## Why

CTI, OSINT and detection code is full of the same re-invented regexes and half-remembered framework
mappings. `cyberonto` is the small, correct, offline, no-dependency version of that — so you can get on
with the interesting part.

## License

Apache-2.0. Contributions welcome.
