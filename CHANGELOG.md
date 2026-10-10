# Changelog

All notable changes to `cyberonto` are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions follow [SemVer](https://semver.org/).

## [0.1.0] — 2026-10-10
Initial release.

### Added
- **Indicators** (`cyberonto.indicators`): `extract`, `classify`, `detect_selector`, `defang`, `refang`,
  `normalize`, `validate`, `pyramid_level`. Recognises ipv4/ipv6, domain, url, email, md5/sha1/sha256/
  sha512, cve, btc, eth, asn, mac, ATT&CK IDs, CWE, CAPEC, and plausible usernames. No dependencies.
- **Frameworks** (`cyberonto.frameworks`): offline model of ATT&CK tactics, the Cyber Kill Chain, the
  Diamond Model, the Pyramid of Pain, STIX 2.1 types, NIST CSF functions and D3FEND tactics, with
  kill-chain ↔ ATT&CK cross-mappings. Bundled dataset; works offline.
- Full type hints (`py.typed`), tests, Apache-2.0.
