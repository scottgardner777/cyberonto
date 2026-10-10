import cyberonto as co
from cyberonto import indicators as ind


def test_classify_basic():
    assert co.classify("8.8.8.8") == "ipv4"
    assert co.classify("2001:4860:4860::8888") == "ipv6"
    assert co.classify("evil.example.com") == "domain"
    assert co.classify("https://evil.example.com/x") == "url"
    assert co.classify("abuse@example.org") == "email"
    assert co.classify("d41d8cd98f00b204e9800998ecf8427e") == "md5"
    assert co.classify("da39a3ee5e6b4b0d3255bfef95601890afd80709") == "sha1"
    assert co.classify("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == "sha256"
    assert co.classify("CVE-2024-1234") == "cve"
    assert co.classify("T1566.001") == "attack_id"
    assert co.classify("CWE-79") == "cwe"
    assert co.classify("CAPEC-66") == "capec"
    assert co.classify("AS15169") == "asn"
    assert co.classify("00:1a:2b:3c:4d:5e") == "mac"
    assert co.classify("0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe") == "eth"
    assert co.classify("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa") == "btc"
    assert co.classify("not an indicator!!") == "unknown"


def test_ipv4_not_domain_and_bounds():
    assert co.classify("256.1.1.1") != "ipv4"
    assert co.classify("1.2.3.4") == "ipv4"


def test_detect_selector_username():
    assert co.detect_selector("john_doe") == "username"
    assert co.detect_selector("@osint_handle") == "username"
    assert co.detect_selector("abuse@example.org") == "email"
    assert co.detect_selector("!!!") == "unknown"


def test_validate():
    assert co.validate("8.8.8.8")
    assert co.validate("8.8.8.8", "ipv4")
    assert not co.validate("8.8.8.8", "ipv6")
    assert not co.validate("nope")
    assert co.validate("example.com", "domain")


def test_defang_refang_roundtrip():
    url = "https://evil.example.com/a.php?x=1"
    d = co.defang(url)
    assert "hxxp" in d and "[.]" in d and "://" not in d.replace("[://]", "")
    assert co.refang(d) == url
    assert co.refang("evil[.]com") == "evil.com"
    assert co.refang("bad(dot)site") == "bad.site"
    assert co.refang("user[at]example[.]com") == "user@example.com"


def test_extract_from_text():
    text = ("beacon to 203.0.113.5 and hxxps://bad[.]site/x, drop "
            "d41d8cd98f00b204e9800998ecf8427e, see CVE-2024-1234 and T1059, "
            "contact mule@fraud[.]example")
    out = co.extract(text)
    assert out["ipv4"] == ["203.0.113.5"]
    assert out["url"] == ["https://bad.site/x"]
    assert out["md5"] == ["d41d8cd98f00b204e9800998ecf8427e"]
    assert out["cve"] == ["CVE-2024-1234"]
    assert out["attack_id"] == ["T1059"]
    assert out["email"] == ["mule@fraud.example"]
    # the domains inside the url/email are not double-reported as bare domains
    assert "bad.site" not in out.get("domain", [])
    assert "fraud.example" not in out.get("domain", [])


def test_normalize():
    assert co.normalize("EVIL.Example.COM") == "evil.example.com"
    assert co.normalize("D41D8CD98F00B204E9800998ECF8427E") == "d41d8cd98f00b204e9800998ecf8427e"
    assert co.normalize("HTTPS://Evil.COM/Path") == "https://evil.com/Path"


def test_pyramid_level():
    assert co.pyramid_level("md5") == "Hash Values"
    assert co.pyramid_level("ipv4") == "IP Addresses"
    assert co.pyramid_level("domain") == "Domain Names"
    assert co.pyramid_level("attack_id") == "TTPs"
    assert co.pyramid_level("nope") is None


def test_type_constants():
    assert ind.MD5 in ind.HASH_TYPES
    assert ind.IPV4 == "ipv4"
