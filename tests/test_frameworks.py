from cyberonto import frameworks as fw


def test_tactics_count_and_lookup():
    ts = fw.tactics()
    assert len(ts) == 14
    assert fw.tactic("TA0003")["name"] == "Persistence"
    assert fw.tactic("persistence")["id"] == "TA0003"
    assert fw.tactic("nope") is None


def test_kill_chain():
    kc = fw.kill_chain()
    assert len(kc) == 7
    assert kc[0]["name"] == "Reconnaissance"
    assert kc[-1]["name"] == "Actions on Objectives"


def test_kill_chain_to_attack():
    m = fw.kill_chain_to_attack("Delivery")
    assert {t["id"] for t in m} == {"TA0001"}
    m2 = fw.kill_chain_to_attack("c2")  # alias handling
    assert {t["id"] for t in m2} == {"TA0011"}


def test_attack_to_kill_chain():
    phases = fw.attack_to_kill_chain("TA0011")
    assert "Command & Control" in phases


def test_other_models():
    assert len(fw.diamond()) == 4
    assert fw.pyramid()[0]["name"] == "Hash Values"
    assert "indicator" in fw.stix_types("sdo")
    assert "relationship" in fw.stix_types("sro")
    assert any(f["name"] == "Govern" for f in fw.nist_csf())
    assert "Detect" in fw.d3fend_tactics()
    assert any(f["key"] == "attack" for f in fw.frameworks())
