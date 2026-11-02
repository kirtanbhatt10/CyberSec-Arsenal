from pathlib import Path

from ioc_extractor import defang, extract, refang

REPORT = Path(__file__).with_name("sample_report.txt").read_text()


def test_refang():
    assert refang("hxxps://evil[.]com/a") == "https://evil.com/a"
    assert refang("1.2.3[.]4 user[at]x[.]ru") == "1.2.3.4 user@x.ru"


def test_extracts_everything_from_report():
    iocs = extract(REPORT)
    assert iocs["url"] == ["https://invoice-portal.xyz/download/inv_2291.zip"]
    assert iocs["ipv4"] == ["45.137.21.9"]  # 10.20.0.15 is private -> filtered
    assert {"cdn-updates.top", "invoice-portal.xyz"} <= set(iocs["domain"])
    assert iocs["email"] == ["billing@invoice-portal.xyz"]
    assert iocs["cve"] == ["CVE-2024-3400"]
    assert set(iocs["mitre_attack"]) == {"T1059.001", "T1566.002"}
    assert len(iocs["sha256"]) == 1 and len(iocs["md5"]) == 1
    assert iocs["bitcoin"] == ["bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"]


def test_benign_reference_links_filtered():
    iocs = extract(REPORT)
    assert not any("mitre.org" in u or "nist.gov" in u for u in iocs["url"])
    assert "attack.mitre.org" not in iocs.get("domain", [])


def test_private_ips_optional():
    assert "10.20.0.15" in extract(REPORT, include_private=True)["ipv4"]


def test_defang():
    assert defang("https://evil.com/x") == "hxxps://evil[.]com/x"
    assert defang("8.8.8.8") == "8.8.8[.]8"
