from pathlib import Path

from web_attack_detector import detect, summarize

LINES = Path(__file__).with_name("sample_access.log").read_text().splitlines()


def rules_for(ip):
    hits, _ = detect(LINES)
    return {h.rule for h in hits if h.ip == ip}


def test_benign_traffic_is_quiet():
    assert rules_for("198.51.100.1") == set()


def test_sqli_and_scanner():
    assert {"sqli", "scanner-ua"} <= rules_for("203.0.113.66")


def test_xss_and_double_encoded_traversal():
    assert {"xss", "path-traversal"} <= rules_for("192.0.2.14")


def test_log4shell_and_command_injection():
    assert {"log4shell", "cmd-injection"} <= rules_for("198.18.0.9")


def test_ssrf_and_sensitive_files():
    assert "ssrf" in rules_for("198.18.0.10")
    assert "sensitive-file" in rules_for("198.18.0.11")


def test_successful_attack_is_counted():
    hits, _ = detect(LINES)
    assert summarize(hits)["203.0.113.66"]["succeeded"] >= 2


def test_forced_browsing_threshold():
    line = '10.9.9.9 - - [02/Nov/2026:10:00:00 +0530] "GET /x{} HTTP/1.1" 404 0 "-" "Mozilla/5.0"'
    _, brute = detect([line.format(i) for i in range(25)], notfound_threshold=20)
    assert brute == {"10.9.9.9": 25}
