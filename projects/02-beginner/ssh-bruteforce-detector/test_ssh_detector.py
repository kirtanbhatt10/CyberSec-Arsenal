from pathlib import Path

from ssh_detector import analyze, firewall_rules, parse_events

SAMPLE = Path(__file__).with_name("sample_auth.log")


def load():
    return parse_events(SAMPLE.read_text().splitlines(), year=2026)


def test_parses_all_auth_events():
    assert len(load()) == 15


def test_brute_force_then_success_is_flagged():
    offenders = analyze(load(), threshold=5, window=60)
    assert offenders["203.0.113.9"].compromised_users == {"root"}


def test_spraying_is_classified():
    offenders = analyze(load(), threshold=5, window=60)
    assert "spraying" in offenders["198.51.100.77"].technique


def test_legit_typo_is_not_flagged():
    assert "192.0.2.50" not in analyze(load())


def test_firewall_rules_handle_ipv6():
    rules = firewall_rules(["2001:db8::1", "203.0.113.9"], "iptables")
    assert rules[0].startswith("ip6tables") and rules[1].startswith("iptables")
