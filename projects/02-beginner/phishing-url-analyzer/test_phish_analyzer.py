import pytest

from phish_analyzer import analyze, levenshtein, split_host


@pytest.mark.parametrize("url", [
    "https://www.paypal.com/signin",
    "https://github.com/kirtanbhatt10",
    "https://www.bbc.co.uk/news",
])
def test_legit_urls_are_safe(url):
    assert analyze(url).label == "LIKELY SAFE", analyze(url).reasons


@pytest.mark.parametrize("url", [
    "http://paypal.com.account-verify.xyz/login",
    "http://paypa1.com/webscr?cmd=login",
    "http://192.168.10.5/bank/login.php",
    "https://xn--pple-43d.com/",
    "http://www.google.com@evil.tk/verify",
])
def test_phishing_urls_are_flagged(url):
    assert analyze(url).label in {"SUSPICIOUS", "PHISHING"}, analyze(url).reasons


def test_reasons_are_explainable():
    v = analyze("http://micros0ft-login.top/verify")
    assert v.reasons and all(r.startswith("+") for r in v.reasons)


def test_helpers():
    assert levenshtein("kitten", "sitting") == 3
    assert split_host("login.evil.co.uk") == (["login"], "evil", "co.uk")
