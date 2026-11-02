from password_auditor import audit, deleet, entropy_bits, find_keyboard_walks, find_sequences


def test_common_password_is_very_weak():
    assert audit("password").score == 0


def test_leetspeak_is_detected():
    assert deleet("P@ssw0rd") == "password"
    report = audit("P@ssw0rd123")
    assert any("leetspeak" in f for f in report.findings)
    assert report.score <= 1


def test_keyboard_walk_and_sequence():
    assert "qwer" in find_keyboard_walks("xxQWERTYxx")[0]
    assert find_sequences("abc1234")


def test_long_random_passphrase_is_strong():
    report = audit("Violet-Kettle-Orbit-73-Lantern!")
    assert report.score >= 3


def test_entropy_grows_with_pool():
    assert entropy_bits("aaaaaaaa") < entropy_bits("aA1!aA1!")
