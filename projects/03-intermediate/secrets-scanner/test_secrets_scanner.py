import subprocess

from secrets_scanner import scan_git_history, scan_text, scan_tree, to_sarif

# Fake credentials assembled at runtime so this test file itself doesn't trip scanners.
AWS = "AKIA" + "Z7Q4N2X8LM3P6RTV"
GH = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"


def rules(findings):
    return {f.rule for f in findings}


def test_provider_rules():
    text = f'aws_key = "{AWS}"\ntoken: {GH}\n-----BEGIN RSA PRIVATE KEY-----\n'
    assert {"aws-access-key-id", "github-token", "private-key"} <= rules(scan_text(text, "x.py"))


def test_generic_entropy_and_placeholders():
    assert rules(scan_text('API_KEY = "q8Zr2LmX9vTb4NwK7pYc"', "c.py")) == {"generic-high-entropy"}
    assert not scan_text('password = "changeme-changeme"', "c.py")
    assert not scan_text('password = "aaaaaaaaaaaaaaaa"', "c.py")  # low entropy


def test_ignore_comment():
    assert not scan_text(f'k = "{AWS}"  # secrets-scanner: ignore', "a.py")


def test_redaction_never_leaks_full_secret():
    f = scan_text(AWS, "a")[0]
    assert AWS not in f.secret and f.secret.startswith("AKIA")


def test_git_history_finds_deleted_secret(tmp_path):
    def git(*args):
        subprocess.run(["git", "-C", str(tmp_path), *args], check=True, capture_output=True)

    git("init", "-q")
    git("config", "user.email", "t@example.com")
    git("config", "user.name", "t")
    (tmp_path / "settings.py").write_text(f'AWS = "{AWS}"\n')
    git("add", ".")
    git("commit", "-qm", "add config")
    (tmp_path / "settings.py").write_text('AWS = os.environ["AWS"]\n')
    git("commit", "-qam", "remove key")

    assert not scan_tree(str(tmp_path))
    hist = scan_git_history(str(tmp_path))
    assert any(f.rule == "aws-access-key-id" and f.commit for f in hist)


def test_sarif_shape():
    doc = to_sarif(scan_text(AWS, "a.py"))
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"][0]["ruleId"] == "aws-access-key-id"
