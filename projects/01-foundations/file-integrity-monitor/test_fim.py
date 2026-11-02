import json
import os

import pytest

from fim import compare, load_baseline, save_baseline, snapshot


@pytest.fixture
def tree(tmp_path):
    (tmp_path / "a.txt").write_text("alpha")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.conf").write_text("beta")
    return tmp_path


def test_detects_add_delete_modify_and_chmod(tree):
    old = snapshot(tree)
    (tree / "a.txt").write_text("tampered")
    (tree / "sub" / "b.conf").unlink()
    (tree / "new.sh").write_text("#!/bin/sh")
    os.chmod(tree / "new.sh", 0o777)
    mid = snapshot(tree)
    d = compare(old, mid)
    assert d.modified == ["a.txt"]
    assert d.deleted == ["sub/b.conf"]
    assert d.added == ["new.sh"]

    os.chmod(tree / "new.sh", 0o700)
    assert compare(mid, snapshot(tree)).metadata


def test_tampered_baseline_is_rejected(tree, tmp_path_factory):
    out = tmp_path_factory.mktemp("bl") / "base.json"
    save_baseline(snapshot(tree), out, b"secret")
    doc = json.loads(out.read_text())
    doc["files"]["a.txt"]["sha256"] = "0" * 64
    out.write_text(json.dumps(doc))
    with pytest.raises(ValueError):
        load_baseline(out, b"secret")


def test_clean_when_unchanged(tree):
    assert compare(snapshot(tree), snapshot(tree)).clean
