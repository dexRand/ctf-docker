"""hashcat command building: wordlist (±rules) and mask brute-force."""
from __future__ import annotations

from pathlib import Path

from backend import cracking


def test_hashcat_args_plain_wordlist():
    args = cracking.hashcat_args(13600, "/tmp/h.hash", wordlist="/tmp/w.txt")
    assert args[:5] == ["hashcat", "-m", "13600", "-a", "0"]
    assert "/tmp/w.txt" in args
    assert "--rules-file" not in args


def test_hashcat_args_with_rules_runtime_and_potfile():
    args = cracking.hashcat_args(17200, "/tmp/h.hash", wordlist="/tmp/w.txt",
                                 rules_file=Path("/r/best64.rule"), runtime=30,
                                 potfile="/tmp/pot")
    assert "--rules-file" in args and "/r/best64.rule" in args
    assert "--runtime" in args and "30" in args
    assert "--potfile-path" in args


def test_hashcat_args_mask_mode():
    args = cracking.hashcat_args(13600, "/tmp/h.hash", mask="?d?d?d?d")
    assert args[:5] == ["hashcat", "-m", "13600", "-a", "3"]
    assert "?d?d?d?d" in args


def test_rules_path_resolves_paths_and_rejects_unknown():
    assert cracking._rules_path("") is None
    assert cracking._rules_path("definitely-not-a-rule") is None


def test_rules_path_accepts_an_existing_file(tmp_path):
    rule = tmp_path / "my.rule"
    rule.write_text(":")
    assert cracking._rules_path(str(rule)) == rule


def test_parse_bkcrack_keys():
    text = "bkcrack 1.8.1\nKeys: 1a2b3c4d 5e6f7a8b 9c0d1e2f\n"
    assert cracking._parse_bkcrack_keys(text) == "1a2b3c4d 5e6f7a8b 9c0d1e2f"
    assert cracking._parse_bkcrack_keys("no keys here") is None


def test_pot_password_keeps_colons_in_the_password():
    h = "$pkzip2$1*1*2*0*c*0*abc*$/pkzip2$"
    assert cracking._pot_password(f"{h}:pa:ss:w0rd\n", h) == "pa:ss:w0rd"
    assert cracking._pot_password("", h) is None


def test_tool_timeout_is_capped_by_the_deadline():
    import time
    assert cracking._tool_timeout(None) == 3600
    assert cracking._tool_timeout(time.time() + 30) <= 30
    assert cracking._tool_timeout(time.time() - 5) == 1


def test_each_crack_gets_its_own_scratch_dir():
    a, b = cracking._scratch("x"), cracking._scratch("x")
    try:
        assert a != b and a.is_dir() and b.is_dir()
    finally:
        a.rmdir(); b.rmdir()


def test_pot_password_ignores_hashcat_errors():
    h = "$pkzip2$1*1*2*0*c*0*abc*$/pkzip2$"
    err = "Hashfile '/tmp/x/hash' on line 1 ($pkzip...zip2$): Hash contains unsupported compression type for current mode"
    assert cracking._pot_password(err + "\n", h) is None
