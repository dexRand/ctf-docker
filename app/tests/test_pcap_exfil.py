"""URL-parameter exfiltration in pcap (issue #11) + XOR by known prefix."""
from __future__ import annotations

from backend.analyzers.pcap import param_exfil
from backend.analyzers.util import xor_known_prefix

FLAG = b"ictf{x_t3nsion}"


def test_xor_known_prefix_derives_the_key():
    enc = bytes(b ^ 0x37 for b in FLAG)
    assert (0x37, FLAG) in xor_known_prefix(enc)
    assert xor_known_prefix(b"random bytes here") == []


def test_one_hex_byte_per_request_doubled_and_xored():
    uris = [f"http://h/?t={b ^ 0x37:02x}" for b in FLAG for _ in range(2)]
    lines = param_exfil(uris)
    assert any(FLAG.decode() in ln for ln in lines)


def test_plain_text_and_base64_series():
    uris = [f"http://h/log?c={ch}" for ch in "flag{plain}"]
    assert any("flag{plain}" in ln for ln in param_exfil(uris))
    import base64
    b64 = base64.b64encode(b"flag{b64_series}").decode().rstrip("=")
    uris = [f"http://h/p?d={b64[i:i + 4]}" for i in range(0, len(b64), 4)]
    assert any("flag{b64_series}" in ln for ln in param_exfil(uris))


def test_few_requests_are_ignored():
    assert param_exfil(["http://h/?a=1", "http://h/?a=2"]) == []


def test_ssid_report_decodes_hex_then_base64_and_lists_rare_first():
    import base64
    from backend.analyzers.pcap import ssid_report
    noise = base64.b64encode(b"not the network you are looking for\n").hex()
    flag = base64.b64encode(b"bctf{w1f1_s51d}\n").hex()
    report = ssid_report([noise] * 50 + [flag] * 50 + ["HomeWiFi"])
    assert report.splitlines()[0].strip().startswith("1")          # rarest first
    assert "bctf{w1f1_s51d}" in report
