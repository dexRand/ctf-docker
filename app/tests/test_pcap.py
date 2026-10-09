"""Unit tests for the DNS-tunneling decoder (no tshark required)."""
from __future__ import annotations

import base64
from pathlib import Path

from backend.analyzers.base import ToolContext
from backend.analyzers.pcap import (
    _key_files,
    _tls_options,
    _expand_http_response,
    dns_tunnel_candidates,
    _try_decodes,
)


def b32_chunks(text: str, size: int = 5) -> list[str]:
    enc = base64.b32encode(text.encode()).decode()
    return [enc[i:i + size] for i in range(0, len(enc), size)]


def test_no_queries_or_single() -> None:
    assert dns_tunnel_candidates([]) == []
    assert dns_tunnel_candidates(["www.example.com"]) == []


def test_base32_first_label_is_reassembled() -> None:
    flag = "ITS{dns_tunnel}"
    chunks = b32_chunks(flag)
    queries = [c + ".exfil.ctf" for c in chunks]
    out = dns_tunnel_candidates(queries)
    assert out and flag in out[0]
    assert "base32" in out[0]


def test_infra_noise_does_not_hide_the_stream() -> None:
    flag = "ITS{noisy_dns}"
    queries = ["www.corp.com", "mail.corp.com", "ns1.corp.com"] \
        + [c + ".exfil.ctf" for c in b32_chunks(flag)]
    out = dns_tunnel_candidates(queries)
    assert any(flag in line for line in out)


def test_chunks_in_second_label_are_found() -> None:
    flag = "ITS{second_label}"
    queries = ["example." + c + ".net" for c in b32_chunks(flag)]
    out = dns_tunnel_candidates(queries)
    assert any(flag in line for line in out)


def test_base64_chunks_are_found() -> None:
    flag = "flag{b64_dns_tunnel}"
    enc = base64.b64encode(flag.encode()).decode()
    queries = [enc[i:i + 5] + ".exfil.ru" for i in range(0, len(enc), 5)]
    out = dns_tunnel_candidates(queries)
    assert any(flag in line for line in out)


def test_normal_traffic_yields_nothing() -> None:
    queries = ["www.example.com", "mail.example.com", "api.example.com",
               "www.google.com", "cdn.example.net", "ns1.example.org"] * 3
    assert dns_tunnel_candidates(queries) == []


def test_decodes_none_for_junk() -> None:
    assert _try_decodes("kdfjkdfjdk") == []


def _project(tmp_path: Path) -> ToolContext:
    proj = tmp_path / "proj"
    (proj / "uploads").mkdir(parents=True)
    (proj / "files").mkdir()
    work = proj / "work" / "5"
    work.mkdir(parents=True)
    (proj / "files" / "0002__picopico.key").write_bytes(
        b"-----BEGIN PRIVATE KEY-----\nMIIabc\n")
    (proj / "uploads" / "sslkeylog.txt").write_bytes(b"CLIENT_RANDOM aa bb\n")
    (proj / "files" / "0003__notes.txt").write_text("just a note")
    cap = proj / "files" / "0001__capture.pcap"
    cap.write_bytes(b"\xd4\xc3\xb2\xa1")
    return ToolContext(input=cap, workdir=work)


def test_key_files_are_discovered_and_deduplicated(tmp_path: Path) -> None:
    keys = _key_files(_project(tmp_path))
    names = {k.name for k in keys}
    assert "0002__picopico.key" in names
    assert "sslkeylog.txt" in names
    assert "0003__notes.txt" not in names      # not a key
    assert len(keys) == 2


def test_tls_options_for_rsa_and_keylog(tmp_path: Path) -> None:
    opts = _tls_options(_key_files(_project(tmp_path)))
    assert any(o.startswith("tls.keys_list:0.0.0.0,0,http,") for o in opts)
    assert any(o.startswith("tls.keylog_file:") for o in opts)


def test_tls13_keylog_without_client_random_is_detected(tmp_path: Path) -> None:
    # TLS 1.3 keylog files have no CLIENT_RANDOM line, only *_TRAFFIC_SECRET*
    proj = tmp_path / "p13"
    (proj / "uploads").mkdir(parents=True)
    (proj / "files").mkdir()
    work = proj / "work" / "1"
    work.mkdir(parents=True)
    cap = proj / "files" / "0001__capture.pcapng"
    cap.write_bytes(b"\x0a\x0d\x0d\x0a")
    (proj / "uploads" / "tls-keys.log").write_bytes(
        b"CLIENT_TRAFFIC_SECRET_0 aa bb\n"
        b"SERVER_HANDSHAKE_TRAFFIC_SECRET cc dd\nEXPORTER_SECRET ee ff\n")
    ctx = ToolContext(input=cap, workdir=work)
    keys = _key_files(ctx)
    assert any(k.name == "tls-keys.log" for k in keys)
    opts = _tls_options(keys)
    assert any(o.startswith("tls.keylog_file:") for o in opts)


def test_expand_http_response_splits_headers_on_one_line_each() -> None:
    # tshark joins response header lines with ',' inside the field value
    row = ("https://host/\tDate: Fri, 23 Aug 2019 15:56:36 GMT\\r\\n,Server: Apache\\r\\n,"
           "Pico-Flag: picoCTF{nongshim.shrimp.crackers}\\r\\n,Content-Length: 821\\r\\n,")
    lines = _expand_http_response(row).split("\n")
    assert lines[0] == "https://host/"
    assert "  Pico-Flag: picoCTF{nongshim.shrimp.crackers}" in lines
    assert any(line.strip().startswith("Server:") for line in lines)
    assert "\r\n" not in "\n".join(lines) and "\\r\\n" not in "\n".join(lines)


def test_expand_http_response_handles_real_crlf() -> None:
    out = _expand_http_response("https://h/\tA: 1\r\n,B: 2\r\n,Pico-Flag: ITS{x}\r\n,")
    assert out.startswith("https://h/")
    assert "  Pico-Flag: ITS{x}" in out.split("\n")


def test_expand_http_response_without_tab_is_unchanged() -> None:
    assert _expand_http_response("no tab here") == "no tab here"
    assert _expand_http_response("") == ""


def test_expand_http_response_request_only_row_is_dropped() -> None:
    # a request packet row carries the URI but no response headers
    assert _expand_http_response("https://host/\t") == ""
    assert _expand_http_response("https://host/\t   ") == ""