"""Unit tests for the DNS-tunneling decoder (no tshark required)."""
from __future__ import annotations

import base64

from backend.analyzers.pcap import dns_tunnel_candidates, _try_decodes


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