#!/usr/bin/env python3
"""Real picoCTF challenge test for StegSuite (downloads from GitHub mirrors).

picoctf.net does not resolve from the dev host, so files come from the
HHousen/PicoCTF-* writeup repos on GitHub.

Run against a running StegSuite:
    STEGSUITE=http://localhost:19014 python3 app/tests/real_challenges.py
"""
from __future__ import annotations

import json
import os
import time
import urllib.parse
import urllib.request
from pathlib import Path

API = os.environ.get("STEGSUITE", "http://localhost:19014") + "/api/v1"
DEST = Path("/tmp/realch")

B19 = "https://raw.githubusercontent.com/HHousen/PicoCTF-2019/master/Forensics"
B21 = "https://raw.githubusercontent.com/HHousen/PicoCTF-2021/master/Forensics"
B22 = "https://raw.githubusercontent.com/HHousen/PicoCTF-2022/master/Forensics"
# OliCyber / ITS training (https://training.olicyber.it) require a login; these
# challenge artifacts come from a public write-up mirror instead.
OLI = "https://raw.githubusercontent.com/00xFE/Olicyber/HEAD/NETWORK"
OLIM = "https://raw.githubusercontent.com/00xFE/Olicyber/HEAD/Olimpiadi Italiane di Cybersecurity"
SW = "https://raw.githubusercontent.com/00xFE/Olicyber/HEAD/SOFTWARE"
OLI23 = "https://raw.githubusercontent.com/00xFE/Olicyber/HEAD/Olicyber 2023/Training camp 3"

CASES = [
    ("pico_img.png", f"{B19}/So Meta/pico_img.png", "picoCTF{s0_m3ta_43f253bb}"),
    ("cat.jpg", f"{B21}/information/cat.jpg", "picoCTF{the_m3tadata_1s_modified}"),
    ("dolls.jpg", f"{B21}/Matryoshka doll/dolls.jpg", "picoCTF{336cf6d51c9d9774fd37196c1d7320ff}"),
    ("buildings.png", f"{B19}/What Lies Within/buildings.png", "picoCTF{h1d1ng_1n_th3_b1t5}"),
    ("garden.jpg", f"{B19}/Glory of the Garden/garden.jpg", "picoCTF{more_than_m33ts_the_3y35a97d3bB}"),
    # extension lies: it's a PNG named .txt -> needs type detection for the plan
    ("flag.txt", f"{B19}/extensions/flag.txt", "picoCTF{now_you_know_about_extensions}"),
    # macro-based: base64 inside the vbaProject of a .docm
    ("weird.docm", f"{B21}/Weird File/weird.docm", "picoCTF{m4cr0s_r_d4ng3r0us}"),
    # LSB stego in the RGB channels -> zsteg
    ("pico.flag.png", f"{B22}/St3g0/pico.flag.png", "picoCTF{7h3r3_15_n0_5p00n_96ae0ac1}"),
    # pcap -> HTTP export -> evil_duck.png -> Invoke-PSImage payload (B/G low
    # nibbles) holding a PowerShell "map" whose two strings XOR to the flag
    ("try_me.pcap", f"{B21}/Very very very Hidden/try_me.pcap",
     "picoCTF{n1c3_job_f1nd1ng_th3_s3cr3t_in_the_im@g3}"),
    # pptm: base64 split by a space between every char in ppt/slideMasters/hidden
    # -> the `office` analyzer unzips the parts and decodes whitespace-split base64
    ("mmwe.pptm", f"{B21}/MacroHard WeakEdge/Forensics is fun.pptm",
     "picoCTF{D1d_u_kn0w_ppts_r_z1p5}"),
    # WAV: samples quantised into 16 levels encode a hex string -> wav-levels
    ("main.wav", f"{B21}/Surfing the Waves/main.wav",
     "picoCTF{mU21C_1s_1337_115155af}"),
    # --- OliCyber / ITS training (public write-up mirror) ---
    ("nw-intro01.pcap", f"{OLI}/NW_1/nw-intro01.pcap", "flag{Y0u_kn0w_Wh4t_a_Pc4p_1s}"),
    ("nw03-http.pcapng", f"{OLI}/NW_3/nw-intro03.pcapng", "flag{L3aRn1N9_4b0uT_F1lter5_p1}"),
    ("nw04-dns.pcapng", f"{OLI}/NW_4/nw-intro03.pcapng", "flag{L3aRn1N9_4b0uT_F1lter5_1P_DN5_f1lt3r}"),
    ("nw05-comments.pcapng", f"{OLI}/NW_5/nw-intro03.pcapng", "flag{L3aRn1N9_4b0uT_F1lter5_C0mm3Nt5_4R3_H4rd_t0_f1nD}"),
    ("nw-intro08.pcap", f"{OLI}/NW_8/nw-intro08.pcap", "flag{Byt35_Ex7rAct10n_1s_3a5y!}"),
    # --- Olimpiadi Italiane di Cybersecurity (public write-up mirror) ---
    ("hex.png", f"{OLIM}/MISCELLANEOUS/Byte-flag/flag.png", "flag{Hex1sntFunn1}"),
    ("dashed.txt", f"{OLIM}/MISCELLANEOUS/Dashed/dashed.txt", "flag{PNRFNE_ZR!-y0u_G07_iT_r1ghT!}"),
    ("flag0.zip", f"{OLIM}/MISCELLANEOUS/Zipception/flag0.zip", "flag{Un0_z1p_d3n7r0_un0_z1p_1mp0551b1l3!}"),
    ("easy_stream.pcapng", f"{OLIM}/NETWORK/easy stream/easy_stream.pcapng", "flag{1sto3asy}"),
    ("useless.pcapng", f"{OLIM}/NETWORK/Useless/capture.pcapng", "flag{4lw4y5_ch3ck_th3_c0mm3nt5}"),
    ("gitgud.zip", f"{OLIM}/MISCELLANEOUS/gitgud/gitgud.zip", "flag{0h_n0_my_4p1_k3y}"),
    # --- OliCyber SOFTWARE (reversing binaries, flag embedded as a string) ---
    ("sw-04", f"{SW}/SW_4/sw-04", "flag{0cca06f6}"),
    ("sw-08", f"{SW}/SW_8/sw-08", "flag{e25b8bdf}"),
    ("sw-09", f"{SW}/SW_9/sw-09", "flag{01b81d48}"),
    ("sw-10", f"{SW}/SW_10/sw-10", "flag{0f32826c}"),
    ("sw-11", f"{SW}/SW_11/sw-11", "flag{5a11b5a6}"),
]

# multi-file challenges: (label, [(filename, url), ...], expected flag)
MULTI = [
    # TLS with an RSA private key: header in the decrypted stream
    ("webnet0", [("capture.pcap", f"{B19}/WebNet0/capture.pcap"),
                 ("picopico.key", f"{B19}/WebNet0/picopico.key")],
     "picoCTF{nongshim.shrimp.crackers}"),
    # TLS with a key: the real flag is in the metadata of a downloaded JPEG
    ("webnet1", [("capture.pcap", f"{B19}/WebNet1/capture.pcap"),
                 ("picopico.key", f"{B19}/WebNet1/picopico.key")],
     "picoCTF{honey.roasted.peanuts}"),
    # TLS1.3 keylog (not CLIENT_RANDOM): the flag is in a decrypted HTTP/2 header
    ("nw09-tls", [("nw-intro09.pcapng", f"{OLI}/NW_9/nw-intro09.pcapng"),
                  ("tls-keys.log", f"{OLI}/NW_9/tls-keys.log")],
     "flag{S3cr3t_K3y5_4re_n0_J0k3}"),
    # Olimpiadi NETWORK: TLS with a keylog -> decrypted request
    ("trasporti-tls", [("capture.pcapng", f"{OLIM}/NETWORK/Sicurezza dei trasporti/capture.pcapng"),
                       ("keys.log", f"{OLIM}/NETWORK/Sicurezza dei trasporti/keys.log")],
     "flag{tls_is_really_hard}"),
    # PNG with a password-protected zip hidden in the RGBA LSB (password in a
    # sibling text file): lsb-carve extracts it, 7z uses the sibling password
    ("gabchan", [("Gab-chan.png", f"{OLI23}/Gab-Chan/Gab-chan.png"),
                 ("gabchan.txt", f"{OLI23}/Gab-Chan/gabchan.txt")],
     "flag{n0n_3_m15c_s3nz4_s73g0}"),
]


def download(url: str, dest: Path) -> None:
    if dest.exists() and dest.stat().st_size > 0:
        return
    encoded = urllib.parse.quote(url, safe=":/")
    with urllib.request.urlopen(encoded, timeout=120) as r:
        dest.write_bytes(r.read())


def _multipart(path: Path, mode: str) -> tuple[bytes, str]:
    return _multipart_many([path], mode)


def _multipart_many(paths: list[Path], mode: str) -> tuple[bytes, str]:
    b = "----stegreal"
    body = (f'--{b}\r\nContent-Disposition: form-data; name="mode"\r\n\r\n{mode}\r\n').encode()
    for path in paths:
        body += (f'--{b}\r\nContent-Disposition: form-data; name="files"; filename="{path.name}"\r\n'
                 f'Content-Type: application/octet-stream\r\n\r\n').encode() + path.read_bytes() + b"\r\n"
    body += f"--{b}--\r\n".encode()
    return body, b


def post(path: str, data: bytes = b"", ctype=None):
    req = urllib.request.Request(API + path, data=data, method="POST")
    if ctype:
        req.add_header("Content-Type", ctype)
    with urllib.request.urlopen(req, timeout=120) as r:
        raw = r.read()
    return json.loads(raw) if raw[:1] in (b"{", b"[") else raw.decode()


def get(path: str):
    with urllib.request.urlopen(API + path, timeout=120) as r:
        return json.loads(r.read())


def run_case(name: str, url: str, expect: str) -> bool:
    DEST.mkdir(parents=True, exist_ok=True)
    p = DEST / name
    download(url, p)
    body, b = _multipart(p, "auto")
    proj = post("/projects", body, f"multipart/form-data; boundary={b}")
    post(f"/projects/{proj['id']}/start")
    status = "?"
    for _ in range(300):
        status = get(f"/projects/{proj['id']}")["status"]
        if status in ("done", "error", "cancelled"):
            break
        time.sleep(3)
    flags = [f["value"] for f in get(f"/projects/{proj['id']}/findings") if f["kind"] == "flag"]
    # a flag must never be a fragment of a longer one (e.g. CTF{x} in picoCTF{x})
    fragments = [fl for fl in flags if any(fl != o and fl in o for o in flags)]
    ok = any(expect in fl for fl in flags) and not fragments
    extra = f" fragments={fragments}" if fragments else ""
    print(f"  [{'PASS' if ok else 'FAIL'}] {name:<15} status={status} expect={expect} got={flags[:3]}{extra}")
    return ok


def run_multi(label: str, files: list[tuple[str, str]], expect: str) -> bool:
    d = DEST / label
    d.mkdir(parents=True, exist_ok=True)
    paths: list[Path] = []
    for name, url in files:
        p = d / name
        download(url, p)
        paths.append(p)
    body, b = _multipart_many(paths, "auto")
    proj = post("/projects", body, f"multipart/form-data; boundary={b}")
    post(f"/projects/{proj['id']}/start")
    status = "?"
    for _ in range(300):
        status = get(f"/projects/{proj['id']}")["status"]
        if status in ("done", "error", "cancelled"):
            break
        time.sleep(3)
    flags = [f["value"] for f in get(f"/projects/{proj['id']}/findings") if f["kind"] == "flag"]
    ok = any(expect in fl for fl in flags)
    print(f"  [{'PASS' if ok else 'FAIL'}] {label:<15} status={status} expect={expect} got={flags[:3]}")
    return ok


def main() -> int:
    print(f"* real picoCTF challenges against {API}")
    results = [run_case(*c) for c in CASES]
    results += [run_multi(*c) for c in MULTI]
    print(f"* {sum(results)}/{len(results)} passed")
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
