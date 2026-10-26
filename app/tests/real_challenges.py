#!/usr/bin/env python3
"""Real picoCTF challenge test for StegSuite (downloads from GitHub mirrors).

picoctf.net does not resolve from the dev host, so files come from the
HHousen/PicoCTF-* writeup repos on GitHub.

Run against a running StegSuite:
    STEGSUITE=http://localhost:19014 python3 app/tests/real_challenges.py
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
import stegsuite_client as ss  # noqa: E402

API = ss.API
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
# susers/Writeups: archive of Chinese CTF challenges + write-ups (challenge files
# under each challenge dir, expected flags in the READMEs).
SUS = "https://raw.githubusercontent.com/susers/Writeups/master"
# SekaiCTF 2026 archived platform (attachments under uploads/external/<hash>/).
SEK26 = "https://2026.ctf.sekai.team/uploads/external/9ba479d8"

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
    # Unicode En/Em spaces as bits -> whitespace/zerowidth stego
    ("whitepages.txt", f"{B19}/WhitePages/whitepages.txt",
     "picoCTF{not_all_spaces_are_created_equal_f71be4d2457dc2d068e8b1e7a51ed39a}"),
    # pcap: the flag is reassembled from UDP payloads -> tshark streams
    ("shark1.pcap", f"{B19}/shark on wire 1/capture.pcap", "picoCTF{StaT31355_636f6e6e}"),
    # pcapng: flag hidden in a stream -> tshark follow/stream
    ("shark1.pcapng", f"{B21}/Wireshark doo dooo do doo.../shark1.pcapng",
     "picoCTF{p33kab00_1_s33_u_deadbeef}"),
    # BMP: flag bits in the LSB of the raw bytes at offset 2000, LSB-first, +5
    # per char -> the `lsb-bits` analyzer scans order/shift/offset
    ("encoded.bmp", f"{B19}/Investigative Reversing 2/encoded.bmp",
     "picoCTF{n3xt_0n300000000000000000000000006c732cee}"),
    # UDP source ports are the ASCII codes of the flag -> pcap `_port_text`
    ("sw2-capture.pcap", f"{B19}/shark on wire 2/capture.pcap",
     "picoCTF{p1LLf3r3d_data_v1a_st3g0}"),
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
    ("corrupted_file", f"{OLIM}/MISCELLANEOUS/Corrupted flag/corrupted_file", "flag{Wh4t_th3_fl4g}"),
    # --- OliCyber SOFTWARE (reversing binaries, flag embedded as a string) ---
    ("sw-04", f"{SW}/SW_4/sw-04", "flag{0cca06f6}"),
    ("sw-08", f"{SW}/SW_8/sw-08", "flag{e25b8bdf}"),
    ("sw-09", f"{SW}/SW_9/sw-09", "flag{01b81d48}"),
    ("sw-10", f"{SW}/SW_10/sw-10", "flag{0f32826c}"),
    ("sw-11", f"{SW}/SW_11/sw-11", "flag{5a11b5a6}"),
    # --- susers/Writeups (Chinese CTF archive) ---
    # SusCTF 2017 Misc "Fun jpg": the flag lives in the JPEG XMP metadata
    # (dc:creator) -> exiftool source, custom "SusCTF" prefix
    ("flag.jpg", f"{SUS}/2017/SusCTF萌新赛/Misc/Misc1/flag.jpg", "SusCTF{MetaData_1s_Important}"),
    # --- SekaiCTF 2026 archived platform ---
    # impossible stego: the flag is inside base64-encoded AI traffic in messages.log;
    # StegSuite extracts the tar.gz, then the `blobs` analyzer decodes the blobs
    ("misc_impossible-stego.tar.gz", f"{SEK26}/misc_impossible-stego.tar.gz",
     "SEKAI{impossible_stego_round_trip_works}"),
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
    dest.parent.mkdir(parents=True, exist_ok=True)
    encoded = urllib.parse.quote(url, safe=":/")
    req = urllib.request.Request(encoded, headers={"User-Agent": "stegsuite-dev"})
    with urllib.request.urlopen(req, timeout=120) as r:  # noqa: S310
        dest.write_bytes(r.read())


def all_cases(extra: bool = False, gaps: bool = False) -> list[tuple[str, list[tuple[str, str]], str]]:
    """Every case as (label, [(file name, url)], expected flag)."""
    cases = [(name, [(name, url)], expect) for name, url, expect in CASES]
    cases += [(label, files, expect) for label, files, expect in MULTI]
    if extra or gaps:
        import real_challenges_extra as rx
        for name, url, expect in (rx.EXTRA if extra else []) + (rx.GAPS if gaps else []):
            cases.append((name, [(name, url)], expect))
    return cases


def run(label: str, files: list[tuple[str, str]], expect: str) -> dict:
    d = DEST / label if len(files) > 1 else DEST
    paths = []
    for name, url in files:
        download(url, d / name)
        paths.append(d / name)
    res = ss.analyze(paths, "auto")
    flags = res["flags"]
    # a flag must never be a fragment of a longer one (e.g. CTF{x} in picoCTF{x})
    fragments = [fl for fl in flags if any(fl != o and fl in o for o in flags)]
    ok = any(expect in fl for fl in flags) and not fragments
    extra = f" fragments={fragments}" if fragments else ""
    print(f"  [{'PASS' if ok else 'FAIL'}] {label:<18} {res['seconds']:>6}s status={res['status']} "
          f"expect={expect} got={flags[:3]}{extra}", flush=True)
    return {"label": label, "ok": ok, "expect": expect, **res}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Real CTF challenges against a running StegSuite.")
    ap.add_argument("-k", dest="match", default="", help="only cases whose label contains this")
    ap.add_argument("-j", dest="jobs", type=int, default=1, help="cases analysed in parallel")
    ap.add_argument("--extra", action="store_true", help="also run real_challenges_extra.EXTRA")
    ap.add_argument("--gaps", action="store_true", help="also run the known-gap backlog (GAPS)")
    ap.add_argument("--only-new", action="store_true", help="skip the core CASES/MULTI")
    ap.add_argument("--json-out", type=Path, help="write per-case results (timing included)")
    args = ap.parse_args(argv)

    core = len(all_cases())
    cases = all_cases(args.extra, args.gaps)[core if args.only_new else 0:]
    cases = [c for c in cases if args.match in c[0]]
    print(f"* {len(cases)} real challenges against {API} (jobs={args.jobs})", flush=True)
    with ThreadPoolExecutor(max(1, args.jobs)) as pool:
        results = list(pool.map(lambda c: run(*c), cases))
    passed = sum(r["ok"] for r in results)
    total_s = round(sum(r["seconds"] for r in results), 1)
    print(f"* {passed}/{len(results)} passed · {total_s}s of analysis")
    if args.json_out:
        args.json_out.write_text(json.dumps(results, indent=2, ensure_ascii=False))
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
