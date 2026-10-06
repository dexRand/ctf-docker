#!/usr/bin/env python3
"""StegSuite CTF regression suite.

Generates deterministic challenge fixtures (one per tool category) and drives
the running API in Auto mode, asserting the expected flag is found.

Run inside the StegSuite container:
    /opt/stegsuite/venv/bin/python /opt/stegsuite/tests/ctf_regression.py
or on the host against a running instance:
    STEGSUITE=http://localhost:19014 python3 app/tests/ctf_regression.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

BASE = os.environ.get("STEGSUITE", "http://127.0.0.1:19014")
API = BASE + "/api/v1"
TMP = Path("/tmp/ctfreg")
TMP.mkdir(parents=True, exist_ok=True)


def sh(cmd: str) -> None:
    subprocess.run(cmd, shell=True, check=True, capture_output=True)


def _multipart(field_files: list[tuple[str, Path]], fields: dict) -> tuple[bytes, str]:
    boundary = "----stegsuite"
    body = b""
    for k, v in fields.items():
        body += (f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n").encode()
    for _name, path in field_files:
        body += (f"--{boundary}\r\nContent-Disposition: form-data; name=\"files\"; "
                 f"filename=\"{path.name}\"\r\nContent-Type: application/octet-stream\r\n\r\n").encode()
        body += path.read_bytes() + b"\r\n"
    body += f"--{boundary}--\r\n".encode()
    return body, boundary


def api(path: str, method: str = "GET", data=None, ctype=None):
    req = urllib.request.Request(API + path, data=data, method=method)
    if ctype:
        req.add_header("Content-Type", ctype)
    with urllib.request.urlopen(req, timeout=120) as r:
        raw = r.read()
    return json.loads(raw) if raw and raw[:1] in (b"{", b"[") else raw.decode(errors="replace")


def make_fixtures() -> list[tuple[str, Path, str]]:
    cases: list[tuple[str, Path, str]] = []
    # 1) plaintext -> strings
    p = TMP / "strings.txt"
    p.write_text("benvenuto ITS{strings_flag_1} fine\n")
    cases.append(("strings", p, "ITS{strings_flag_1}"))

    # 2) exif -> exiftool
    p = TMP / "exif.jpg"
    sh(f"convert -size 96x96 xc:navy {p}")
    sh(f"exiftool -overwrite_original -Artist='ITS{{exif_flag_2}}' {p}")
    cases.append(("exif", p, "ITS{exif_flag_2}"))

    # 3) zip appended to a PNG -> binwalk -e + 7z
    sh(f"cd {TMP} && printf 'ITS{{appended_zip_3}}' > f3.txt && rm -f a3.zip && zip -q a3.zip f3.txt")
    p = TMP / "appended.png"
    sh(f"convert -size 64x64 xc:red {p} && cat {TMP}/a3.zip >> {p}")
    cases.append(("binwalk", p, "ITS{appended_zip_3}"))

    # 4) AES-256 ZIP -> fcrackzip/hashcat (secret123 is in passwords.txt)
    sh(f"cd {TMP} && printf 'ITS{{aes_zip_4}}' > f4.txt && rm -f a4.zip && "
       f"7z a -tzip -mem=AES256 -psecret123 a4.zip f4.txt")
    cases.append(("aes-zip", TMP / "a4.zip", "ITS{aes_zip_4}"))

    # 5) steghide JPEG (password ctf)
    p = TMP / "stego.jpg"
    sh(f"cd {TMP} && convert -size 512x512 xc: +noise Random n.png && convert n.png {p} && "
       f"printf 'ITS{{steghide_5}}' > s5.txt && steghide embed -cf {p} -ef s5.txt -p ctf -f")
    cases.append(("steghide", p, "ITS{steghide_5}"))

    # 6) animated GIF with a visible flag -> gif-frames + OCR
    from PIL import Image, ImageDraw
    frames = []
    for text, color in [("intro", "black"), ("ITS{gif_frame_6}", "red"), ("end", "black")]:
        im = Image.new("RGB", (400, 140), "white")
        ImageDraw.Draw(im).text((15, 55), text, fill=color)
        frames.append(im)
    p = TMP / "anim.gif"
    frames[0].save(p, save_all=True, append_images=frames[1:], duration=250, loop=0)
    cases.append(("gif-frames", p, "ITS{gif_frame_6}"))

    # 7) flag in a PNG tEXt chunk -> png-chunks
    from PIL import Image, ImageDraw
    from PIL.PngImagePlugin import PngInfo
    p = TMP / "chunked.png"
    meta = PngInfo()
    meta.add_text("Comment", "nothing here")
    meta.add_text("flag", "ITS{png_chunk_7}")
    Image.new("RGB", (80, 80), "white").save(p, pnginfo=meta)
    cases.append(("png-chunks", p, "ITS{png_chunk_7}"))

    # 8) base64(rot13(flag)) -> decode
    import base64, codecs
    inner = codecs.encode("ITS{decode_8}", "rot13")
    p = TMP / "encoded.txt"
    p.write_text(base64.b64encode(inner.encode()).decode())
    cases.append(("decode", p, "ITS{decode_8}"))

    # 9) Morse of base64(flag) -> morse-text + layer chain (Dashed style)
    table = {v: k for k, v in {
        ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F", "--.": "G",
        "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L", "--": "M", "-.": "N",
        "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T", "..-": "U",
        "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y", "--..": "Z", "-----": "0",
        ".----": "1", "..---": "2", "...--": "3", "....-": "4", ".....": "5", "-....": "6",
        "--...": "7", "---..": "8", "----.": "9", "-...-": "=", ".-.-.": "+",
    }.items()}
    # Morse is case-insensitive, so encode the flag as HEX (like the real Dashed
    # challenge: Morse -> hex -> binary -> base64 -> rot13).
    hexs = b"ITS{morse_layer_9}".hex().upper()
    morse = " ".join(table.get(c, "/") for c in hexs)
    p = TMP / "dashed.txt"
    p.write_text(morse)
    cases.append(("morse-text", p, "ITS{morse_layer_9}"))

    # 10) flag drawn in the red LSB only -> bit-planes + OCR
    import numpy as np
    mask_img = Image.new("1", (200, 60), 0)
    ImageDraw.Draw(mask_img).text((2, 20), "ITS{lsb_10}", fill=1)
    mask = np.array(mask_img.resize((800, 240), Image.NEAREST)).astype("uint8")
    h, w = mask.shape
    host = np.random.default_rng(1).integers(120, 160, size=(h, w, 3), dtype="uint8")
    host[:, :, 0] = (host[:, :, 0] & 0xFE) | mask
    p = TMP / "lsb.png"
    Image.fromarray(host).save(p)
    cases.append(("bit-planes", p, "ITS{lsb_10}"))

    # 11) flag in the brightest pixels -> image-enhance + OCR
    im = Image.new("RGB", (600, 150), (250, 250, 250))
    ImageDraw.Draw(im).text((10, 60), "ITS{enhance_11}", fill=(242, 242, 242))
    p = TMP / "highlights.png"
    im.save(p)
    cases.append(("image-enhance", p, "ITS{enhance_11}"))

    # 12) Dashed-style: 0x30/0x31 -> binary -> base64 -> rot13 -> flag
    r13 = codecs.encode("ITS{dashed_12}", "rot13")
    b64 = base64.b64encode(r13.encode()).decode()
    binstr = "".join(f"{ord(c):08b}" for c in b64)
    tokens = ",".join("0x30" if bit == "0" else "0x31" for bit in binstr)
    p = TMP / "dashed_chain.txt"
    p.write_text(tokens)
    cases.append(("decode-chain", p, "ITS{dashed_12}"))

    # 13) QR code containing the flag -> qr (zbarimg)
    qr = TMP / "qr.png"
    try:
        sh(f'qrencode -o {qr} "ITS{{qr_13}}"')
        if qr.is_file():
            cases.append(("qr", qr, "ITS{qr_13}"))
    except subprocess.CalledProcessError:
        pass

    # 14) flag in the LSB of WAV samples -> wav-lsb
    import struct as _struct
    import wave as _wave

    def _wav_with_lsb(path: Path, text: str) -> None:
        bits = [(ord(c) >> i) & 1 for c in text for i in range(8)]
        with _wave.open(str(path), "wb") as w:
            w.setnchannels(1)
            w.setsampwidth(2)
            w.setframerate(8000)
            w.writeframes(_struct.pack("<" + "h" * 1000, *([0] * 1000)))
            w.writeframes(_struct.pack("<" + "h" * len(bits), *[(0x100 | b) for b in bits]))

    p = TMP / "lsb.wav"
    _wav_with_lsb(p, "ITS{wav_lsb_14}")
    cases.append(("wav-lsb", p, "ITS{wav_lsb_14}"))

    # 15) HTTP request with the flag in the URI -> pcap (tshark)
    def _pcap_http(path: Path, uri: str) -> None:
        payload = f"GET {uri} HTTP/1.1\r\nHost: ctf.local\r\n\r\n".encode()
        eth = b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + b"\x08\x00"
        src, dst = b"\x0a\x00\x00\x01", b"\x0a\x00\x00\x02"
        total = 20 + 20 + len(payload)
        ip = _struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1, 0, 64, 6, 0, src, dst)

        def cksum(h: bytes) -> int:
            s = 0
            for i in range(0, len(h), 2):
                s += (h[i] << 8) + (h[i + 1] if i + 1 < len(h) else 0)
            while s >> 16:
                s = (s & 0xFFFF) + (s >> 16)
            return (~s) & 0xFFFF

        ip = ip[:10] + _struct.pack("!H", cksum(ip)) + ip[12:]
        tcp = _struct.pack("!HHLLBBHHH", 12345, 80, 1, 0, 0x50, 0x18, 0xFFFF, 0, 0)
        frame = eth + ip + tcp + payload
        gh = _struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        rec = _struct.pack("<IIII", 0, 0, len(frame), len(frame)) + frame
        path.write_bytes(gh + rec)

    p = TMP / "http.pcap"
    _pcap_http(p, "/ITS{pcap_15}")
    cases.append(("pcap", p, "ITS{pcap_15}"))

    # 16) the real challenge.png (1x1 PNG + AES zip appended). Password "robot"
    #     is cracked by 10k-most-common.txt: cracking concatenates the image's
    #     wordlists smallest->largest (/wordlists + /opt/wordlists) and stops at
    #     the first hit; "robot" is on line 5387 of 10k-most-common.txt
    fixtures = Path(os.environ.get("FIXTURES_DIR", "/tmp/fixtures"))
    real = fixtures / "challenge.png"
    if real.is_file():
        cases.append(("real-challenge", real, "ITS{stego_z1p_appended}"))

    # 17) BMP with a corrupt header (offset/DIB = 0xD0BA, declared height 1):
    #     image-repair rebuilds it, then OCR reads the drawn flag
    from PIL import Image, ImageDraw

    def _corrupt_bmp(path: Path, text: str, width: int = 400, height: int = 60) -> None:
        im = Image.new("RGB", (width, height), (20, 20, 20))
        ImageDraw.Draw(im).text((10, height // 2 - 8), text, fill="white")
        im.save(path)
        raw = bytearray(path.read_bytes())
        raw[10:14] = (0xD0BA).to_bytes(4, "little")  # pixel-data offset
        raw[14:18] = (0xD0BA).to_bytes(4, "little")  # DIB header size
        raw[22:26] = (1).to_bytes(4, "little")       # height
        path.write_bytes(raw)

    p = TMP / "corrupt.bmp"
    _corrupt_bmp(p, "ITS{repair_17}")
    cases.append(("image-repair", p, "ITS{repair_17}"))

    # 18) DNS tunneling: the flag, base32-encoded, split into subdomain labels
    #     of queries to a shared base domain -> pcap dns tunneling decoder
    import base64 as _b64

    def _pcap_dns(path: Path, queries: list[str]) -> None:
        def frame(qname: str, ident: int) -> bytes:
            dns_hdr = _struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0)
            qname_b = b"".join(bytes([len(l)]) + l.encode() for l in qname.split(".")) + b"\x00"
            dns = dns_hdr + qname_b + _struct.pack("!HH", 1, 1)
            udp = _struct.pack("!HHHH", 0xC000 + ident, 53, 8 + len(dns), 0)
            udp_len = len(udp) + len(dns)
            total = 20 + udp_len
            src, dst = b"\x0a\x00\x00\x01", b"\x08\x08\x08\x08"
            ip = _struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1, 0, 64, 17, 0, src, dst)

            def cksum(h: bytes) -> int:
                s = sum((h[i] << 8) + (h[i + 1] if i + 1 < len(h) else 0)
                        for i in range(0, len(h), 2))
                while s >> 16:
                    s = (s & 0xFFFF) + (s >> 16)
                return (~s) & 0xFFFF

            ip = ip[:10] + _struct.pack("!H", cksum(ip)) + ip[12:]
            eth = b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + b"\x08\x00"
            return eth + ip + udp + dns

        gh = _struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        recs = b"".join(
            _struct.pack("<IIII", 0, 0, len(f), len(f)) + f
            for f in (frame(q, i) for i, q in enumerate(queries))
        )
        path.write_bytes(gh + recs)

    flag18 = "ITS{dns_tunnel_18}"
    enc18 = _b64.b32encode(flag18.encode()).decode()
    _pcap_dns(TMP / "tunnel.pcap", [enc18[i:i + 5] + ".exfil.ctf"
                                    for i in range(0, len(enc18), 5)])
    cases.append(("dns-tunnel", TMP / "tunnel.pcap", flag18))

    return cases


def run_case(name: str, path: Path, expect: str) -> bool:
    body, boundary = _multipart([("files", path)], {"mode": "auto"})
    p = api("/projects", "POST", body, f"multipart/form-data; boundary={boundary}")
    pid = p["id"]
    api(f"/projects/{pid}/start", "POST", b"", "application/json")
    status = "?"
    for _ in range(150):
        status = api(f"/projects/{pid}")["status"]
        if status in ("done", "error", "cancelled"):
            break
        time.sleep(2)
    flags = [f["value"] for f in api(f"/projects/{pid}/findings") if f["kind"] == "flag"]
    ok = any(expect in fl for fl in flags)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name:<10} expected {expect:<22} status={status} flags={flags[:3]}")
    return ok


def main() -> int:
    print(f"* StegSuite CTF regression against {BASE}")
    cases = make_fixtures()
    results = [run_case(n, p, e) for n, p, e in cases]
    passed, total = sum(results), len(results)
    print(f"* {passed}/{total} passed")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
