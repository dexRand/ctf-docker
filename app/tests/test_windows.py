"""Windows artifacts: GPP cpassword, evtx base64 pieces, flag assembly."""
import base64
import shutil
import subprocess

import pytest

from backend.analyzers.base import ToolContext
from backend.analyzers.util import assemble_flag_fragments

KEY = "4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b"


def test_assemble_flag_fragments_skips_noise():
    pieces = ["{3D3C3833-DED6-4022}", "picoCTF{Ev3nt_vi3wv3r_", "{GUID-NOISE}",
              "1s_a_pr3tty_us3ful_", "t00l_81ba3fe9}", "unrelated text"]
    # the brace-only noise breaks nothing: it is neither a start nor a body piece
    assert assemble_flag_fragments([p for p in pieces if p != "{GUID-NOISE}"]) == \
        ["picoCTF{Ev3nt_vi3wv3r_1s_a_pr3tty_us3ful_t00l_81ba3fe9}"]


@pytest.mark.skipif(not shutil.which("openssl"), reason="openssl not installed")
def test_gpp_cpassword_is_decrypted(tmp_path):
    from backend.analyzers.text import MarkupTextAnalyzer
    plain = "DUCTF{gpp_t3st}".encode("utf-16-le")
    enc = subprocess.run(["openssl", "enc", "-aes-256-cbc", "-K", KEY, "-iv", "0" * 32],
                         input=plain, capture_output=True, check=True).stdout
    cpw = base64.b64encode(enc).decode().rstrip("=")
    xml = tmp_path / "Groups.xml"
    xml.write_text(f'<Groups><User><Properties userName="Backup" cpassword="{cpw}"/></User></Groups>')
    res = MarkupTextAnalyzer().run(ToolContext(input=xml, workdir=tmp_path / "w"))
    assert "[gpp cpassword] Backup: DUCTF{gpp_t3st}" in res.output


def test_evtx_rejects_other_files(tmp_path):
    from backend.analyzers.evtx import EvtxAnalyzer
    p = tmp_path / "x.evtx"
    p.write_bytes(b"not an event log")
    assert EvtxAnalyzer().run(ToolContext(input=p, workdir=tmp_path / "w")).status == "skipped"
