"""Catalog of the toolbox's web tools (for the API, the MCP server and agents).

Host URLs follow the *_PORT values from .env (compose passes the file in);
`up` is checked from inside the Compose network by service name.
"""
from __future__ import annotations

import os
import urllib.request
from concurrent.futures import ThreadPoolExecutor

# key, name, what it is for, profile ('' = core), host port var, default port,
# path, internal "service:port" on ctfnet
SERVICES = [
    ("dashboard", "Homepage", "dashboard of every tool", "", "HOMEPAGE_PORT", 19001, "/", "homepage:3000"),
    ("stegsuite", "StegSuite", "automatic stego/forensics analysis, CTF projects, cracking (this API)",
     "", "STEGSUITE_PORT", 19014, "/", "127.0.0.1:19014"),
    ("files", "FileBrowser", "browse ./data (projects, extracted files, reports)", "",
     "FILEBROWSER_PORT", 19012, "/", "filebrowser:80"),
    ("cyberchef", "CyberChef", "encodings, crypto, data transforms (recipes)", "",
     "CYBERCHEF_PORT", 19002, "/", "cyberchef:8080"),
    ("mitmweb", "mitmproxy", "intercepting HTTP(S) proxy UI (proxy on MITMPROXY_PORT)", "",
     "MITMWEB_UI_PORT", 19003, "/", "mitmproxy:8081"),
    ("it-tools", "IT-Tools", "small dev/network utilities", "", "ITTOOLS_PORT", 19011, "/", "it-tools:80"),
    ("dork", "Dork generator", "search-engine dorks from a target", "", "DORK_PORT", 19019, "/", "dork:80"),
    ("term", "Terminal", "shell in any toolbox container (StegSuite, rev, ...)", "", "TERM_PORT", 19022,
     "/", "term:7681"),
    ("zap", "OWASP ZAP", "web app scanner + proxy", "web", "ZAP_UI_PORT", 19005, "/zap", "zap:8080"),
    ("spiderfoot", "SpiderFoot", "OSINT / recon automation", "recon", "SPIDERFOOT_PORT", 19007,
     "/spiderfoot/", "spiderfoot:8080"),
    ("wireshark", "Wireshark", "packet analysis GUI", "forensics", "WIRESHARK_HTTP_PORT", 19008, "/",
     "wireshark:3000"),
    ("sagemath", "SageMath", "math/crypto notebooks", "crypto", "SAGEMATH_PORT", 19010, "/", "sagemath:8888"),
    ("hashtopolis", "Hashtopolis", "distributed hashcat", "crack", "HASHTOPOLIS_FRONTEND_PORT", 19016, "/",
     "hashtopolis-frontend:80"),
    ("whisper", "Whisper-WebUI", "speech-to-text with timestamps", "audio", "WHISPER_PORT", 19017, "/",
     "whisper:7860"),
    ("rev", "rev sandbox", "isolated reversing/pwn terminal (ELF/PE/APK, Ghidra, gdb)", "rev",
     "REV_PORT", 19018, "/", "rev-proxy:7681"),
    ("rev-web", "rev workbench", "browser workbench: auto report, Unicorn emulation, brute", "rev",
     "REV_WEB_PORT", 19020, "/", "rev-web-proxy:8080"),
    ("shell", "shell", "pure terminal with panes/tabs (zellij), every sandbox tool", "rev",
     "SHELL_PORT", 19021, "/", "shell:7681"),
]


def _up(internal: str, path: str) -> bool:
    try:
        with urllib.request.urlopen(f"http://{internal}{path}", timeout=1.5):  # noqa: S310 (internal)
            return True
    except urllib.error.HTTPError:
        return True        # it answered (401/404 still means the service is up)
    except OSError:
        return False


def catalog(check: bool = True) -> list[dict]:
    rows = [{"key": k, "name": n, "description": d, "profile": prof or "core",
             "url": f"http://localhost:{os.environ.get(var) or port}{path}",
             "_internal": internal, "_path": path}
            for k, n, d, prof, var, port, path, internal in SERVICES]
    if check:
        with ThreadPoolExecutor(len(rows)) as pool:
            for row, up in zip(rows, pool.map(lambda r: _up(r["_internal"], r["_path"]), rows)):
                row["up"] = up
    for row in rows:
        row.pop("_internal"), row.pop("_path")
    return rows
