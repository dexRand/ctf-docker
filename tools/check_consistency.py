#!/usr/bin/env python3
"""Keep compose.yaml, .env.example, the dashboard, ./ctf and the StegSuite
service catalog in sync (AGENTS.md: "update them together").

Checks, for every published port variable `${X_PORT:-n}` in compose.yaml:
  * .env.example defines X_PORT with the same default
  * ./ctf's SERVICES table knows it (urls/open), unless it is backend-only
and for every service with a host port:
  * config/homepage/services.yaml has a card for its container
Exits 1 with a list of problems. Stdlib only (no YAML parser needed).
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# published but deliberately not in ./ctf urls (API-only / internal)
NOT_IN_CTF = {"HASHTOPOLIS_BACKEND_PORT", "WIRESHARK_HTTPS_PORT"}
# services with a port but no dashboard card (reached through another card)
NOT_ON_DASHBOARD = {"hashtopolis-backend", "rev-proxy"}


def compose_ports(text: str) -> dict[str, tuple[str, int]]:
    """{PORT_VAR: (service, default)} from `${BIND..}:${VAR:-n}:...` lines."""
    out: dict[str, tuple[str, int]] = {}
    service = ""
    for line in text.splitlines():
        m = re.match(r"^  ([a-z][a-z0-9-]*):\s*$", line)
        if m:
            service = m.group(1)
        for var, default in re.findall(r"\$\{([A-Z_]+_PORT):-(\d+)\}:\d+", line):
            out[var] = (service, int(default))
    return out


def main() -> int:
    problems: list[str] = []
    compose = (ROOT / "compose.yaml").read_text()
    env = (ROOT / ".env.example").read_text()
    ctf = (ROOT / "ctf").read_text()
    dash = (ROOT / "config/homepage/services.yaml").read_text()
    catalog = (ROOT / "app/backend/services.py").read_text()

    env_vals = dict(re.findall(r"(?m)^([A-Z_]+_PORT)=(\d+)", env))
    ports = compose_ports(compose)
    for var, (service, default) in sorted(ports.items()):
        if var not in env_vals:
            problems.append(f".env.example: missing {var} (service {service})")
        elif int(env_vals[var]) != default:
            problems.append(f".env.example: {var}={env_vals[var]} but compose default is {default}")
        if var not in NOT_IN_CTF and f"|{var}|{default}|" not in ctf:
            problems.append(f"ctf SERVICES: no row for {var} (default {default})")
        if service not in NOT_ON_DASHBOARD and f"container: ctf-{service}-1" not in dash:
            problems.append(f"homepage services.yaml: no card for container ctf-{service}-1")
        if service not in NOT_ON_DASHBOARD and var not in NOT_IN_CTF \
                and var.endswith(("_PORT",)) and var not in catalog and "PROXY" not in var:
            problems.append(f"app/backend/services.py: {var} not in the catalog")
    for hard in sorted(set(re.findall(r"localhost:(190\d\d)", dash))):
        problems.append(f"homepage services.yaml: hardcoded port {hard} (use {{{{HOMEPAGE_VAR_*}}}})")

    for p in problems:
        print("[x]", p)
    print(f"[{'x' if problems else 'ok'}] {len(ports)} published ports checked, {len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
