<h1 align="center">CTF Toolbox</h1>

<p align="center">
  Self-hosted, browser-based toolkit for <strong>solving CTFs</strong>.
  <br>
  One dashboard, the essential tools with a web GUI, and a single
  <code>docker compose up</code>.
</p>

<p align="center">
  <a href="README.md">🇬🇧 English</a> · <a href="README.it.md">🇮🇹 Italiano</a>
</p>

<p align="center">
  <a href="https://github.com/dexRand/ctf-docker/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/dexRand/ctf-docker/actions/workflows/ci.yml/badge.svg"></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white" alt="Docker Compose">
  <img src="https://img.shields.io/badge/ports-19000%2B-6E56CF" alt="Ports 19000+">
  <img src="https://img.shields.io/badge/images-upstream--only-informational" alt="Upstream images only">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT">
</p>

---

**CTF Toolbox** is a Docker Compose stack that bundles the tools people actually
reach for during a Capture The Flag event — steganalysis, encoding/crypto, web
interception, OSINT, forensics and password work — each with a **web interface**,
behind a single dashboard that lists them **ordered by phase of work** with a
short description and live status.

It is designed to live next to other self-hosted apps: every service runs on the
**19000+ port range** so it will not collide with the usual suspects (8080, 9000,
5432, …), and the heavy tools sit behind optional Compose **profiles**.

## ✨ Features

- **Single dashboard** ([Homepage](https://gethomepage.dev)) showing every tool,
  grouped by CTF phase, with a description and an up/down indicator.
- **Web GUI everywhere** — no X11 forwarding, no desktop installs.
- **Upstream images only** — no custom builds to maintain; every image is a real,
  actively used project and was verified before being added.
- **Optional heavy tools** (ZAP, Wireshark, SageMath, SpiderFoot) behind Compose
  profiles, so `./ctf up` stays light.
- **No port collisions** — everything on 19000+, all overridable from `.env`.
- **Isolated stack** — project name `ctf`, no fixed container names; the
  AperiSolve `postgres`/`redis` are internal and never publish a port.

## 🧰 Tools

| Phase | Tool | URL | What it is for | Profile |
| --- | --- | --- | --- | --- |
| Dashboard | Homepage | http://localhost:19001 | Overview and status of every tool | core |
| Stego | **AperiSolve** | http://localhost:19000 | Image steganalysis: binwalk, zsteg, steghide, exiftool, foremost… | core |
| Crypto/Encoding | **CyberChef** | http://localhost:19002 | Base64, XOR, RSA, hashing, JWT and much more | core |
| Web | **mitmproxy** | http://localhost:19003 | Intercept and rewrite HTTP(S) · proxy on `:19004` | core |
| Utility | IT-Tools | http://localhost:19011 | Encoders, converters, hashes, regex and friends | core |
| Deep triage | **CTF Triage** | http://localhost:19013 | Recursive extract + wordlist cracking + flag hunt · Auto/Check GUI, reports in FileBrowser Quantum (`./ctf triage <file>`) | core |
| Stego workbench | **StegSuite** | http://localhost:19014 | Recursive auto/triage over 29 tools (stego, forensics, vision/OCR, audio/Morse), file tree, live log, embedded terminal, REST API | core |
| Web | **OWASP ZAP** | http://localhost:19005/zap | Web security scanner with an in-browser GUI · proxy on `:19006` | `web` |
| Recon | SpiderFoot | http://localhost:19007/spiderfoot/ | OSINT automation: domains, IPs, e-mails, leaks | `recon` |
| Crypto | SageMath | http://localhost:19010 | Python/Sage notebook for crypto and math | `crypto` |
| Forensics | Wireshark | http://localhost:19008 | Packet / pcap analysis with a web GUI | `forensics` |

> Deliberately excluded because they have no reliable upstream GUI image:
> Burp Suite, Ghidra, Autopsy, Volatility, hashcat/john (CLI tools, already on Kali).
> Distributed hash cracking (Hashtopolis) is on the roadmap.

## 🚀 Quick start

```bash
git clone https://github.com/dexRand/ctf-docker.git
cd ctf-docker
cp .env.example .env      # optional: ./ctf creates it automatically
./ctf up
```

Then open the dashboard: **http://localhost:19001**

### With plain Docker Compose

```bash
docker compose up -d                              # core tools
docker compose --profile web up -d                # core + OWASP ZAP
docker compose --profile web --profile recon up -d
docker compose down                               # stop everything
```

## 🎛️ CLI

The small `ctf` wrapper is a thin, readable layer over Compose:

```bash
./ctf up                  # core tools
./ctf up web              # core + a profile
./ctf up web forensics    # combine profiles
./ctf up-all              # everything (heavy: several GB of images)
./ctf status              # container status
./ctf logs wireshark      # follow logs of one service
./ctf triage <file>       # deep recursive triage (see below)
./ctf reports             # URL + credentials of the report browser
./ctf down                # stop and remove containers
```

## 🔬 Deep triage

`./ctf triage <file|directory>` runs a full steg/forensic pipeline in a
container built on top of the AperiSolve image, and writes a report you can
browse in **FileBrowser Quantum** (http://localhost:19012, no login).

There is also a **web GUI** at **http://localhost:19013** (linked from the
dashboard) with two modes:

- **Auto** — runs everything and tries every wordlist on its own;
- **Check** — scans first, then shows the file tree and the locked items and
  lets you choose, per item, which wordlist to use (or skip).

It automatically:

1. **recurses**: `7z`, `binwalk -e`, `foremost` on every extracted file, until
   the tree is exhausted (bounded depth);
2. **analyses** each file: `strings`, `exiftool`, `zsteg`, `steghide`, `pdfinfo`…;
3. **hunts flags** with sensible patterns (`ITS{}`, `flag{}`, `CTF{}`, `HTB{}`,
   `picoCTF{}` + a generic one on printable text);
4. when it hits something **password-locked** (encrypted zip/7z/PDF, or an image
   that may hide a steghide payload) it **stops and asks you which wordlist to
   use**.

Password attacks use the right tool per format — `stegseek` (steghide),
`fcrackzip` + **`hashcat`** (ZIP, including **AES-256** via the vendored
`zip2hashcat`), `pdfcrack` (PDF) — and wordlists are tried
**smallest → largest** so the fast dictionaries run first. Any password found is
reused automatically for the remaining files.

```bash
./ctf triage ./challenge.png            # interactive: asks which wordlist
./ctf triage ./challenge.png -w wordlists/rockyou.txt
./ctf triage ./challenge.png --yes      # no prompt: try all lists, small→large
./ctf triage ./dir --no-crack --depth 4 # no password attacks
```

The most-used wordlists are already included, ordered smallest → largest:
`passwords.txt`, `500-worst-passwords`, `probable-v2_top-1575`,
`10k-most-common`, `darkweb2017_top-10000`, `rockyou-75` (in the repo) and the
full **rockyou.txt** (14M entries, baked into the image). Put extra dictionaries
in `./wordlists/` (mounted read-only at `/wordlists`); they show up in the menu
automatically, sorted by size.

| Profile | Adds |
| --- | --- |
| *(core)* | Homepage, AperiSolve, CyberChef, mitmproxy, IT-Tools |
| `web` | OWASP ZAP |
| `recon` | SpiderFoot |
| `crypto` | SageMath |
| `forensics` | Wireshark |

## 🔌 Ports

All host ports live in the **19000+ range** and are configurable in `.env`:

| Port | Service |
| ---: | --- |
| 19000 | AperiSolve |
| 19001 | Homepage (dashboard) |
| 19002 | CyberChef |
| 19003 / 19004 | mitmweb UI / mitmproxy |
| 19005 / 19006 | ZAP UI (`/zap`) / ZAP proxy |
| 19007 | SpiderFoot |
| 19008 / 19009 | Wireshark HTTP / HTTPS |
| 19010 | SageMath (Jupyter) |
| 19011 | IT-Tools |
| 19012 | FileBrowser Quantum (triage reports, no login, localhost only) |
| 19013 | Triage web GUI (Auto/Check, localhost only) |
| 19014 | StegSuite workbench + API (localhost only) |
| 19181 | RQ Dashboard (AperiSolve, localhost only) |

## 📂 Project structure

```
compose.yaml            services definition (project name: ctf)
ctf                     CLI wrapper (up / up-all / down / status / logs)
.env.example            ports and configuration
config/homepage/        dashboard config (services / settings / widgets)
config/zap/             ZAP working dir (certificates)
SPEC.md                 specification
tasks/                  plan.md + todo.md
.opencode/              Agent Skills (MIT — see ATTRIBUTION.md)
```

## 🧪 StegSuite (stego workbench)

**StegSuite** is the all-in-one stego/forensics app (the AperiSolve replacement):
http://localhost:19014 (localhost only).

- **Auto / Check** modes: Auto runs everything and tries every wordlist; Check
  first scans, then lets you choose what to attack.
- **Recursive, ordered** analysis over **31 tools**: `file`, `exiftool`,
  `identify`, `ffprobe`, `strings`, `xxd`/`hexdump`/`hexyl`, `binwalk`
  (scan + `binwalk -e`), `foremost`, `7z`, `zsteg`, `steghide`, `outguess`,
  `jsteg`, `openstego`, `bit-planes`, `channel-remap`, `gif-frames`
  (split + frame-diff + delay decode + per-frame OCR), `ocr` (tesseract),
  `qr` (zbarimg), `png-chunks`, `png-repair`, `morse`, `dtmf`,
  `spectrogram`, `waveform`, `pngcheck`, `pdfid`, `pdftotext`.
- **GUI**: file tree, per-tool output, extracted children, image/audio
  previews, live log over WebSocket, and an embedded **terminal** (xterm.js).
- **Flag hunt + cracking**: ZIP (incl. AES via hashcat), steghide, PDF.
- **REST API** (OpenAPI at `/api/docs`), including stateless single-tool runs:
  `POST /api/v1/tools/{tool}`.
- **Docs**: `docs/ADDING-A-TOOL.md` (add an analyzer), `docs/API.md` (drive the
  API from other projects), `docs/CHALLENGES.md` (reference challenges + flags
  used to verify the suite, with manual solve commands).

## ⚙️ Configuration

Everything is driven by `.env` (created from `.env.example`):

| Variable | Purpose |
| --- | --- |
| `*_PORT` | Host port of each service (all in 19000+) |
| `HOMEPAGE_ALLOWED_HOSTS` | Hosts allowed to reach the dashboard (add your LAN IP for remote access) |
| `MITMWEB_PASSWORD` | Password for the mitmweb GUI (user is ignored) |
| `WORDLIST` | Default wordlist used by the triage pipeline |
| `PUID` / `PGID` / `TZ` | User mapping and timezone for Wireshark |
| `POSTGRES_*`, `DB_URI`, `REDIS_URL` | AperiSolve internal database/broker (not exposed) |

## 📝 Notes

- **First start** pulls large images (ZAP, Wireshark, SageMath): give it time.
  Running *all* profiles at once needs roughly **8 GB of free RAM**.
- **SageMath** prints its Jupyter access token in the logs:
  `./ctf logs sagemath`.
- **mitmproxy** requires a password: the login page uses `MITMWEB_PASSWORD`
  (default `mitm`). Its dashboard status checks an unauthenticated endpoint.
- **Profiled tools** show up as *down* on the dashboard until you start that
  profile — that is expected.
- The **triage** image is the only one built locally (from the AperiSolve image,
  adding `stegseek`, `john`, `fcrackzip`, `pdfcrack`); the first `./ctf up`
  builds it once.
- **FileBrowser Quantum** (the maintained fork of the archived FileBrowser) is
  bound to `127.0.0.1` only and runs with **no login** (`auth.methods.noauth`).
- AperiSolve runs its own internal `postgres` and `redis`; they are **not**
  published on the host and do not touch other databases.

## 🤖 Agent Skills

The skills under `.opencode/skills/` come from
[`addyosmani/agent-skills`](https://github.com/addyosmani/agent-skills) (MIT).
See [`.opencode/ATTRIBUTION.md`](.opencode/ATTRIBUTION.md) and
[`AGENTS.md`](AGENTS.md).

## 📚 Documentation

- Specification: [`SPEC.md`](SPEC.md)
- Plan and tasks: [`tasks/plan.md`](tasks/plan.md) · [`tasks/todo.md`](tasks/todo.md)
- Agent guide: [`AGENTS.md`](AGENTS.md)

## 📄 License

MIT — see [`LICENSE`](LICENSE) for the project, and
[`.opencode/LICENSE-agent-skills`](.opencode/LICENSE-agent-skills) for the
imported Agent Skills.
