# StegSuite API

Base: `http://localhost:19014/api/v1` · OpenAPI/Swagger: `/api/docs`
Everything the GUI does is available here: the SPA only calls these endpoints.

**Auth.** If `API_KEY` (env `STEGSUITE_API_KEY`) is set, every `/api` request
(except `/api/v1/health`) needs the key, as any of:

| Where | For |
|---|---|
| header `X-API-Key: <key>` | scripts, other containers, agents |
| cookie `stegsuite_key=<key>` | browser loads (`<img>`, downloads); the GUI sets it |
| query `?key=<key>` | WebSockets, quick links |

The GUI asks for the key on the first `401`. `./ctf scan` / `./ctf test` read it
from `.env`. Everything listens on `127.0.0.1` by default (`BIND_ADDR`).

## Use a single tool from another project (stateless)

Upload a file, get the tool output + downloadable artifacts. Great for wiring
StegSuite's tools into other pipelines.

```bash
# list available tools
curl -s localhost:19014/api/v1/tools | jq '.[].name'

# run one tool
curl -s -F file=@challenge.png localhost:19014/api/v1/tools/binwalk-extract | jq .
# → { tool, status, summary, output, artifacts:[{name,path,size}], job_id }

# crack a ZIP/PDF/steghide file with a wordlist (optional password)
curl -s -F file=@secret.zip -F password=secret123 localhost:19014/api/v1/tools/7z | jq .
```

Download an artifact produced by a stateless run:

```bash
curl -OJ "localhost:19014/api/v1/tooljobs/<job_id>/files/<artifact-name>"
```

## CTFs (one CTF = many challenges)

A CTF groups its challenges (each challenge is a project). Its `flag_format`
is used by the flag hunt of every challenge, and a flag in that format marks
the challenge **solved** automatically.

```bash
# create a CTF: flag_format is a prefix ("DUCTF" / "DUCTF{...}") or a regex
CID=$(curl -s -H 'Content-Type: application/json' \
        -d '{"name":"DownUnderCTF 2026","flag_format":"DUCTF{...}","url":"https://play.duc.tf"}' \
        localhost:19014/api/v1/ctfs | jq -r .id)

# add challenges (one upload = one challenge; start=true analyzes it now)
curl -s -F name="bad policies" -F category=forensics -F files=@badpolicies.zip \
     localhost:19014/api/v1/ctfs/$CID/challenges

# autosolver: analyze every unsolved challenge, 2 at a time
curl -s -X POST -H 'Content-Type: application/json' -d '{"parallel":2}' \
     localhost:19014/api/v1/ctfs/$CID/autosolve
curl -s localhost:19014/api/v1/ctfs/$CID/autosolve          # progress
curl -s -X DELETE localhost:19014/api/v1/ctfs/$CID/autosolve # stop queueing

# the scoreboard: challenges with status / solved / flag / flags found
curl -s localhost:19014/api/v1/ctfs/$CID | jq '.challenge_list[] | {name,status,solved,flag}'
curl -s localhost:19014/api/v1/ctfs | jq .                   # all CTFs + counters

# edit a challenge (confirm/correct the flag, move it to another CTF…)
curl -s -X PATCH -H 'Content-Type: application/json' \
     -d '{"solved":true,"flag":"DUCTF{...}","category":"misc"}' \
     localhost:19014/api/v1/projects/<pid>
```

`PATCH /ctfs/{cid}` edits name/flag_format/url/notes; `DELETE /ctfs/{cid}`
removes the CTF and keeps its challenges (detached).

## Projects (stateful, recursive)

```bash
# create (Auto = runs everything + auto-cracks; Check = waits for you)
# optional: -F ctf_id=<cid> -F category=forensics
PID=$(curl -s -F mode=auto -F files=@a.png -F files=@b.jpg \
        localhost:19014/api/v1/projects | jq -r .id)

# start / pause / resume / cancel (pause/resume show up as status paused/running)
curl -X POST localhost:19014/api/v1/projects/$PID/start
curl -X POST localhost:19014/api/v1/projects/$PID/pause
curl -X POST localhost:19014/api/v1/projects/$PID/resume
curl -X POST localhost:19014/api/v1/projects/$PID/cancel

# results
curl -s localhost:19014/api/v1/projects/$PID            | jq .      # project + tree
curl -s localhost:19014/api/v1/projects/$PID/findings   | jq .      # flags/passwords/notes
curl -s localhost:19014/api/v1/projects/$PID/runs       | jq .      # per-tool runs + artifacts
curl -s localhost:19014/api/v1/projects/$PID/events     | jq .      # log

# reports (built server-side: the same text the GUI shows)
curl -s localhost:19014/api/v1/projects/$PID/flags      | jq .      # each flag: chain of files + evidence
curl -s localhost:19014/api/v1/projects/$PID/summary    | jq .      # what the GUI highlights: route ids/steps/tree, solver runs, tools
curl -s "localhost:19014/api/v1/projects/$PID/report?lang=it"       # Markdown report (lang=en|it)
curl -s "localhost:19014/api/v1/projects/$PID/report?format=json" | jq .
curl -s localhost:19014/api/v1/projects/$PID/logs                   # event log + every run output
curl -s localhost:19014/api/v1/projects/$PID/transcript             # context for an AI agent

# re-run tools on one file (optionally with a password you found); 202, runs in background
curl -X POST -H 'Content-Type: application/json' \
     -d '{"tools":["steghide","outguess"],"password":"s3cret"}' \
     localhost:19014/api/v1/projects/$PID/files/<fid>/run

# file / artifact / tool output
curl -OJ localhost:19014/api/v1/projects/$PID/files/<fid>/content
curl -OJ localhost:19014/api/v1/projects/$PID/artifacts/<aid>/content
curl -s  localhost:19014/api/v1/projects/$PID/files/<fid>/runs/<rid>      # one run's output
curl -s  localhost:19014/api/v1/projects/$PID/runs/<rid>/artifacts         # files a run produced

# crack a locked file (Check mode), choosing wordlists
curl -s localhost:19014/api/v1/projects/$PID/locked
curl -X POST -H 'Content-Type: application/json' \
     -d '{"file_id":<fid>,"wordlists":["passwords.txt","rockyou-75.txt"]}' \
     localhost:19014/api/v1/projects/$PID/crack
curl -s localhost:19014/api/v1/projects/$PID/crack/status   # this project's crack jobs
# the crack queue: one job per file, CRACK_WORKERS at a time (several files of
# the same project can be queued; the same file can't be queued twice)
curl -s localhost:19014/api/v1/cracks | jq '.[] | {id,name,status,password}'
curl -X DELETE localhost:19014/api/v1/cracks/<job id>         # cancel a queued job

# delete one project, or the whole history (all projects + files)
curl -X DELETE localhost:19014/api/v1/projects/$PID
curl -X DELETE localhost:19014/api/v1/projects
```

### For AI agents

1. `POST /projects` (multipart `files`, `mode=auto`) → `id`
2. `POST /projects/{id}/start`, then poll `GET /projects/{id}` until `status` is
   `done`/`error`/`cancelled` (or follow the WebSocket)
3. `GET /projects/{id}/flags` for the answer and how it was found; if there is
   none, `GET /projects/{id}/transcript` gives the full context to continue from
4. still locked files: `GET /projects/{id}/locked` → `POST /projects/{id}/crack`

A stdlib client is in [`../tools/stegsuite_client.py`](../tools/stegsuite_client.py).

## MCP server (AI agents)

StegSuite is also an [MCP](https://modelcontextprotocol.io) server
(Streamable HTTP, stateless) at `/api/v1/mcp`, with the same API key. With
Claude Code:

```bash
claude mcp add --transport http ctf http://127.0.0.1:19014/api/v1/mcp
# with a key: add  --header "X-API-Key: <key>"
```

Tools: `list_ctfs`, `create_ctf`, `ctf_scoreboard`, `add_challenge` (files by
URL or base64), `autosolve`, `analyze`, `project_status`, `get_flags`,
`get_report`, `get_transcript`, `read_file`, `list_tools`, `run_tools`,
`locked_files`, `crack`, `crack_jobs`, `list_wordlists`, `set_challenge`, `toolbox_services`.

`GET /api/v1/stats?window=20` returns the dashboard numbers (status/mode
counts, flags, passwords, locked files, top tools) in one call.

`GET /api/v1/services` lists the other web tools of the toolbox (CyberChef,
ZAP, Wireshark, rev sandbox…) with their URL and whether they are up.

## Live updates & terminal (WebSocket)

- `ws://localhost:19014/ws/projects/{pid}` → JSON events
  (`status`, `file`, `tool`, `progress`, `crack`, `event`).
- `ws://localhost:19014/ws/projects/{pid}/terminal` → PTY bash (cwd = project);
  send `{"t":"i","d":"ls\n"}` for input and `{"t":"r","c":120,"r":30}` to resize.

## Models

| Model | Notes |
|---|---|
| Ctf | id, name, flag_format, url, notes |
| Project (challenge) | id, name, status, mode(`auto`/`check`), ctf_id, category, solved, flag, timestamps |
| FileNode | id, parent_id, name, rel_path, size, mime, hashes, depth, order_index, origin |
| ToolRun | file_id, tool, status, needs_password, summary, output_path |
| Artifact | run_id, file_id, name, path, size |
| Finding | file_id, kind(`flag`/`password`/`note`), value, source |
| Event | ts, level, message |

## Wordlists

Bundled in the repo (`wordlists/*.txt`) plus full `rockyou.txt` baked into the
image. They are tried **smallest → largest**, first match wins.
`GET /api/v1/wordlists` lists them (name, size, lines).

## Call the API from another container

If your service runs on the same Compose network (`ctfnet`), reach StegSuite by
**service name** — no host port, no conflicts:

```
http://stegsuite:19014/api/v1
```

Example (from the repo):

```bash
docker compose -f compose.yaml -f osint/compose.yaml up -d
```

Inside your container:

```python
import urllib.request
urllib.request.urlopen("http://stegsuite:19014/api/v1/health")
```

A ready-made stdlib client is in [`../osint/example_client.py`](../osint/example_client.py);
the `osint/` area (override compose + contract) is where a separate developer
adds their own services without touching the core.
