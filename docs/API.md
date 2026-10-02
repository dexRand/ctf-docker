# StegSuite API

Base: `http://localhost:19014/api/v1` · OpenAPI/Swagger: `/api/docs`
If `API_KEY` (env `STEGSUITE_API_KEY`) is set, send header `X-API-Key: <key>`
on every `/api` request. WebSockets (`/ws/...`) are protected too: send the same
header or append `?key=<key>`. In the GUI store it with
`localStorage.setItem('stegsuite_api_key','<key>')`.

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

## Projects (stateful, recursive)

```bash
# create (Auto = runs everything + auto-cracks; Check = waits for you)
PID=$(curl -s -F mode=auto -F files=@a.png -F files=@b.jpg \
        localhost:19014/api/v1/projects | jq -r .id)

# start / pause / resume / cancel
curl -X POST localhost:19014/api/v1/projects/$PID/start
curl -X POST localhost:19014/api/v1/projects/$PID/cancel

# results
curl -s localhost:19014/api/v1/projects/$PID            | jq .      # project + tree
curl -s localhost:19014/api/v1/projects/$PID/findings   | jq .      # flags/passwords/notes
curl -s localhost:19014/api/v1/projects/$PID/runs       | jq .      # per-tool runs + artifacts
curl -s localhost:19014/api/v1/projects/$PID/events     | jq .      # log

# file / artifact / tool output
curl -OJ localhost:19014/api/v1/projects/$PID/files/<fid>/content
curl -OJ localhost:19014/api/v1/projects/$PID/artifacts/<aid>/content
curl -s  localhost:19014/api/v1/projects/$PID/files/<fid>/runs/<rid>

# crack a locked file (Check mode), choosing wordlists
curl -s localhost:19014/api/v1/projects/$PID/locked
curl -X POST -H 'Content-Type: application/json' \
     -d '{"file_id":<fid>,"wordlists":["passwords.txt","rockyou-75.txt"]}' \
     localhost:19014/api/v1/projects/$PID/crack
curl -s localhost:19014/api/v1/projects/$PID/crack/status

# delete one project, or the whole history (all projects + files)
curl -X DELETE localhost:19014/api/v1/projects/$PID
curl -X DELETE localhost:19014/api/v1/projects
```

## Live updates & terminal (WebSocket)

- `ws://localhost:19014/ws/projects/{pid}` → JSON events
  (`status`, `file`, `tool`, `progress`, `crack`, `event`).
- `ws://localhost:19014/ws/projects/{pid}/terminal` → PTY bash (cwd = project);
  send `{"t":"i","d":"ls\n"}` for input and `{"t":"r","c":120,"r":30}` to resize.

## Models

| Model | Notes |
|---|---|
| Project | id, name, status, mode(`auto`/`check`), timestamps |
| FileNode | id, parent_id, name, rel_path, size, mime, hashes, depth, order_index, origin |
| ToolRun | file_id, tool, status, needs_password, summary, output_path |
| Artifact | run_id, file_id, name, path, size |
| Finding | file_id, kind(`flag`/`password`/`note`), value, source |
| Event | ts, level, message |

## Wordlists

Bundled in the repo (`wordlists/*.txt`) plus full `rockyou.txt` baked into the
image. They are tried **smallest → largest**, first match wins.
`GET /api/v1/wordlists` lists them (name, size, lines).
