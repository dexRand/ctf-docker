"""Project reports built server-side, so every client (SPA, CLI, AI agent)
gets the same thing from the API.

* `flag_routes`  each flag with the chain of files that led to it and the tool
                 output that shows it (evidence)
* `markdown`     human report (it/en): flags, passwords, route, commands
* `full_logs`    event log + every run with its full output
* `transcript`   XML-ish context for an AI agent, task at the end
"""
from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path

from sqlmodel import Session, select

from . import storage
from .crackflow import locked_files
from .models import Event, FileNode, Finding, Project, ToolRun

# finding sources look like "[b64:|hex:|fuzzy:]*<tool>:<file>"
_SRC_PREFIX = ("b64", "hex", "fuzzy")
_SRC_DECODER = {"b64": "base64", "hex": "hex", "fuzzy": "fuzzy/OCR"}
_ORIGIN_RE = re.compile(r"^extracted:([^:]+):\d+$")

TEXT = {
    "en": {
        "title": "StegSuite report — {name}",
        "status": "**Status:** {status} · **Mode:** --{mode} · **Files:** {files} · **Date:** {date}",
        "passwords": "Passwords", "passwords_head": "| Password | Origin | Cracked with |",
        "notes": "Notes / locked", "notes_head": "| Note | Tool |",
        "how_header": "How the flag was found", "where": "**Where:**", "how": "**How:**",
        "chain": "**Chain:**", "no_flag": "_No flag._", "via": "via",
        "path_header": "Flag route", "no_path": "(no flag found)", "solved": "**(solved)**",
        "tools_header": "Tools on the flag", "route_runs": "Tools on the route ({n})",
        "run_head": "| File | Tool | Status | Summary |", "commands": "Commands",
        "route_files": "Files on the route ({n})",
        "route_files_head": "| File | Size | Produced by | Open |", "open": "open",
        "footer": "> Analysed {files} files and {runs} tool runs; above only what leads to "
                  "the flag. The other {noise} files are in the GUI.",
    },
    "it": {
        "title": "Report StegSuite — {name}",
        "status": "**Stato:** {status} · **Modalità:** --{mode} · **File:** {files} · **Data:** {date}",
        "passwords": "Password", "passwords_head": "| Password | Origine | Craccata con |",
        "notes": "Note / bloccati", "notes_head": "| Nota | Tool |",
        "how_header": "Come è stata trovata la flag", "where": "**Dove:**", "how": "**Come:**",
        "chain": "**Catena:**", "no_flag": "_Nessuna flag._", "via": "via",
        "path_header": "Percorso della flag", "no_path": "(nessuna flag trovata)",
        "solved": "**(risolto)**", "tools_header": "Tool usati per la flag",
        "route_runs": "Tool sul percorso ({n})", "run_head": "| File | Tool | Stato | Sintesi |",
        "commands": "Comandi", "route_files": "File sul percorso ({n})",
        "route_files_head": "| File | Dim | Prodotto da | Apri |", "open": "apri",
        "footer": "> Analizzati {files} file e {runs} esecuzioni di tool; qui solo ciò che porta "
                  "alla flag. Gli altri {noise} file sono nella GUI.",
    },
}


def fmt_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return str(n)


def fmt_date(d: dt.datetime | None) -> str:
    return d.strftime("%Y-%m-%d %H:%M") if d else "-"


def origin_tool(n: FileNode) -> str:
    """Tool that produced a node ('upload' for uploads)."""
    o = n.origin or ""
    if not o or o == "upload" or n.parent_id is None:
        return "upload"
    m = _ORIGIN_RE.match(o)
    return m.group(1) if m else "extracted"


def source_parts(src: str) -> tuple[str, list[str]]:
    """(tool, decoders) of a finding source, e.g. 'b64:exiftool:x.jpg' -> ('exiftool', ['b64'])."""
    parts = [p for p in (src or "").split(":") if p]
    dec = []
    while len(parts) > 1 and parts[0] in _SRC_PREFIX:
        dec.append(parts.pop(0))
    tool = "raw scan" if parts and parts[0] == "raw" else (parts[0] if parts else "?")
    return tool, dec


def source_how(src: str) -> str:
    tool, dec = source_parts(src)
    return tool + "".join(" + " + _SRC_DECODER.get(d, d) for d in dec)


def commands_of(text: str) -> list[str]:
    """Commands recorded at the top of a run output (`# commands:` block)."""
    return [ln[2:] for ln in (text or "").split("\n")
            if ln.startswith("# ") and ln[2:] and ln[2:] != "commands:"]


def evidence_lines(text: str, flag: str, width: int = 3) -> str:
    lines = (text or "").split("\n")
    for i, ln in enumerate(lines):
        if flag in ln:
            return "\n".join(lines[max(0, i - width):i + width + 1])[:900]
    return ""


@dataclass
class ProjectView:
    """Everything a report needs, loaded once (run outputs read lazily)."""
    project: Project
    nodes: list[FileNode]
    runs: list[ToolRun]
    findings: list[Finding]
    events: list[Event]
    locked: dict[int, str]
    _outputs: dict[int, str] = field(default_factory=dict)
    _evidence: dict[int, dict | None] = field(default_factory=dict)

    @classmethod
    def load(cls, session: Session, pid: str) -> "ProjectView | None":
        proj = session.get(Project, pid)
        if not proj:
            return None
        q = lambda m: select(m).where(m.project_id == pid)  # noqa: E731
        return cls(
            project=proj,
            nodes=list(session.exec(q(FileNode).order_by(FileNode.order_index, FileNode.id)).all()),
            runs=list(session.exec(q(ToolRun).order_by(ToolRun.id)).all()),
            findings=list(session.exec(q(Finding).order_by(Finding.id)).all()),
            events=list(session.exec(q(Event).order_by(Event.id)).all()),
            locked=locked_files(session, pid),
        )

    # --- indexes ---
    @cached_property
    def by_id(self) -> dict[int, FileNode]:
        return {n.id: n for n in self.nodes}

    def children(self) -> dict[int, list[FileNode]]:
        m: dict[int, list[FileNode]] = {}
        for n in self.nodes:
            m.setdefault(n.parent_id or 0, []).append(n)
        return m

    def runs_of(self, file_id: int | None) -> list[ToolRun]:
        return [r for r in self.runs if r.file_id == file_id]

    def kind(self, k: str) -> list[Finding]:
        return [f for f in self.findings if f.kind == k]

    def password_of(self, file_id: int) -> Finding | None:
        return next((p for p in self.kind("password") if p.file_id == file_id), None)

    def output(self, run: ToolRun) -> str:
        if run.id not in self._outputs:
            text = ""
            if run.output_path:
                try:
                    p = storage.project_dir(run.project_id) / run.output_path
                    text = Path(p).read_text("utf-8", "replace")
                except OSError:
                    pass
            self._outputs[run.id] = text
        return self._outputs[run.id]

    def eff_status(self, r: ToolRun) -> str:
        return "cracked" if r.needs_password and self.password_of(r.file_id) else r.status

    # --- the flag route ---
    def chain_of(self, file_id: int | None) -> list[FileNode]:
        by_id, chain, cur = self.by_id, [], file_id
        while cur and cur in by_id:
            chain.insert(0, by_id[cur])
            cur = by_id[cur].parent_id
        return chain

    def route_nodes(self) -> list[FileNode]:
        ids = {n.id for f in self.kind("flag") for n in self.chain_of(f.file_id)}
        return [n for n in self.nodes if n.id in ids]

    def evidence_for(self, f: Finding) -> dict | None:
        """The run whose output really shows the flag (the source may be a
        pseudo-tool like 'raw scan' that matches no run)."""
        if f.id not in self._evidence:
            self._evidence[f.id] = None
            src, _ = source_parts(f.source)
            for r in sorted(self.runs_of(f.file_id), key=lambda r: r.tool != src):
                o = self.output(r)
                if o and f.value in o:
                    self._evidence[f.id] = {"run": r.id, "tool": r.tool,
                                            "command": (commands_of(o) or [""])[0],
                                            "lines": evidence_lines(o, f.value)}
                    break
        return self._evidence[f.id]

    def relevant_runs(self) -> list[ToolRun]:
        """The finder run of each flag + the runs that produced each file on its path."""
        wanted: set[tuple[int, str]] = set()
        found: set[int] = set()
        for f in self.kind("flag"):
            wanted.add((f.file_id, source_parts(f.source)[0]))
            ev = self.evidence_for(f)
            if ev:
                found.add(ev["run"])
            for n in self.chain_of(f.file_id):
                if n.parent_id is not None and origin_tool(n) not in ("upload", "extracted"):
                    wanted.add((n.parent_id, origin_tool(n)))
        return [r for r in self.runs if r.id in found or (r.file_id, r.tool) in wanted]

    def solver_tools(self) -> set[str]:
        out = set()
        for f in self.kind("flag"):
            ev = self.evidence_for(f)
            out.add(ev["tool"] if ev else source_parts(f.source)[0])
        return out

    def flag_tools(self) -> list[str]:
        s = set(self.solver_tools())
        for f in self.kind("flag"):
            for n in self.chain_of(f.file_id):
                if origin_tool(n) not in ("upload", "extracted"):
                    s.add(origin_tool(n))
        s.update(r.tool for r in self.relevant_runs())
        return sorted(s)

    def chain_text(self, f: Finding, via: str = "via") -> str:
        parts = []
        for i, n in enumerate(self.chain_of(f.file_id)):
            if i == 0:
                parts.append(n.name)
                continue
            pw = self.password_of(n.id)
            pwd = f", pwd {pw.value}" + (f" (via {pw.context})" if pw.context else "") if pw else ""
            parts.append(f"{n.name} ({via} {origin_tool(n)}{pwd})")
        ev = self.evidence_for(f)
        parts.append(f"[{ev['tool'] if ev else source_how(f.source)}]")
        return "  ->  ".join(parts)

    def ascii_route_tree(self) -> str:
        route = self.route_nodes()
        kids: dict[int, list[FileNode]] = {}
        for n in route:
            kids.setdefault(n.parent_id or 0, []).append(n)
        lines: list[str] = []

        def label(n: FileNode) -> str:
            fl = [f.value for f in self.kind("flag") if f.file_id == n.id]
            pw = [p.value for p in self.kind("password") if p.file_id == n.id]
            s = n.name
            if origin_tool(n) not in ("upload", "extracted"):
                s += f"   ({origin_tool(n)})"
            if fl:
                s += "   <-- FLAG: " + ", ".join(fl)
            elif pw:
                s += "   <-- password: " + ", ".join(pw)
            return s

        def walk(pid: int, prefix: str) -> None:
            ks = kids.get(pid, [])
            for i, k in enumerate(ks):
                last = i == len(ks) - 1
                lines.append(prefix + ("└── " if last else "├── ") + label(k))
                walk(k.id, prefix + ("    " if last else "│   "))

        walk(0, "")
        return "\n".join(lines)

    def file_url(self, n: FileNode) -> str:
        return f"/api/v1/projects/{self.project.id}/files/{n.id}/content"


# --- API payloads -------------------------------------------------------------

def flag_routes(v: ProjectView) -> list[dict]:
    """Each flag with where/how it was found and the file chain that led to it."""
    out = []
    for f in v.kind("flag"):
        node = v.by_id.get(f.file_id)
        ev = v.evidence_for(f)
        out.append({
            "id": f.id, "value": f.value, "source": f.source,
            "file": {"id": node.id, "name": node.name} if node else None,
            "how": ev["tool"] if ev else source_how(f.source),
            "evidence": ev,
            "context": f.context,
            "chain": [{"id": n.id, "name": n.name, "tool": origin_tool(n),
                       "password": (v.password_of(n.id).value if n.parent_id is not None
                                    and v.password_of(n.id) else None)}
                      for n in v.chain_of(f.file_id)],
            "chain_text": v.chain_text(f),
        })
    return out


def markdown(v: ProjectView, lang: str = "en") -> str:
    T = TEXT.get(lang, TEXT["en"])
    P = v.project
    L = [f"# {T['title'].format(name=P.name)}", "",
         T["status"].format(status=P.status, mode=P.mode, files=len(v.nodes),
                            date=fmt_date(P.created_at)), ""]
    pws = v.kind("password")
    if pws:
        L += ["## " + T["passwords"], T["passwords_head"], "|---|---|---|"]
        L += [f"| `{p.value}` | {p.source} | {f'`{p.context}`' if p.context else '—'} |" for p in pws]
    notes = v.kind("note")
    if notes:
        L += ["", "## " + T["notes"], T["notes_head"], "|---|---|"]
        L += [f"| {n.value} | {n.source} |" for n in notes]
    L += ["", "## " + T["how_header"]]
    flags = v.kind("flag")
    for f in flags:
        fn = v.by_id.get(f.file_id)
        ev = v.evidence_for(f)
        L.append(f"### `{f.value}`")
        L.append(f"- {T['where']} {fn.name if fn else '?'}"
                 + (f"  ·  [{T['open']}]({v.file_url(fn)})" if fn else ""))
        L.append(f"- {T['how']} {ev['tool'] if ev else source_how(f.source)}")
        L.append(f"- {T['chain']} `{v.chain_text(f, T['via'])}`")
        body = (f"# {ev['tool']}" + (f"  —  {ev['command']}" if ev["command"] else "")
                + "\n" + ev["lines"]) if ev and ev["lines"] else (f.context or "")
        if body:
            L += ["```", body.replace("```", "'''"), "```"]
        L.append("")
    if not flags:
        L.append(T["no_flag"])
    tools, solved = v.flag_tools(), v.solver_tools()
    L.append(f"## {T['tools_header']} ({len(tools)})")
    L.append(", ".join(f"`{t}`" + (f" {T['solved']}" if t in solved else "") for t in tools) or "_—_")
    route = v.route_nodes()
    L += ["", "## " + T["path_header"], "```", v.ascii_route_tree() if route else T["no_path"], "```"]
    rel = v.relevant_runs()
    if rel:
        L += ["", "## " + T["route_runs"].format(n=len(rel)), T["run_head"], "|---|---|---|---|"]
        for r in rel:
            n = v.by_id.get(r.file_id)
            L.append(f"| {n.name if n else '?'} | {r.tool} | {r.status} | "
                     f"{(r.summary or '').replace('|', chr(92) + '|')} |")
        blocks = []
        for r in rel:
            cmds = commands_of(v.output(r))
            if cmds:
                n = v.by_id.get(r.file_id)
                blocks.append(f"```\n# {n.name if n else '?'} — {r.tool}\n" + "\n".join(cmds) + "\n```")
        if blocks:
            L += ["", "## " + T["commands"], *blocks]
    route_files = [n for n in route if n.parent_id is not None]
    if route_files:
        L += ["", "## " + T["route_files"].format(n=len(route_files)), T["route_files_head"],
              "|---|---|---|---|"]
        L += [f"| {n.name} | {fmt_size(n.size)} | {origin_tool(n)} | [{T['open']}]({v.file_url(n)}) |"
              for n in route_files]
    L += ["", T["footer"].format(files=len(v.nodes), runs=len(v.runs),
                                 noise=len(v.nodes) - len(route))]
    return "\n".join(L)


def event_log(v: ProjectView) -> str:
    return "\n".join(f"{e.ts.strftime('%H:%M:%S') if e.ts else ''}  "
                     f"{'!' if e.level in ('warn', 'error') else '·'} {e.message}" for e in v.events)


def full_logs(v: ProjectView) -> str:
    P = v.project
    L = [f"# StegSuite full logs — {P.name} ({P.id})", "", "## Event log",
         event_log(v) or "(none)", "", "## Runs"]
    for n in v.nodes:
        for r in v.runs_of(n.id):
            L += ["", f"### {n.name} — {r.tool} — {v.eff_status(r)} (exit "
                      f"{'-' if r.exit_code is None else r.exit_code}) — "
                      f"{fmt_date(r.finished_at or r.started_at)}",
                  v.output(r) or "(no output)"]
    return "\n".join(L)


def _xa(s) -> str:
    return (str("" if s is None else s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;").replace("\n", " "))


def _cdata(s: str) -> str:
    return "<![CDATA[" + (s or "").replace("]]>", "]]]]><![CDATA[>") + "]]>"


def transcript(v: ProjectView) -> str:
    """Machine log for an AI agent: long context first, the task at the end."""
    P = v.project
    by_id = v.by_id
    flags = v.kind("flag")
    L = ["You are a CTF assistant. The transcript below is the machine log of an",
         "automated steganography/forensics tool run on a challenge. If the flag is",
         "not present or the tool stopped early, continue from this transcript.", "",
         "<transcript>",
         f'<challenge name="{_xa(P.name)}" id="{_xa(P.id)}" status="{_xa(P.status)}" mode="{_xa(P.mode)}">',
         f"  <files_count>{len(v.nodes)}</files_count>",
         f"  <created>{_xa(fmt_date(P.created_at))}</created>"]
    m = re.match(r"^([A-Za-z0-9_]+)\{", flags[0].value) if flags else None
    if m:
        L.append(f"  <flag_format>{_xa(m.group(1) + '{...}')}</flag_format>")
    L += ["</challenge>", "", "<findings>", "  <flags>"]
    for f in flags:
        L.append(f'    <flag value="{_xa(f.value)}" file="{_xa((by_id.get(f.file_id) or FileNode()).name or "?")}" '
                 f'how="{_xa(source_how(f.source))}"/>')
    L += ["  </flags>", "  <passwords>"]
    for p in v.kind("password"):
        L.append(f'    <password value="{_xa(p.value)}" source="{_xa(p.source)}"'
                 + (f' wordlist="{_xa(p.context)}"' if p.context else "")
                 + f' file="{_xa((by_id.get(p.file_id) or FileNode()).name or "?")}"/>')
    L += ["  </passwords>", "  <notes>"]
    L += [f"    <note>{_xa(n.value)} ({_xa(n.source)})</note>" for n in v.kind("note")]
    L.append("  </notes>")
    if v.locked:
        L.append("  <still_locked>")
        L += [f'    <locked file="{_xa(by_id[fid].name)}" tool="{_xa(tool)}"/>'
              for fid, tool in v.locked.items() if fid in by_id]
        L.append("  </still_locked>")
    L += ["</findings>", "", "<flag_path>",
          v.ascii_route_tree() if v.route_nodes() else "(no path to a flag yet)", "</flag_path>", ""]
    flag_files = {f.file_id for f in flags}
    kids = v.children()
    L.append("<files>")

    def walk(pid: int, depth: int) -> None:
        for n in kids.get(pid, []):
            mark = (' flag="true"' if n.id in flag_files else ' cracked="true"' if v.password_of(n.id)
                    else ' locked="true"' if n.id in v.locked else "")
            L.append(f'{"  " * (depth + 1)}<file name="{_xa(n.name)}" tool="{_xa(origin_tool(n))}" '
                     f'size="{fmt_size(n.size)}"' + (f' sha256="{n.sha256[:16]}"' if n.sha256 else "")
                     + f"{mark}/>")
            walk(n.id, depth + 1)

    walk(0, 0)
    L += ["</files>", "", "<runs>"]
    relevant = {r.id for r in v.relevant_runs()}
    for n in v.nodes:
        for r in v.runs_of(n.id):
            text = v.output(r)
            cap = 3000 if r.id in relevant else 1200
            L.append(f'  <run file="{_xa(n.name)}" tool="{_xa(r.tool)}" status="{_xa(v.eff_status(r))}" '
                     f'exit="{"-" if r.exit_code is None else r.exit_code}" '
                     f'at="{_xa(fmt_date(r.finished_at or r.started_at))}">')
            if r.summary:
                L.append(f"    <summary>{_xa(r.summary)}</summary>")
            L.append("    <commands>")
            L += [f"      <cmd>{_xa(c)}</cmd>" for c in commands_of(text)] or ["      <cmd>(none recorded)</cmd>"]
            L.append("    </commands>")
            if text:
                body = re.sub(r"^# commands:\n(?:# .*\n)*\n?", "", text)[:cap]
                more = f"\n… [truncated {len(text) - cap} chars]" if len(text) > cap else ""
                L.append(f"    <output>{_cdata(body)}{more}</output>")
            L.append("  </run>")
    L += ["</runs>", "", "<event_log>", _cdata(event_log(v) or "(none)"), "</event_log>",
          "</transcript>", "", "<task>",
          "The automated tool may have stopped early or missed the flag. Using the transcript above:",
          "1. Summarize what has already been done and what is still unsolved (see <still_locked>).",
          "2. Give the exact next commands (tool + file paths) to finish the challenge and obtain the flag.",
          ("A flag is already present in <findings><flags>: verify it and, if valid, confirm it."
           if flags else "No flag has been found yet, so propose the next steps to find it."),
          "Explain briefly why each command is the right next step.", "</task>"]
    return "\n".join(L)
