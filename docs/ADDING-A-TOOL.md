# Adding an analyzer (tool)

StegSuite analyzers are small, self-contained plugins. Adding one is usually a
single file plus a registration line.

## 1. Write the analyzer

Create `app/backend/analyzers/<name>.py`:

```python
from .base import Analyzer, ToolContext, ToolResult
from .registry import register, subprocess_analyzer

# (a) simplest case: a command wrapper
subprocess_analyzer(
    "my-tool",                     # tool name (API + GUI)
    ["my-tool", "--flag", "{input}"],
    "steg",                        # category: metadata|text|hex|extract|steg|png|vision|radio|audio
    "What it does (one line).",
    accepts=(".png", ".jpg"),      # () = every file; or extensions
    order=300,                     # display/execution order
)


# (b) custom logic
class MyAnalyzer(Analyzer):
    name = "my-custom"
    category = "steg"
    description = "Does something custom."
    needs_password = False
    display_order = 305
    accepts = (".png",)

    def run(self, ctx: ToolContext) -> ToolResult:
        proc = ctx.run(["my-cmd", str(ctx.input)], timeout=120)   # capture stdout/stderr
        return ToolResult(
            self.name,
            status="done" if proc.returncode == 0 else "error",
            output=(proc.stdout or "") + (proc.stderr or ""),
            summary="short status",
            # files to be treated as CHILDREN and re-analysed recursively:
            extracted=[str(p) for p in ctx.sub(self.name).glob("*")],
            # files to show in the GUI but NOT recurse into:
            artifacts=[{"name": p.name, "path": str(p), "size": p.stat().st_size}],
        )


register(MyAnalyzer())
```

## 2. Register the module

Add it to `app/backend/analyzers/__init__.py` imports:

```python
from . import metadata, text, hex, decode, extract, steg, png, image, gif, vision, morse, audio, <name>
```

## 3. (Optional) add it to the default pipeline

`app/backend/orchestrator.py` → `DEFAULT_PLAN` (only tools that should run
automatically). Tools not in the plan are still available via
`POST /api/v1/tools/{tool}`.

## 4. Test

```bash
# rebuild + restart
docker compose build stegsuite && docker compose up -d --force-recreate stegsuite
# catalog must list it
curl -s localhost:19014/api/v1/tools | python3 -m json.tool | grep my-tool
# run it on a file
curl -s -F file=@sample.png localhost:19014/api/v1/tools/my-tool | python3 -m json.tool
```

## Conventions

- **Command wrappers**: use `subprocess_analyzer(...)`; automatic skip if the
  binary is missing.
- **Status**: `done` | `error` | `skipped` | `needs_password`.
- **`extracted` vs `artifacts`**: anything that should be analysed again →
  `extracted`; visualisations (bit planes, frames, spectrograms) → `artifacts`.
- **Bound the work**: cap output size and set a `timeout`; skip too-large inputs.
- No heavy dependencies: the image already ships the main toolset.
