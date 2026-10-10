"""Whitespace esolang interpreter.

A Whitespace program is made only of spaces (0), tabs (1) and newlines — invisible
in most editors. The flag is usually what the program prints. We run it with no
input (bounded steps) and emit the output so the flag hunt scans it.
"""
from __future__ import annotations

from .base import Analyzer, ToolContext, ToolResult
from .registry import register

S, T, L = " ", "\t", "\n"
_WS_CHARS = (S, T, L, "\r", "\v", "\f")
_MAX_STEPS = 5_000_000
_MAX_OUT = 200_000

_ARITH = {(S, S): "add", (S, T): "sub", (S, L): "mul", (T, S): "div", (T, T): "mod"}
_IO = {(S, S): "outchar", (S, T): "outnum", (T, S): "readchar", (T, T): "readnum"}
_STACK = {S: "dup", T: "swap", L: "pop"}


def _parse(code: str) -> tuple[list[tuple[str, object]], dict[int, int]]:
    toks = [c for c in code if c in (S, T, L)]
    prog: list[tuple[str, object]] = []
    labels: dict[int, int] = {}
    i, n = 0, len(toks)

    def num(k: int) -> tuple[int, int]:
        sign = 1 if toks[k] == S else -1
        k += 1
        val = 0
        while k < n and toks[k] != L:
            val = (val << 1) | (0 if toks[k] == S else 1)
            k += 1
        return sign * val, k + 1

    while i < n:
        c0 = toks[i]
        if c0 == S:
            c1 = toks[i + 1] if i + 1 < n else ""
            if c1 == S:
                v, i = num(i + 2)
                prog.append(("push", v))
            elif c1 == L and i + 2 < n:
                prog.append((_STACK[toks[i + 2]], None))
                i += 3
            else:
                break
        elif c0 == T:
            c1 = toks[i + 1] if i + 1 < n else ""
            if c1 == S and i + 3 < n:
                prog.append((_ARITH[(toks[i + 2], toks[i + 3])], None))
                i += 4
            elif c1 == T and i + 2 < n:
                prog.append(({S: "store", T: "retrieve"}[toks[i + 2]], None))
                i += 3
            elif c1 == L and i + 3 < n:
                prog.append((_IO[(toks[i + 2], toks[i + 3])], None))
                i += 4
            else:
                break
        elif c0 == L:
            c1 = toks[i + 1] if i + 1 < n else ""
            c2 = toks[i + 2] if i + 2 < n else ""
            if (c1, c2) in ((S, S), (S, T), (S, L), (T, S), (T, T)):
                lab, i = num(i + 3)
                if (c1, c2) == (S, S):
                    labels[lab] = len(prog)
                    prog.append(("nop", None))
                else:
                    prog.append(({(S, T): "call", (S, L): "jmp", (T, S): "jz", (T, T): "jn"}[(c1, c2)], lab))
            elif (c1, c2) == (T, L):
                prog.append(("ret", None))
                i += 3
            elif (c1, c2) == (L, L):
                prog.append(("end", None))
                i += 3
            else:
                break
        else:
            break
    return prog, labels


def run(code: str, stdin: str = "", max_steps: int = _MAX_STEPS) -> str:
    prog, labels = _parse(code)
    if not prog:
        return ""
    stack: list[int] = []
    heap: dict[int, int] = {}
    call: list[int] = []
    out: list[str] = []
    inp = list(stdin)
    pc = 0
    steps = 0

    def pop() -> int:
        return stack.pop() if stack else 0

    while 0 <= pc < len(prog) and steps < max_steps:
        steps += 1
        op, arg = prog[pc]
        pc += 1
        if op == "push":
            stack.append(int(arg))  # type: ignore[arg-type]
        elif op == "dup":
            stack.append(stack[-1] if stack else 0)
        elif op == "swap" and len(stack) >= 2:
            stack[-1], stack[-2] = stack[-2], stack[-1]
        elif op == "pop":
            pop()
        elif op in ("add", "sub", "mul", "div", "mod"):
            b, a = pop(), pop()
            stack.append({"add": a + b, "sub": a - b, "mul": a * b,
                          "div": a // b if b else 0, "mod": a % b if b else 0}[op])
        elif op == "store":
            v, a = pop(), pop()
            heap[a] = v
        elif op == "retrieve":
            stack.append(heap.get(pop(), 0))
        elif op == "outchar":
            v = pop()
            out.append(chr(v) if 0 <= v < 0x110000 else "")
        elif op == "outnum":
            out.append(str(pop()))
        elif op == "readchar":
            a = pop()
            heap[a] = ord(inp.pop(0)) if inp else -1
        elif op == "readnum":
            a = pop()
            heap[a] = int(inp.pop(0)) if inp and inp[0].lstrip("-").isdigit() else 0
        elif op in ("label", "nop"):
            pass
        elif op == "call":
            call.append(pc)
            pc = labels.get(int(arg), pc)  # type: ignore[arg-type]
        elif op == "jmp":
            pc = labels.get(int(arg), pc)  # type: ignore[arg-type]
        elif op == "jz":
            if pop() == 0:
                pc = labels.get(int(arg), pc)  # type: ignore[arg-type]
        elif op == "jn":
            if pop() < 0:
                pc = labels.get(int(arg), pc)  # type: ignore[arg-type]
        elif op == "ret":
            pc = call.pop() if call else len(prog)
        elif op == "end":
            break
        if len(out) > _MAX_OUT:
            break
    return "".join(out)[:_MAX_OUT]


def looks_like_whitespace(data: bytes) -> bool:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    body = text.rstrip("\r\n")   # strip only trailing newlines (keep spaces/tabs)
    return len(body) >= 16 and all(c in _WS_CHARS for c in body) and L in body


class WhitespaceAnalyzer(Analyzer):
    name = "whitespace"
    category = "stego"
    description = "Interpret a Whitespace esolang program (spaces/tabs/newlines)."
    accepts = ()   # any file; gated by looks_like_whitespace()
    display_order = 129

    def run(self, ctx: ToolContext) -> ToolResult:
        try:
            data = ctx.input.read_bytes()
        except OSError as exc:
            return ToolResult(self.name, status="error", summary=f"cannot read: {exc}")
        if not looks_like_whitespace(data):
            return ToolResult(self.name, status="skipped", summary="not a whitespace program")
        try:
            out = run(data.decode("utf-8"))
        except Exception as exc:  # noqa: BLE001
            return ToolResult(self.name, status="error", summary=f"interpreter error: {exc}")
        if not out.strip():
            return ToolResult(self.name, status="done", summary="ran, no output")
        return ToolResult(self.name, status="done", summary=f"{len(out)} char(s) output",
                          output=out[:_MAX_OUT])


register(WhitespaceAnalyzer())
