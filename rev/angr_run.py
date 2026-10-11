#!/usr/bin/env python3
"""angr-run — symbolic execution helper: find an input that reaches a target.

The classic CTF rev move: instead of reasoning about a check by hand, let angr
explore for a path that hits a target address/symbol and hand you the concrete
input. Wrap it with a timeout because symbolic execution can run long.

Examples
--------
  # find a path to the `win` function, solving 16 symbolic stdin bytes
  angr-run ./chall --find win --stdin 16

  # by address, avoid a failure block
  angr-run ./chall --find 0x401234 --avoid 0x401280 --stdin 32

  # start from a function instead of the entry point
  angr-run ./chall --start check --find win --stdin 8

Notes
-----
- Symbolic stdin bytes are constrained to printable ASCII by default.
- It is a *search*, not a guarantee: widen --timeout or add --avoid hints.
- angr ships with the sandbox; the helper only wires the common knobs.
"""

from __future__ import annotations

import argparse
import signal
import sys
import time


def load_angr():
    import angr  # noqa: PLC0415
    try:
        import claripy  # noqa: PLC0415
    except ImportError:
        claripy = angr.claripy
    return angr, claripy


class _Timeout(Exception):
    pass


def _on_alarm(signum, frame):
    raise _Timeout()


def resolve(proj, token: str) -> int:
    if token.lower().startswith("0x") or token.isdigit():
        return int(token, 0)
    sym = proj.loader.find_symbol(token)
    if sym is None:
        sys.exit(f"angr-run: simbolo non trovato: {token!r}")
    return sym.rebased_addr


def main(argv) -> int:
    ap = argparse.ArgumentParser(prog="angr-run",
                                 description="Symbolic execution: find an input that reaches a target.")
    ap.add_argument("binary")
    ap.add_argument("--find", action="append", default=[], metavar="SYM|0xADDR",
                    help="indirizzo/simbolo da raggiungere (ripetibile)")
    ap.add_argument("--avoid", action="append", default=[], metavar="SYM|0xADDR",
                    help="indirizzo/simbolo da evitare (ripetibile)")
    ap.add_argument("--start", metavar="SYM|0xADDR", help="parti da qui invece che dall'entry")
    ap.add_argument("--stdin", type=int, default=0, metavar="N",
                    help="N byte di stdin simbolici (ASCII stampabile)")
    ap.add_argument("--timeout", type=int, default=120, help="secondi (default 120)")
    ap.add_argument("--constraints", action="store_true", help="stampa anche i vincoli risolti")
    a = ap.parse_args(argv)

    if not a.find:
        sys.exit("angr-run: serve almeno un --find (simbolo o indirizzo)")

    angr, claripy = load_angr()
    proj = angr.Project(a.binary, auto_load_libs=False)
    finds = [resolve(proj, t) for t in a.find]
    avoids = [resolve(proj, t) for t in a.avoid]

    state = (proj.factory.blank_state(addr=resolve(proj, a.start)) if a.start
             else proj.factory.entry_state())
    stdin_sym = None
    if a.stdin:
        stdin_sym = claripy.BVS("stdin", a.stdin * 8)
        for byte in stdin_sym.chop(8):
            state.solver.add(byte >= 0x20)
            state.solver.add(byte <= 0x7E)
        state.posix.stdin.content = [(stdin_sym, a.stdin)]

    signal.signal(signal.SIGALRM, _on_alarm)
    signal.alarm(a.timeout)
    t0 = time.time()
    sm = proj.factory.simgr(state)
    try:
        sm.explore(find=finds, avoid=avoids, num_find=1)
    except _Timeout:
        print(f"angr-run: timeout dopo {a.timeout}s (nessuna soluzione)", file=sys.stderr)
        return 2
    finally:
        signal.alarm(0)
    dt = time.time() - t0

    if not sm.found:
        print(f"angr-run: nessuna soluzione ({dt:.1f}s, active={len(sm.active)})", file=sys.stderr)
        return 1

    found = sm.found[0]
    print(f"# trovato in {dt:.1f}s · find {[hex(f) for f in finds]} · start {hex(found.addr)}")
    if stdin_sym is not None:
        data = found.solver.eval(stdin_sym, cast_to=bytes)
        print(f"# stdin ({len(data)} byte):")
        sys.stdout.flush()
        sys.stdout.buffer.write(data + b"\n")
        sys.stdout.buffer.flush()
    if a.constraints:
        for c in found.solver.constraints:
            print(c)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
