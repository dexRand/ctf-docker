"""Live WebSocket endpoints: project events and an interactive terminal."""
from __future__ import annotations

import asyncio
import fcntl
import json
import os
import pty
import queue
import shutil
import struct
import termios

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from .. import storage
from ..bus import bus

router = APIRouter()

BASH = shutil.which("bash") or "/bin/sh"
RC = "/etc/stegsuite/term.bashrc"


@router.websocket("/ws/projects/{pid}")
async def ws_project(ws: WebSocket, pid: str) -> None:
    """Live stream of project events (status, files, tools, progress, findings)."""
    await ws.accept()
    q = bus.subscribe(f"project:{pid}")
    try:
        while True:
            try:
                event = await asyncio.to_thread(q.get, True, 1.0)
            except queue.Empty:
                await ws.send_json({"type": "ping"})
                continue
            await ws.send_json(event)
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        bus.unsubscribe(f"project:{pid}", q)


@router.websocket("/ws/projects/{pid}/terminal")
async def ws_terminal(ws: WebSocket, pid: str) -> None:
    """Interactive, colourised bash shell with cwd = the project directory."""
    await ws.accept()
    cwd = storage.project_dir(pid)
    if not cwd.is_dir():
        await ws.send_json({"type": "error", "message": "project not found"})
        await ws.close()
        return
    master, slave = pty.openpty()
    env = {**os.environ, "TERM": "xterm-256color", "LANG": os.environ.get("LANG", "C.UTF-8")}
    args = [BASH, "-i"]
    if os.path.exists(RC):
        args = [BASH, "--rcfile", RC, "-i"]
    try:
        proc = await asyncio.create_subprocess_exec(
            *args, stdin=slave, stdout=slave, stderr=slave, cwd=str(cwd),
            env=env, start_new_session=True,
        )
    finally:
        os.close(slave)
    loop = asyncio.get_event_loop()

    async def pump() -> None:
        while True:
            try:
                data = await loop.run_in_executor(None, os.read, master, 65536)
            except OSError:
                break
            if not data:
                break
            try:
                await ws.send_text(data.decode("utf-8", "replace"))
            except (WebSocketDisconnect, RuntimeError):
                break

    out_task = asyncio.create_task(pump())
    try:
        while True:
            msg = await ws.receive_text()
            try:
                m = json.loads(msg)
            except (ValueError, TypeError):
                m = {"t": "i", "d": msg}
            if m.get("t") == "r":
                cols = int(m.get("c", 80))
                rows = int(m.get("r", 24))
                try:
                    fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
                except OSError:
                    pass
            else:
                try:
                    os.write(master, str(m.get("d", "")).encode())
                except OSError:
                    break
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        out_task.cancel()
        try:
            os.close(master)
        except OSError:
            pass
        try:
            proc.terminate()
        except ProcessLookupError:
            pass
