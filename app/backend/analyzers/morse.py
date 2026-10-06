"""Morse decoders: audio (on/off envelope) and text (. and -), plus layer chain."""
from __future__ import annotations

import re
import wave
from pathlib import Path

from .base import Analyzer, ToolContext, ToolResult, which
from .registry import register

AV_EXT = (".wav", ".mp3", ".flac", ".ogg", ".m4a", ".aac", ".au", ".mp4", ".mkv", ".webm", ".avi")

MORSE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F", "--.": "G",
    "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L", "--": "M", "-.": "N",
    "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T", "..-": "U",
    "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y", "--..": "Z",
    "-----": "0", ".----": "1", "..---": "2", "...--": "3", "....-": "4", ".....": "5",
    "-....": "6", "--...": "7", "---..": "8", "----.": "9",
    ".-.-.-": ".", "--..--": ",", "..--..": "?", "-..-.": "/", "-...-": "=", ".-.-.": "+",
    "-....-": "-", "---...": ":", "-.-.-.": ";", "-.--.": "(", "-.--.-": ")", ".-..-.": '"',
}


def _read_wav_mono(path: Path):
    import numpy as np
    with wave.open(str(path), "rb") as w:
        ch, width, rate, n = w.getnchannels(), w.getsampwidth(), w.getframerate(), w.getnframes()
        raw = w.readframes(n)
    if width == 2:
        data = np.frombuffer(raw, dtype="<i2").astype("float32")
    elif width == 1:
        data = (np.frombuffer(raw, dtype="u1").astype("float32") - 128.0)
    else:
        data = np.frombuffer(raw, dtype="<i4").astype("float32")
    if ch > 1:
        data = data.reshape(-1, ch).mean(axis=1)
    return data, rate


def decode_morse(samples, rate: int) -> tuple[str, list]:
    import numpy as np
    if len(samples) == 0:
        return "", []
    env = np.abs(samples)
    win = max(1, int(0.005 * rate))  # 5 ms smoothing
    env = np.convolve(env, np.ones(win) / win, mode="same")
    peak = float(env.max())
    if peak <= 0:
        return "", []
    on = env > 0.2 * peak
    # runs of on/off
    runs: list[tuple[bool, float]] = []
    i, n = 0, len(on)
    while i < n:
        j = i
        while j < n and on[j] == on[i]:
            j += 1
        runs.append((bool(on[i]), (j - i) / rate))
        i = j
    # drop leading/trailing silence
    while runs and not runs[0][0]:
        runs.pop(0)
    while runs and not runs[-1][0]:
        runs.pop()
    on_durs = sorted(d for s, d in runs if s)
    if not on_durs:
        return "", []
    unit = max(on_durs[0], 1e-3)
    text = ""
    symbol = ""
    for is_on, dur in runs:
        if is_on:
            symbol += "." if dur < 2 * unit else "-"
        else:
            if dur < 2 * unit:
                continue                       # intra-character
            elif dur < 5 * unit:               # inter-character
                text += MORSE.get(symbol, "?")
                symbol = ""
            else:                              # word gap
                text += MORSE.get(symbol, "?") + " "
                symbol = ""
    if symbol:
        text += MORSE.get(symbol, "?")
    return text.strip(), runs


class MorseAnalyzer(Analyzer):
    name = "morse"
    category = "radio"
    description = "Decode Morse code from audio (on/off envelope)."
    accepts = AV_EXT
    display_order = 420

    def run(self, ctx: ToolContext) -> ToolResult:
        if not which("ffmpeg"):
            return ToolResult(self.name, status="skipped", summary="ffmpeg not installed")
        wav = ctx.sub(self.name) / "audio.wav"
        if str(ctx.input).lower().endswith(".wav"):
            wav = ctx.input
        else:
            ctx.run(["ffmpeg", "-y", "-i", str(ctx.input), "-ac", "1", "-ar", "8000", str(wav)],
                    timeout=300)
        try:
            samples, rate = _read_wav_mono(wav)
        except Exception as exc:
            return ToolResult(self.name, status="error", summary=f"read wav: {exc}")
        text, runs = decode_morse(samples, rate)
        out = f"decoded: {text}\n\n" + "\n".join(
            f"{'ON ' if s else 'off'} {d*1000:.1f} ms" for s, d in runs[:200])
        return ToolResult(self.name, status="done", output=out,
                          summary=f"Morse: {text[:60]}" if text else "no Morse")


register(MorseAnalyzer())


def decode_text_morse(text: str) -> str:
    words: list[str] = []
    word: list[str] = []
    for tok in re.split(r"\s+", text.strip()):
        if tok in ("/", "|", "//"):
            words.append("".join(word))
            word = []
            continue
        ch = MORSE.get(tok)
        if ch:
            word.append(ch)
    if word:
        words.append("".join(word))
    return " ".join(w for w in words if w)


class MorseTextAnalyzer(Analyzer):
    name = "morse-text"
    category = "radio"
    description = ("Decode text Morse (. and -) from a text file, then try nested "
                   "encodings (hex/binary/base64/rot13).")
    accepts = (".txt", ".md", ".dat")
    display_order = 422

    def run(self, ctx: ToolContext) -> ToolResult:
        text = ctx.input.read_text(errors="replace")
        probe = text.strip()[:2000]
        if not probe or not re.fullmatch(r"[\s.\-/|,A-Za-z0-9]+", probe) or probe.count(".") + probe.count("-") < 3:
            return ToolResult(self.name, status="skipped", summary="does not look like Morse")
        decoded = decode_text_morse(text.replace(",", " "))
        lines = [f"morse: {decoded}"]
        try:
            from .decode import chain
            lines += chain(decoded.encode())
        except Exception:
            pass
        return ToolResult(self.name, status="done", output="\n".join(lines[:200]),
                          summary=f"Morse: {decoded[:60]}")


register(MorseTextAnalyzer())
