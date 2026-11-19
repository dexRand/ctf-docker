"""Password/credential -> flag wrapping (issue #16).

A credential that emerges from an analyzer (a VNC password decrypted from a
hive, a password in a crack hint) is often the flag body itself:
`Password = Slay4U!!` -> `ictf{Slay4U!!}`. The hunt tries every known prefix as
a *candidate* and never replaces a confirmed flag.
"""
from __future__ import annotations

from sqlmodel import Session, select

from backend import flagpatterns as fp
from backend.db import engine, init_db
from backend.models import Finding, Project


def _findings(pid: str, text: str, source: str,
              extra: list[tuple[str, str]] | None = None) -> list[tuple[str, str, str]]:
    """Run the hunt on `text` and return (kind, value, source) of the project."""
    init_db()
    with Session(engine) as s:
        s.add(Project(id=pid, name=pid, status="running"))
        for kind, value in extra or []:
            s.add(Finding(project_id=pid, kind=kind, value=value, source="test"))
        s.commit()
        from backend.orchestrator import _hunt
        _hunt(s, pid, None, text, source)
        s.commit()
        return [(f.kind, f.value, f.source) for f in
                s.exec(select(Finding).where(Finding.project_id == pid)).all()]


def test_password_line_yields_a_candidate_for_every_prefix() -> None:
    out = _findings("fp-wrap-vnc",
                    "== VNC passwords (fixed DES key) ==\n"
                    "\\Software\\TightVNC\\Server\n  Password = Slay4U!!\n",
                    "winreg:NTUSER.DAT")
    flags = {v for k, v, _ in out if k == "flag"}
    assert "ictf{Slay4U!!}" in flags
    # every known prefix is tried; candidates that would be fragments of one
    # another (`CTF{…}`/`picoCTF{…}`, `flag{…}`/`utflag{…}`) are deduped
    for prefix in fp.FLAG_PREFIXES:
        cand = f"{prefix}{{Slay4U!!}}"
        assert cand in flags or any(cand in other or other in cand for other in flags), cand
    assert not any(fl != o and fl in o for fl in flags for o in flags)


def test_vnc_registry_value_names_are_recognised() -> None:
    # winreg prints the decrypted VNC value with its registry name
    for name in ("Password", "PasswordViewOnly", "ControlPassword", "passwd", "passwd2"):
        assert fp.password_values(f"  {name} = Slay4U!!") == ["Slay4U!!"]


def test_wrapped_candidates_are_marked_low_confidence() -> None:
    out = _findings("fp-wrap-src", "passwd = hunter2!\n", "hashes:x.txt")
    src = [s for k, v, s in out if k == "flag" and v == "flag{hunter2!}"]
    assert src and src[0].startswith("wrap:")


def test_unlabelled_assignment_is_not_wrapped() -> None:
    out = _findings("fp-wrap-no", "foo = bar\nuser = bob\ncomment: hello world\n",
                    "strings:x.txt")
    assert not [v for k, v, _ in out if k == "flag"]


def test_password_finding_is_wrapped_too() -> None:
    out = _findings("fp-wrap-db", "nothing to see here", "strings:x.txt",
                    extra=[("password", "Slay4U!!")])
    assert "ictf{Slay4U!!}" in {v for k, v, _ in out if k == "flag"}


def test_candidate_cap_is_respected() -> None:
    text = "\n".join(f"Password = pw{n:04d}" for n in range(40))
    out = _findings("fp-wrap-cap", text, "winreg:hive")
    wrapped = [v for k, v, src in out if k == "flag" and src.startswith("wrap:")]
    assert 0 < len(wrapped) <= fp.MAX_WRAP_CANDIDATES
    assert f"ictf{{pw{fp.MAX_WRAP_VALUES - 1:04d}}}" in wrapped
    assert f"ictf{{pw{fp.MAX_WRAP_VALUES:04d}}}" not in wrapped


def test_candidate_never_replaces_a_confirmed_flag() -> None:
    out = _findings("fp-wrap-keep", "Password = Slay4U!!", "winreg:hive",
                    extra=[("flag", "picoCTF{Slay4U!!}")])
    flags = {v for k, v, _ in out if k == "flag"}
    assert "picoCTF{Slay4U!!}" in flags
    assert "CTF{Slay4U!!}" not in flags          # fragment of the confirmed flag
    assert not any(fl != o and fl in o for fl in flags for o in flags)
