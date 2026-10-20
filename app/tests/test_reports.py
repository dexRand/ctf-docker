"""Server-side reports: flag route, markdown, logs, transcript (API-first)."""
import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session

from backend import storage
from backend.db import engine, init_db
from backend.models import Event, FileNode, Finding, Project, ToolRun

PID = "rep-test"


@pytest.fixture(scope="module")
def client():
    from backend.main import app
    init_db()
    work = storage.project_dir(PID)
    (work / "work" / "2").mkdir(parents=True, exist_ok=True)
    (work / "work" / "2" / "strings.out").write_text(
        "# commands:\n# strings -a inner.txt\n\nnoise\nthe flag is ITS{route_ok}\nmore\n")
    with Session(engine) as s:
        if not s.get(Project, PID):
            s.add(Project(id=PID, name="chall.zip", status="done"))
            s.add(FileNode(id=901, project_id=PID, name="chall.zip", rel_path="uploads/chall.zip",
                           order_index=0))
            s.add(FileNode(id=902, project_id=PID, parent_id=901, name="inner.txt",
                           rel_path="files/0001__inner.txt", depth=1, order_index=1,
                           origin="extracted:7z:901"))
            s.add(ToolRun(id=801, project_id=PID, file_id=901, tool="7z", status="done",
                          summary="1 file"))
            s.add(ToolRun(id=802, project_id=PID, file_id=902, tool="strings", status="done",
                          output_path="work/2/strings.out"))
            s.add(Finding(project_id=PID, file_id=902, kind="flag", value="ITS{route_ok}",
                          source="raw:inner.txt"))
            s.add(Finding(project_id=PID, file_id=902, kind="password", value="hunter2",
                          source="crack:archive", context="10k.txt"))
            s.add(Event(project_id=PID, message="analysis done"))
            s.commit()
    with TestClient(app) as c:
        yield c


def test_flags_endpoint_gives_route_and_evidence(client):
    [f] = client.get(f"/api/v1/projects/{PID}/flags").json()
    assert f["value"] == "ITS{route_ok}"
    assert [n["name"] for n in f["chain"]] == ["chall.zip", "inner.txt"]
    assert f["chain"][1]["tool"] == "7z"
    assert f["evidence"]["tool"] == "strings"          # real output, not the 'raw' pseudo-source
    assert "ITS{route_ok}" in f["evidence"]["lines"]


def test_markdown_report_in_both_languages(client):
    en = client.get(f"/api/v1/projects/{PID}/report").text
    it = client.get(f"/api/v1/projects/{PID}/report?lang=it").text
    assert "How the flag was found" in en and "ITS{route_ok}" in en
    assert "Come è stata trovata la flag" in it
    assert "└── inner.txt" in en and "<-- FLAG: ITS{route_ok}" in en
    assert "strings -a inner.txt" in en                 # commands of the route runs


def test_json_report(client):
    r = client.get(f"/api/v1/projects/{PID}/report?format=json").json()
    assert r["project"]["files"] == 2
    assert r["passwords"][0]["wordlist"] == "10k.txt"
    assert "strings" in r["flag_tools"] and "7z" in r["flag_tools"]


def test_logs_and_transcript(client):
    logs = client.get(f"/api/v1/projects/{PID}/logs").text
    assert "analysis done" in logs and "the flag is ITS{route_ok}" in logs
    tr = client.get(f"/api/v1/projects/{PID}/transcript").text
    assert tr.rstrip().endswith("</task>")
    assert '<flag value="ITS{route_ok}"' in tr and "<flag_format>ITS{...}</flag_format>" in tr


def test_unknown_project_is_404(client):
    assert client.get("/api/v1/projects/nope/report").status_code == 404
    assert client.get("/api/v1/projects/%2e%2e/flags").status_code == 404


def test_run_tools_on_a_file(client, tmp_path):
    import time

    from backend import storage as st
    work = st.project_dir(PID)
    (work / "uploads").mkdir(parents=True, exist_ok=True)
    (work / "uploads" / "chall.zip").write_bytes(b"plain text with flag{rerun_ok} inside\n")
    r = client.post(f"/api/v1/projects/{PID}/files/901/run", json={"tools": ["strings"]})
    assert r.status_code == 202
    for _ in range(50):
        vals = {f["value"] for f in client.get(f"/api/v1/projects/{PID}/findings").json()}
        if "flag{rerun_ok}" in vals:
            break
        time.sleep(0.1)
    assert "flag{rerun_ok}" in vals
    tools = [x["tool"] for x in client.get(f"/api/v1/projects/{PID}/runs?file_id=901").json()]
    assert "strings" in tools


def test_run_tools_rejects_unknown_tools(client):
    r = client.post(f"/api/v1/projects/{PID}/files/901/run", json={"tools": ["nope"]})
    assert r.status_code == 422
    assert client.post(f"/api/v1/projects/{PID}/files/999999/run", json={"tools": ["strings"]}).status_code == 404


def test_summary_for_the_gui(client):
    s = client.get(f"/api/v1/projects/{PID}/summary").json()
    assert s["route_ids"] == [901, 902]
    assert [x["name"] for x in s["route_steps"]] == ["chall.zip", "inner.txt"]
    assert s["route_steps"][1]["flag"] is True
    assert 802 in s["solver_run_ids"] and "strings" in s["solver_tools"]
    assert "inner.txt" in s["route_tree"]


def test_waves_isolate_consumers():
    from backend.pipeline import _waves
    plan = ["file", "strings", "binwalk-scan", "nested-archive", "git", "7z", "office"]
    assert _waves(plan) == [["file", "strings", "binwalk-scan"], ["nested-archive"], ["git"],
                            ["7z", "office"]]


def test_stats_aggregate(client):
    st = client.get("/api/v1/stats?window=50").json()
    assert st["projects"] >= 1 and isinstance(st["topTools"], list)
    me = st["perProject"].get(PID)
    assert me and me["flagsN"] >= 1


def _view_with(tmp_path, output: str, finding_source: str, context: str):
    from backend.models import FileNode, Finding, Project, ToolRun
    from backend.report import ProjectView
    out = tmp_path / "psimage.out"
    out.write_text(output)
    run = ToolRun(id=1, project_id="ev", file_id=10, tool="psimage", output_path=None)
    f = Finding(id=5, project_id="ev", file_id=10, kind="flag", value="flag{decoded_one}",
                source=finding_source, context=context)
    v = ProjectView(project=Project(id="ev", name="ev"), nodes=[FileNode(id=10, project_id="ev", name="duck.png")],
                    runs=[run], findings=[f], events=[], locked={})
    v._outputs[1] = output
    return v, f


def test_evidence_of_a_decoded_flag_points_at_the_encoded_text(tmp_path):
    from backend.report import MATCH_MARK
    v, f = _view_with(tmp_path, '# commands:\n# psimage duck.png\n\n$a = "QUJDREVGR0hJSktMTU5PUA=="\n',
                      "xor:psimage:duck.png", "«flag{decoded_one}»" + MATCH_MARK + "QUJDREVGR0hJSktMTU5PUA==")
    ev = v.evidence_for(f)
    assert ev["run"] == 1 and ev["tool"] == "psimage" and ev["decoded"] == "XOR of two strings"
    assert "QUJDREVGR0hJSktMTU5PUA==" in ev["lines"]


def test_evidence_falls_back_to_the_source_tool_run(tmp_path):
    v, f = _view_with(tmp_path, "nothing literal here", "b64:psimage:duck.png", "«flag{decoded_one}»")
    ev = v.evidence_for(f)
    assert ev["run"] == 1 and ev["decoded"] == "base64"


def test_raw_scan_evidence_is_a_hexdump_at_the_offset(tmp_path, monkeypatch):
    from backend import storage
    v, f = _view_with(tmp_path, "", "raw:duck.png", "xx «flag{decoded_one}» yy")
    v.nodes[0].rel_path = "uploads/duck.png"
    proj = tmp_path / "proj"
    (proj / "uploads").mkdir(parents=True)
    (proj / "uploads" / "duck.png").write_bytes(b"\x89PNG" + b"\x00" * 60 + b"flag{decoded_one}" + b"\x00" * 20)
    monkeypatch.setattr(storage, "project_dir", lambda pid: proj)
    ev = v.evidence_for(f)
    assert ev["run"] is None and ev["tool"] == "file bytes" and ev["command"] == "offset 0x40"
    assert "00000040: 66 6c 61 67" in ev["lines"]


def test_hunt_stores_the_encoded_token_for_decoded_flags():
    import base64

    from sqlmodel import Session, select

    from backend.db import engine, init_db
    from backend.flaghunt import hunt
    from backend.models import Finding, Project
    from backend.report import split_context
    init_db()
    tok = base64.b64encode(b"here is flag{b64_inside_out}").decode()
    with Session(engine) as s:
        s.add(Project(id="ev-hunt", name="x", status="running"))
        s.commit()
        hunt(s, "ev-hunt", None, f"Comment: {tok}", "exiftool:x.jpg")
        s.commit()
        f = s.exec(select(Finding).where(Finding.project_id == "ev-hunt")).first()
    assert f.value == "flag{b64_inside_out}" and f.source.startswith("b64:exiftool")
    assert split_context(f.context)[1] == tok


def test_old_xor_finding_recovers_the_operand(tmp_path):
    a = "flag{decoded_one}".encode()
    key = b"K" * len(a)
    x = bytes(p ^ q for p, q in zip(a, key)).decode("latin-1")
    out = f'$m = "{x}"\n$k = "{key.decode()}"\n'
    v, f = _view_with(tmp_path, out, "xor:psimage:duck.png", "«flag{decoded_one}»")
    ev = v.evidence_for(f)
    assert ev["run"] == 1 and ev["match"] in (x, key.decode()) and "$m" in ev["lines"]


def test_carved_files_are_not_carved_again():
    from backend.planner import _plan_for
    up = _plan_for("x.bin", None, False)
    carved = _plan_for("x.bin", None, False, made_by="foremost")
    from_archive = _plan_for("x.bin", None, False, made_by="7z")
    assert {"binwalk-scan", "binwalk-extract", "foremost"} <= set(up)
    assert not {"binwalk-scan", "binwalk-extract", "foremost"} & set(carved)
    assert set(from_archive) == set(up)
    assert "strings" in carved and "7z" in _plan_for("x.zip", None, False, made_by="foremost")
