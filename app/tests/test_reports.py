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
