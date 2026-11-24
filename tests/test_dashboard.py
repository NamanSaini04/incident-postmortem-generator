"""Phase 10: dashboard data layer (always) and a smoke test of the Streamlit app (if installed)."""

from pathlib import Path

import pytest

from pmgen import dashboard_data as dd
from pmgen.evidence_pack import build_pack
from pmgen.ingest import ingest_folder
from pmgen.llm import FakeClient
from pmgen.postmortem import generate
from pmgen.samples import DATA_DIR
from pmgen.schemas import Priority

from .test_impact import phase8_draft

INC = "INC-2026-001"
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def report():
    pack = build_pack(ingest_folder(DATA_DIR / INC))
    return generate(pack, FakeClient([phase8_draft(pack)]))


@pytest.fixture
def reports_dir(report, tmp_path, monkeypatch):
    (tmp_path / f"{INC}_postmortem.json").write_text(report.model_dump_json(), encoding="utf-8")
    (tmp_path / f"{INC}_postmortem_norag.json").write_text("not read", encoding="utf-8")
    monkeypatch.setenv(dd.ENV_REPORTS, str(tmp_path))
    return tmp_path


def test_loads_main_reports_only(reports_dir):
    got = dd.load_reports(reports_dir)
    assert list(got) == [INC]          # the _norag file is skipped (it is not even valid JSON)
    assert dd.find_reports_dir() == reports_dir


def test_bundle_has_verification_and_score(report):
    b = dd.load_bundle(report, DATA_DIR)
    assert b.check.ok
    assert b.score is not None and b.score.milestone_accuracy == 1.0


def test_overview_never_claims_final(report):
    ov = dd.overview(report)
    assert ov["Status"].startswith("Draft")
    assert ov["Accounts involved"] == "j.patel"


def test_timeline_rows_mark_key_events_and_milestones(report):
    rows = dd.timeline_rows(report)
    assert [r["event_id"] for r in rows] == [e.event_id for e in report.timeline.events if e.timestamp]
    times = [r["time"] for r in rows]
    assert times == sorted(times)
    marked = {r["event_id"]: r["milestone"] for r in rows if r["milestone"]}
    assert set(marked.values()) == {"attack start", "first detection", "response start", "containment"}
    assert any(r["key"] for r in rows)
    assert {r["kind"] for r in rows} == {"response milestone", "key event", "other event"}


def test_evidence_rows_count_citations(report):
    rows = dd.evidence_rows(report, DATA_DIR / INC)
    by_loc = {(r["file"], r["locator"]): r["cited_by_claims"] for r in rows}
    assert by_loc[("analyst_notes.txt", "line 8")] >= 2   # root cause + lesson + action all cite it
    assert by_loc[("email_gateway.csv", "row 3")] == 0     # the unrelated vendor newsletter
    assert 0 < dd.uncited_share(rows) < 1


def test_actions_sorted_by_priority(report):
    pm = report.model_copy(deep=True)
    pm.corrective_actions.append(pm.corrective_actions[0].model_copy(update={"priority": Priority.LOW}))
    pm.corrective_actions.insert(0, pm.corrective_actions[0].model_copy(update={"priority": Priority.MEDIUM}))
    order = [r["priority"] for r in dd.action_rows(pm)]
    assert order == sorted(order, key=["critical", "high", "medium", "low"].index)


def test_duration_rows_in_minutes(report):
    rows = {r["measure"]: r for r in dd.duration_rows(report)}
    assert rows["time to detect"]["minutes"] == pytest.approx(9.97, abs=0.01)
    assert rows["time to respond"]["approximate"] is True


def test_score_rows_format(report):
    rows = {r["metric"]: r["value"] for r in dd.score_rows(dd.load_bundle(report, DATA_DIR).score)}
    assert rows["Category correct"] == "yes" and rows["Response milestones right"] == "100%"
    assert dd.score_rows(None) == []


def test_live_generation_off_by_default(monkeypatch):
    monkeypatch.delenv("PMGEN_LIVE", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "x")
    assert not dd.live_generation_enabled()          # a key alone is not enough
    monkeypatch.setenv("PMGEN_LIVE", "1")
    monkeypatch.delenv("ANTHROPIC_API_KEY")
    assert not dd.live_generation_enabled()


# ---------------------------------------------------------------- the app itself

def test_app_renders_every_tab(reports_dir, monkeypatch):
    pytest.importorskip("streamlit")
    pytest.importorskip("plotly")
    from streamlit.testing.v1 import AppTest

    monkeypatch.delenv("PMGEN_LIVE", raising=False)
    at = AppTest.from_file(str(ROOT / "streamlit_app.py"), default_timeout=60).run()
    assert not at.exception, [e.value for e in at.exception]
    assert len(at.tabs) == 9
    assert "DRAFT" in at.warning[0].value
    assert any("PASS" in m.value for m in at.metric)
    assert not any("Live generation" in s.value for s in at.sidebar.subheader)
    text = " ".join(m.value for m in at.markdown)
    assert "Immediate cause" in text and "Exchange Online" in text


def test_app_explains_missing_reports(tmp_path, monkeypatch):
    pytest.importorskip("streamlit")
    from streamlit.testing.v1 import AppTest

    monkeypatch.setenv(dd.ENV_REPORTS, str(tmp_path))
    at = AppTest.from_file(str(ROOT / "streamlit_app.py"), default_timeout=60).run()
    assert not at.exception
    assert "No saved reports" in at.error[0].value
