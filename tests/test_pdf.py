"""Phase 11: PDF export. Checks content, not looks (looks were checked by rendering pages)."""

import pytest

pytest.importorskip("reportlab")
pypdf = pytest.importorskip("pypdf")

from pmgen.evidence_pack import build_pack  # noqa: E402
from pmgen.ingest import ingest_folder  # noqa: E402
from pmgen.llm import FakeClient  # noqa: E402
from pmgen.pdf import _t, main, pdf_bytes, pdf_filename, timeline_drawing  # noqa: E402
from pmgen.postmortem import generate, render_markdown  # noqa: E402
from pmgen.samples import DATA_DIR  # noqa: E402
from pmgen.verify import verify  # noqa: E402

from .test_impact import phase8_draft  # noqa: E402

INC = "INC-2026-001"


@pytest.fixture(scope="module")
def report():
    pack = build_pack(ingest_folder(DATA_DIR / INC))
    d = phase8_draft(pack)
    d["corrective_actions"][0]["citations"].append({"record_id": "K01", "quote": pack.kb["K01"].text[:40]})
    return generate(pack, FakeClient([d]))


def _text(data: bytes, tmp_path) -> tuple[str, int]:
    f = tmp_path / "x.pdf"
    f.write_bytes(data)
    r = pypdf.PdfReader(str(f))
    return "\n".join(p.extract_text() for p in r.pages), len(r.pages)


def test_filename_matches_spec():
    assert pdf_filename("INC-2026-001") == "Cybersecurity_Incident_Postmortem_INC-2026-001.pdf"


def test_pdf_has_every_required_section(report, tmp_path):
    text, pages = _text(pdf_bytes(report, verify(report, DATA_DIR / INC)), tmp_path)
    assert pages >= 3
    for s in ("CYBERSECURITY INCIDENT POSTMORTEM", "DRAFT", "1. Executive summary", "2. Timeline", "3. What happened",
              "4. Indicators of compromise", "5. MITRE ATT&CK", "6. Root cause", "Immediate cause",
              "7. Impact assessment", "8. Response analysis", "9. Detection gaps", "10. Lessons learned",
              "11. Corrective actions", "12. Open questions", "References", "Evidence file hashes",
              "Independent verification", "PASS", f"Page 1 of {pages}", f"Page {pages} of {pages}"):
        assert s in text, s


def test_citation_numbers_match_markdown(report, tmp_path):
    text, _ = _text(pdf_bytes(report), tmp_path)
    md = render_markdown(report)
    # the root-cause record is E17 in both, so a reader can move between the two formats
    import re
    md_ref = re.search(r"MFA was not enforced for the account (\[E\d+\])", md).group(1)
    assert md_ref in text


def test_without_evidence_folder_says_so(report, tmp_path):
    text, _ = _text(pdf_bytes(report, None), tmp_path)
    assert "not run (evidence folder not available)" in text


def test_unsupported_characters_and_markup_are_safe(report, tmp_path):
    pm = report.model_copy(deep=True)
    pm.executive_summary = "Attack → contained <b>not bold</b> & 5 ≥ 3 · emoji 🔥 ok"
    text, _ = _text(pdf_bytes(pm), tmp_path)
    assert "Attack -> contained <b>not bold</b> & 5 >= 3" in text
    assert _t("a<b>&c") == "a&lt;b&gt;&amp;c"


def test_timeline_drawing_skips_undated(report):
    pm = report.model_copy(deep=True)
    for e in pm.timeline.events:
        e.timestamp = None
    assert timeline_drawing(pm) is None
    assert timeline_drawing(report) is not None


def test_cli_writes_file(report, tmp_path, capsys):
    src = tmp_path / "in"
    src.mkdir()
    (src / f"{INC}_postmortem.json").write_text(report.model_dump_json(), encoding="utf-8")
    assert main([str(src), "--out", str(tmp_path / "out")]) == 0
    out = tmp_path / "out" / pdf_filename(INC)
    assert out.is_file() and out.read_bytes()[:5] == b"%PDF-"


def test_chart_axis_shows_date_when_events_cross_midnight(report):
    from datetime import timedelta
    from reportlab.graphics.shapes import String
    pm = report.model_copy(deep=True)
    pm.timeline.events[-1].timestamp = pm.timeline.events[0].timestamp + timedelta(hours=20)
    labels = [s.text for s in timeline_drawing(pm).contents if isinstance(s, String)]
    first = pm.timeline.events[0].timestamp.strftime("%d %b")
    assert any(first in t for t in labels), labels                     # dates on the axis
    same_day = [s.text for s in timeline_drawing(report).contents if isinstance(s, String)]
    assert not any(first in t for t in same_day)                       # same-day stays short


def test_close_milestone_labels_do_not_overlap(report):
    from datetime import timedelta
    from reportlab.graphics.shapes import String
    pm = report.model_copy(deep=True)
    # stretch the axis so response start and containment (6 minutes apart) land a few points apart
    pm.timeline.events[-1].timestamp = pm.timeline.events[0].timestamp + timedelta(hours=11)
    labels = [s for s in timeline_drawing(pm).contents if isinstance(s, String) and s.text in ("R", "C")]
    (r,), (c,) = [x for x in labels if x.text == "R"], [x for x in labels if x.text == "C"]
    assert abs(r.x - c.x) < 12 and r.y != c.y
