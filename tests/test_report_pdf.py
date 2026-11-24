"""Phase 14: the technical report builds from its Markdown source with all 17 sections."""

from pathlib import Path

import pytest

pytest.importorskip("reportlab")
pypdf = pytest.importorskip("pypdf")

from pmgen.report_pdf import build_pdf, inline  # noqa: E402

SRC = Path(__file__).resolve().parents[1] / "docs" / "technical_report.md"
SECTIONS = ["Executive Summary", "Problem Statement", "Incident Response Background", "LLM Architecture",
            "RAG Architecture", "Evidence Processing", "Timeline Reconstruction", "MITRE ATT&CK Mapping",
            "Root Cause Analysis", "Postmortem Generation", "Evaluation", "Results", "Safety", "Limitations",
            "Future Improvements", "Conclusion", "References"]


def test_source_has_the_17_spec_sections_in_order():
    heads = [line[3:] for line in SRC.read_text(encoding="utf-8").splitlines() if line.startswith("## ")]
    assert len(heads) == 17
    for n, (head, want) in enumerate(zip(heads, SECTIONS), 1):
        assert head.startswith(f"{n}. ") and want in head, head


def test_pdf_builds_with_page_numbers(tmp_path):
    out = build_pdf(SRC, tmp_path / "r.pdf")
    r = pypdf.PdfReader(str(out))
    text = "\n".join(p.extract_text() for p in r.pages)
    n = len(r.pages)
    assert n >= 5 and f"Page {n} of {n}" in text
    assert "17. References" in text and "1401/1401" in text


def test_inline_markup_is_escaped_first():
    assert inline("**bold** <script> `x`") == '<b>bold</b> &lt;script&gt; <font face="Courier" size="8.5">x</font>'
