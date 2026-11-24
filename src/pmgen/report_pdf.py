"""Phase 14: build the technical report PDF from docs/technical_report.md.

Usage:  python -m pmgen.report_pdf [docs/technical_report.md] [--out docs/Cybersecurity_Incident_Postmortem_Generator_Technical_Report.pdf]

The Markdown file is the source (readable on GitHub); the PDF is generated from it.
Supports the subset the report uses: # title, ## sections, ### subsections, paragraphs,
- bullets, 1. numbered items, | tables |, ``` code blocks, **bold** and `code`.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import PageBreak, Paragraph, Preformatted, SimpleDocTemplate, Spacer, Table

from .pdf import CONTENT_W, GREY, LIGHT, MARGIN, NAVY, _NumberedCanvas, _styles, _t, _table

DEFAULT_SRC = Path("docs/technical_report.md")
DEFAULT_OUT = Path("docs/Cybersecurity_Incident_Postmortem_Generator_Technical_Report.pdf")


def inline(text: str) -> str:
    """Markdown inline -> ReportLab markup, after escaping."""
    s = _t(text)
    s = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", s)
    s = re.sub(r"(?<![\w*])\*(?!\s)(.+?)(?<!\s)\*(?![\w*])", r"<i>\1</i>", s)
    s = re.sub(r"`([^`]+)`", r'<font face="Courier" size="8.5">\1</font>', s)
    return s


def _flush_table(rows: list[str], S) -> Table:
    cells = [[c.strip() for c in r.strip().strip("|").split("|")] for r in rows]
    cells = [r for r in cells if not all(re.fullmatch(r":?-{3,}:?", c) for c in r)]
    ncol = len(cells[0])
    # width by content length, capped so no column dominates
    lens = [max(len(r[i]) if i < len(r) else 0 for r in cells) for i in range(ncol)]
    weights = [min(max(n, 6), 60) for n in lens]
    widths = [CONTENT_W * w / sum(weights) for w in weights]
    data = [[Paragraph(inline(c), S["th"] if r == 0 else S["cell"]) for c in row + [""] * (ncol - len(row))]
            for r, row in enumerate(cells)]
    return _table(data, widths)


def build(md: str) -> list:
    S = _styles()
    S["bullet"] = ParagraphStyle("bullet", parent=S["body"], leftIndent=12, bulletIndent=2, spaceAfter=2)
    S["code"] = ParagraphStyle("code", fontName="Courier", fontSize=7.6, leading=9.6, backColor=LIGHT,
                               borderPadding=5, leftIndent=4, rightIndent=4, spaceBefore=4, spaceAfter=8)
    story: list = []
    lines = md.splitlines()
    i, para, table = 0, [], []

    def flush_para():
        if para:
            story.append(Paragraph(inline(" ".join(para)), S["body"]))
            story.append(Spacer(1, 2 * mm))
            para.clear()

    def flush_table():
        if table:
            story.append(_flush_table(table, S))
            story.append(Spacer(1, 3 * mm))
            table.clear()

    while i < len(lines):
        line = lines[i]
        if line.startswith("```"):
            flush_para(); flush_table()
            block = []
            i += 1
            while i < len(lines) and not lines[i].startswith("```"):
                block.append(lines[i])
                i += 1
            story.append(Preformatted("\n".join(_t(b).replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
                                                  for b in block), S["code"]))
        elif line.startswith("# "):
            flush_para(); flush_table()
            story += [Spacer(1, 28 * mm), Paragraph("TECHNICAL REPORT", S["kicker"]),
                      Paragraph(_t(line[2:].split(":")[0]), S["title"])]
            sub = line[2:].split(":", 1)[1].strip() if ":" in line else ""
            if sub:
                story.append(Paragraph(_t(sub), S["h2"]))
            # the byline paragraph follows the title
            j = i + 1
            while j < len(lines) and not lines[j].strip():
                j += 1
            if j < len(lines) and not lines[j].startswith("#"):
                story.append(Spacer(1, 6 * mm))
                for part in lines[j].split(" · "):
                    story.append(Paragraph(inline(part), S["body"]))
                i = j
            story += [Spacer(1, 10 * mm),
                      Paragraph("All incident data in this report is synthetic. Every figure comes from "
                                "docs/results.md and docs/evaluation.md in the repository.", S["muted"]),
                      PageBreak()]
        elif line.startswith("## "):
            flush_para(); flush_table()
            story.append(Paragraph(_t(line[3:]), S["h1"]))
        elif line.startswith("### "):
            flush_para(); flush_table()
            story.append(Paragraph(_t(line[4:]), S["h2"]))
        elif line.lstrip().startswith("|"):
            flush_para()
            table.append(line)
        elif re.match(r"^\s*(- |\d+\. )", line):
            flush_para(); flush_table()
            m = re.match(r"^\s*(- |(\d+)\. )(.*)", line)
            text = m.group(3)
            while i + 1 < len(lines) and lines[i + 1].startswith("  ") and not re.match(r"^\s*(- |\d+\. )", lines[i + 1]):
                i += 1
                text += " " + lines[i].strip()
            bullet = f"{m.group(2)}." if m.group(2) else "•"
            story.append(Paragraph(inline(text), S["bullet"], bulletText=bullet))
        elif not line.strip():
            flush_para(); flush_table()
        else:
            flush_table()
            para.append(line.strip())
        i += 1
    flush_para(); flush_table()
    return story


def build_pdf(src: Path = DEFAULT_SRC, out: Path = DEFAULT_OUT) -> Path:
    md = Path(src).read_text(encoding="utf-8")
    title = md.splitlines()[0].lstrip("# ").strip()
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(str(out), pagesize=A4, leftMargin=MARGIN, rightMargin=MARGIN, topMargin=20 * mm,
                            bottomMargin=18 * mm, title=_t(title), author="Naman Saini")
    doc.build(build(md), canvasmaker=lambda *a, **k: _NumberedCanvas(
        *a, header="Cybersecurity Incident Postmortem Generator | Technical report", right="Naman Saini, 2026", **k))
    return out


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    out = DEFAULT_OUT
    if "--out" in argv:
        k = argv.index("--out")
        out = Path(argv[k + 1])
        argv = argv[:k] + argv[k + 2:]
    src = Path(argv[0]) if argv else DEFAULT_SRC
    print(f"wrote {build_pdf(src, out)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
