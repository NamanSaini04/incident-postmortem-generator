"""Phase 11: export a postmortem as a PDF.

Usage:  python -m pmgen.pdf reports/phase8/INC-2026-001_postmortem.json [--out DIR]
        python -m pmgen.pdf reports/phase8/            (every *_postmortem.json in the folder)
Writes  Cybersecurity_Incident_Postmortem_<Incident_ID>.pdf

Same content and the same [E#]/[P#] citation numbers as the Markdown report.
The verification result is included when the evidence folder is available.
Pure ReportLab (no browser), so it also works on Streamlit Community Cloud.
"""
from __future__ import annotations

import io
import re
import sys
from datetime import datetime
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.graphics.shapes import Circle, Drawing, Line, Polygon, Rect, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas as rl_canvas
from reportlab.platypus import (KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table,
                                TableStyle)

from .postmortem import _Cites, _PolicyCites, fmt_duration
from .schemas import Postmortem, Priority, TimeBasis
from .verify import VerifyResult

NAVY = colors.HexColor("#0F172A")
BLUE = colors.HexColor("#0369A1")
AMBER = colors.HexColor("#B45309")
GREY = colors.HexColor("#64748B")
LIGHT = colors.HexColor("#F1F5F9")
LINE = colors.HexColor("#CBD5E1")
RED = colors.HexColor("#B91C1C")
PRIORITY_COLOUR = {Priority.CRITICAL: RED, Priority.HIGH: AMBER, Priority.MEDIUM: BLUE, Priority.LOW: GREY}
PAGE_W, PAGE_H = A4
MARGIN = 18 * mm
CONTENT_W = PAGE_W - 2 * MARGIN

# Built-in PDF fonts only cover Latin-1/cp1252. Map the few other characters the model uses.
_CHARMAP = {"→": "->", "←": "<-", "≥": ">=", "≤": "<=", "≈": "~", "×": "x", "✓": "yes", "✗": "no",
            "‑": "-", " ": " "}


def pdf_filename(incident_id: str) -> str:
    return f"Cybersecurity_Incident_Postmortem_{incident_id}.pdf"


def _t(s) -> str:
    """Text safe for a ReportLab Paragraph: no unsupported characters, XML escaped."""
    s = "".join(_CHARMAP.get(ch, ch) for ch in str(s))
    s = s.encode("cp1252", errors="replace").decode("cp1252")
    return escape(s)


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    body = ParagraphStyle("body", parent=base["BodyText"], fontName="Helvetica", fontSize=9.5, leading=13)
    return {
        "body": body,
        "small": ParagraphStyle("small", parent=body, fontSize=8, leading=10.5),
        "cell": ParagraphStyle("cell", parent=body, fontSize=8, leading=10),
        "cellb": ParagraphStyle("cellb", parent=body, fontSize=8, leading=10, fontName="Helvetica-Bold"),
        "th": ParagraphStyle("th", parent=body, fontSize=8, leading=10, fontName="Helvetica-Bold",
                             textColor=colors.white),
        "muted": ParagraphStyle("muted", parent=body, fontSize=8, leading=10, textColor=GREY),
        "h1": ParagraphStyle("h1", parent=base["Heading1"], fontName="Helvetica-Bold", fontSize=14,
                             textColor=NAVY, spaceBefore=10, spaceAfter=6, keepWithNext=1),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], fontName="Helvetica-Bold", fontSize=11,
                             textColor=NAVY, spaceBefore=6, spaceAfter=4, keepWithNext=1),
        "title": ParagraphStyle("title", parent=body, fontName="Helvetica-Bold", fontSize=22, leading=27,
                                textColor=NAVY, spaceAfter=10),
        "kicker": ParagraphStyle("kicker", parent=body, fontName="Helvetica-Bold", fontSize=10,
                                 textColor=BLUE, spaceAfter=4),
        "banner": ParagraphStyle("banner", parent=body, fontName="Helvetica-Bold", fontSize=9.5,
                                 textColor=AMBER, alignment=TA_CENTER),
    }


def _table(rows, widths, header=True, zebra=True) -> Table:
    t = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
    style = [("VALIGN", (0, 0), (-1, -1), "TOP"), ("GRID", (0, 0), (-1, -1), 0.4, LINE),
             ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
             ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]
    if header:
        style += [("BACKGROUND", (0, 0), (-1, 0), NAVY), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white)]
    if zebra:
        for r in range(1 if header else 0, len(rows)):
            if r % 2 == 0:
                style.append(("BACKGROUND", (0, r), (-1, r), LIGHT))
    t.setStyle(TableStyle(style))
    return t


def timeline_drawing(pm: Postmortem, width: float = CONTENT_W) -> Drawing | None:
    """One row per evidence file, one dot per event. Diamond = key event, A/D/R/C = response milestones.
    Blue = exact time; amber = date inferred or timezone assumed."""
    events = [e for e in pm.timeline.events if e.timestamp is not None]
    if not events:
        return None
    files = sorted({e.sources[0].file if e.sources else "?" for e in events})
    left, right, top_pad, row_h = 95, 12, 22, 22
    height = top_pad + row_h * len(files) + 52
    d = Drawing(width, height)
    t0, t1 = min(e.timestamp for e in events), max(e.timestamp for e in events)
    span = max((t1 - t0).total_seconds(), 1)

    def x(ts):
        return left + (width - left - right) * (ts - t0).total_seconds() / span

    def y(f):
        return height - top_pad - row_h * files.index(f) - row_h / 2

    for f in files:
        d.add(Line(left, y(f), width - right, y(f), strokeColor=LINE, strokeWidth=0.5))
        d.add(String(left - 6, y(f) - 3, _t(f)[:22], fontName="Helvetica", fontSize=7, fillColor=GREY,
                     textAnchor="end"))
    key = set(pm.key_event_ids)
    letters = {"attack_start": "A", "first_detection": "D", "response_start": "R", "containment": "C"}
    marks: dict[str, list[str]] = {}
    if pm.response:
        for name, m in pm.response.milestones.items():
            if m:
                marks.setdefault(m.event_id, []).append(letters[name])
    for e in events:
        f = e.sources[0].file if e.sources else "?"
        cx, cy = x(e.timestamp), y(f)
        col = BLUE if e.time_basis is TimeBasis.EXACT else AMBER
        if e.event_id in key:
            r = 4.2
            d.add(Polygon([cx, cy + r, cx + r, cy, cx, cy - r, cx - r, cy], fillColor=col, strokeColor=col))
        else:
            d.add(Circle(cx, cy, 2.6, fillColor=col, strokeColor=col))
        if e.event_id in marks:
            d.add(String(cx, cy + 6, "".join(marks[e.event_id]), fontName="Helvetica-Bold", fontSize=7,
                         fillColor=NAVY, textAnchor="middle"))
    base = 36
    d.add(Line(left, base, width - right, base, strokeColor=GREY, strokeWidth=0.5))
    for i in range(5):
        ts = t0 + (t1 - t0) * (i / 4)
        label = ts.strftime("%d %b %H:%M") if span > 86400 else ts.strftime("%H:%M")
        d.add(Line(x(ts), base, x(ts), base - 3, strokeColor=GREY, strokeWidth=0.5))
        d.add(String(x(ts), base - 12, label, fontName="Helvetica", fontSize=7, fillColor=GREY,
                     textAnchor="middle"))
    lx = left
    for colr, label in ((BLUE, "exact time"), (AMBER, "date inferred / timezone assumed")):
        d.add(Rect(lx, 12, 6, 6, fillColor=colr, strokeColor=colr))
        d.add(String(lx + 9, 12.5, label, fontName="Helvetica", fontSize=7, fillColor=GREY))
        lx += 150
    d.add(String(left, 1, "Diamond = key event.  A / D / R / C = attack start / first detection / "
                 "response start / containment.", fontName="Helvetica", fontSize=7, fillColor=GREY))
    return d


class _NumberedCanvas(rl_canvas.Canvas):
    """Adds 'Page X of Y' and a running header; needs all pages first to know Y."""

    def __init__(self, *args, header: str = "", **kwargs):
        super().__init__(*args, **kwargs)
        self._pages, self._header = [], header

    def showPage(self):  # noqa: N802 (ReportLab API)
        self._pages.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total = len(self._pages)
        for state in self._pages:
            self.__dict__.update(state)
            if self._pageNumber > 1:
                self.setFont("Helvetica", 7.5)
                self.setFillColor(GREY)
                self.drawString(MARGIN, PAGE_H - 12 * mm, self._header)
                self.drawRightString(PAGE_W - MARGIN, PAGE_H - 12 * mm, "DRAFT: requires human review")
                self.setStrokeColor(LINE)
                self.line(MARGIN, PAGE_H - 13.5 * mm, PAGE_W - MARGIN, PAGE_H - 13.5 * mm)
            self.setFont("Helvetica", 7.5)
            self.setFillColor(GREY)
            self.drawCentredString(PAGE_W / 2, 10 * mm, f"Page {self._pageNumber} of {total}")
            super().showPage()
        super().save()


def build_pdf(pm: Postmortem, out, check: VerifyResult | None = None) -> None:
    """Write the PDF to a path or a binary file-like object."""
    S = _styles()
    cite, pcite = _Cites(), _PolicyCites()
    story: list = []
    P = lambda text, st="body": Paragraph(text, S[st])  # noqa: E731

    def refs(evidence) -> str:
        c = cite(evidence)
        return f' <font color="#64748B" size="7">{c.strip()}</font>' if c else ""

    def prefs(policy) -> str:
        c = pcite(policy)
        return f' <font color="#64748B" size="7">{c.strip()}</font>' if c else ""

    def certainty(c) -> str:
        colour = {"confirmed": "#0369A1", "probable": "#B45309"}.get(c.value, "#64748B")
        return f'<font color="{colour}"><b>[{c.value}]</b></font>'

    title = re.sub(rf"^\s*{re.escape(pm.incident_id)}\s*[:\-]\s*", "", pm.title)

    # ---------------------------------------------------------------- title page
    story += [Spacer(1, 30 * mm), P("CYBERSECURITY INCIDENT POSTMORTEM", "kicker"), P(_t(title), "title"),
              Spacer(1, 4 * mm)]
    banner = Table([[P("DRAFT: requires human review. Generated by code plus an LLM from synthetic evidence. "
                       "Every claim cites its source record.", "banner")]], colWidths=[CONTENT_W])
    banner.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FEF3C7")),
                                ("BOX", (0, 0), (-1, -1), 0.6, AMBER), ("TOPPADDING", (0, 0), (-1, -1), 6),
                                ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
    story += [banner, Spacer(1, 8 * mm)]
    verdict = "not run (evidence folder not available)"
    if check is not None:
        n = sum(c.checked for c in check.checks)
        verdict = f"{'PASS' if check.ok else 'FAIL'} ({n} items re-checked against the evidence files)"
    meta = [("Incident ID", pm.incident_id), ("Incident title", title),
            ("Date", pm.timeline.events[0].timestamp.strftime("%Y-%m-%d") if pm.timeline.events
             and pm.timeline.events[0].timestamp else "unknown"),
            ("Severity", pm.severity.value), ("Category", pm.category.value.replace("_", " ")),
            ("Classification confidence", f"{pm.classification_confidence:.0%}"),
            ("Final status", "Draft, pending human review"), ("Independent verification", verdict),
            ("Generated", f"{pm.generated_at:%Y-%m-%d %H:%M} UTC by {pm.model}")]
    story.append(_table([[P(_t(k), "cellb"), P(_t(v), "cell")] for k, v in meta], [48 * mm, CONTENT_W - 48 * mm],
                        header=False))
    story += [Spacer(1, 10 * mm),
              P("Defensive use only. All incident data in this report is synthetic.", "muted"), PageBreak()]

    # ---------------------------------------------------------------- 1 summary
    story += [P("1. Executive summary", "h1"), P(_t(pm.executive_summary)), Spacer(1, 2 * mm),
              P(f"<b>Severity rationale:</b> {_t(pm.severity_rationale)}")]

    # ---------------------------------------------------------------- 2 timeline
    story.append(P("2. Timeline (UTC)", "h1"))
    story.append(P("Built by code from the evidence, not by the LLM.", "muted"))
    dr = timeline_drawing(pm)
    if dr:
        story += [Spacer(1, 2 * mm), dr, Spacer(1, 3 * mm)]
    key = set(pm.key_event_ids)
    rows = [[P("ID", "th"), P("Time", "th"), P("Event", "th"), P("Basis", "th"), P("Src", "th")]]
    for e in pm.timeline.events:
        st = "cellb" if e.event_id in key else "cell"
        basis = "exact" if e.time_basis is TimeBasis.EXACT else e.time_basis.value.replace("_", " ")
        rows.append([P(_t(e.event_id), st), P(f"{e.timestamp:%m-%d %H:%M:%S}" if e.timestamp else "?", st),
                     P(_t(e.description[:160]), st), P(basis, "cell"), P(_t(cite(e.sources).strip()), "cell")])
    story.append(_table(rows, [14 * mm, 26 * mm, CONTENT_W - 84 * mm, 24 * mm, 20 * mm]))
    story.append(P("Bold = key event.", "muted"))

    # ---------------------------------------------------------------- 3 what happened
    story.append(P("3. What happened", "h1"))
    for f in pm.what_happened:
        story.append(P(f"{certainty(f.certainty)} {_t(f.statement)}{refs(f.evidence)}"))

    # ---------------------------------------------------------------- 4 IOCs
    story.append(P("4. Indicators of compromise", "h1"))
    if pm.indicators:
        rows = [[P("Indicator", "th"), P("Type", "th"), P("First seen", "th")]]
        rows += [[P(_t(i.value), "cell"), P(i.entity_type.value, "cell"), P(_t(cite([i.first_seen]).strip()), "cell")]
                 for i in pm.indicators]
        story.append(_table(rows, [CONTENT_W - 55 * mm, 25 * mm, 30 * mm]))
        story.append(P("Only values found in the evidence; nothing invented.", "muted"))
    else:
        story.append(P("None identified.", "muted"))

    # ---------------------------------------------------------------- 5 ATT&CK
    story.append(P("5. MITRE ATT&amp;CK mapping", "h1"))
    if pm.attack:
        rows = [[P(h, "th") for h in ("Tactic", "Technique", "ID", "Certainty", "Behaviour", "Evidence")]]
        for a in pm.attack:
            rows.append([P(_t(a.tactic), "cell"), P(_t(a.technique_name), "cell"), P(_t(a.technique_id), "cell"),
                         P(a.certainty.value, "cell"), P(_t(a.rationale), "cell"), P(_t(cite(a.evidence).strip()), "cell")])
        story.append(_table(rows, [26 * mm, 32 * mm, 17 * mm, 17 * mm, CONTENT_W - 112 * mm, 20 * mm]))
        story.append(P(_t(f"IDs checked against {pm.attack_catalog or 'the bundled ATT&CK catalogue'}. "
                          "ATT&CK is a registered trademark of The MITRE Corporation."), "muted"))
    else:
        story.append(P("No techniques mapped.", "muted"))

    # ---------------------------------------------------------------- 6 root cause
    story.append(P("6. Root cause", "h1"))
    if pm.immediate_cause:
        ic = pm.immediate_cause
        story.append(P(f"<b>Immediate cause</b> {certainty(ic.certainty)} {_t(ic.statement)}{refs(ic.evidence)}"))
    if pm.root_cause:
        story.append(P(f"<b>Root cause</b> {certainty(pm.root_cause.certainty)} {_t(pm.root_cause.statement)}"
                       f"{refs(pm.root_cause.evidence)}"))
    else:
        story.append(P("Root cause not determined: the draft failed validation.", "muted"))
    if pm.contributing_factors:
        story.append(P("Contributing factors", "h2"))
        for f in pm.contributing_factors:
            story.append(P(f"{certainty(f.certainty)} {_t(f.statement)}{refs(f.evidence)}"))

    # ---------------------------------------------------------------- 7 impact + 8 response
    story.append(P("7. Impact assessment", "h1"))
    imp = pm.impact
    rows = [[P("Systems involved", "cellb"), P(_t(", ".join(imp.systems_involved) or "none identified"), "cell")],
            [P("Accounts involved", "cellb"), P(_t(", ".join(imp.accounts_involved) or "none identified"), "cell")]]
    for label, f in (("Data affected", imp.data_affected), ("Operational impact", imp.operational_impact),
                     ("Business impact", imp.business_impact)):
        rows.append([P(label, "cellb"), P(f"{certainty(f.certainty)} {_t(f.statement)}{refs(f.evidence)}"
                                          if f else "not assessed", "cell")])
    story.append(KeepTogether(_table(rows, [38 * mm, CONTENT_W - 38 * mm], header=False)))

    response_head = [P("8. Response analysis", "h1"),
                     P("Milestones chosen by the model from the timeline; durations computed by code.", "muted")]
    if pm.response:
        rows = [[P(h, "th") for h in ("Milestone", "Event", "Time (UTC)", "Basis")]]
        for name, m in pm.response.milestones.items():
            rows.append([P(name.replace("_", " "), "cell"), P(m.event_id if m else "-", "cell"),
                         P(f"{m.timestamp:%Y-%m-%d %H:%M:%S}" if m else "not in evidence", "cell"),
                         P(m.time_basis.value.replace("_", " ") if m else "-", "cell")])
        milestones = _table(rows, [40 * mm, 22 * mm, 45 * mm, CONTENT_W - 107 * mm])
        rows = [[P(h, "th") for h in ("Measure", "From -> to", "Duration")]]
        for dd in pm.response.durations:
            rows.append([P(dd.name.replace("_", " "), "cell"),
                         P(f"{dd.start.replace('_', ' ')} -> {dd.end.replace('_', ' ')}", "cell"),
                         P(fmt_duration(dd.seconds) + (" (approximate: inferred time)" if dd.approximate else ""),
                           "cell")])
        story.append(KeepTogether(response_head + [milestones, Spacer(1, 2 * mm),
                                                   _table(rows, [35 * mm, 60 * mm, CONTENT_W - 95 * mm])]))
    else:
        story += response_head + [P("Not computed: the milestones failed validation.", "muted")]

    # ---------------------------------------------------------------- 9 gaps, 10 lessons
    story.append(P("9. Detection gaps", "h1"))
    for f in pm.detection_gaps:
        story.append(P(f"{certainty(f.certainty)} {_t(f.statement)}{refs(f.evidence)}"))
    if not pm.detection_gaps:
        story.append(P("None validated.", "muted"))

    story.append(P("10. Lessons learned", "h1"))
    for area in ("people", "process", "technology", "governance"):
        items = [x for x in pm.lessons if x.area == area]
        if items:
            story.append(P(area.capitalize(), "h2"))
            for x in items:
                story.append(P(f"- {_t(x.lesson)}{refs(x.evidence)}{prefs(x.policy_refs)}"))

    # ---------------------------------------------------------------- 11 actions
    story.append(P("11. Corrective actions", "h1"))
    order = {Priority.CRITICAL: 0, Priority.HIGH: 1, Priority.MEDIUM: 2, Priority.LOW: 3}
    rows = [[P(h, "th") for h in ("Priority", "Action", "Why", "Owner", "When", "Benefit")]]
    for a in sorted(pm.corrective_actions, key=lambda a: order[a.priority]):
        colour = PRIORITY_COLOUR[a.priority].hexval().replace("0x", "#")
        rows.append([P(f'<font color="{colour}"><b>{a.priority.value}</b></font>', "cell"),
                     P(_t(a.recommendation), "cell"),
                     P(f"{_t(a.reason)}{refs(a.supporting_evidence)}{prefs(a.policy_refs)}", "cell"),
                     P(_t(a.owner_team), "cell"), P(_t(a.timeframe), "cell"), P(_t(a.expected_benefit), "cell")])
    story.append(_table(rows, [15 * mm, 48 * mm, 45 * mm, 20 * mm, 18 * mm, CONTENT_W - 146 * mm]))

    # ---------------------------------------------------------------- 12 open questions / risks
    story.append(P("12. Open questions and remaining risks", "h1"))
    for q in pm.open_questions:
        story.append(P(f"<b>Open:</b> {_t(q)}"))
    for r in pm.remaining_risks:
        story.append(P(f"<b>Risk:</b> {_t(r)}"))

    # ---------------------------------------------------------------- references
    story += [PageBreak(), P("References", "h1"), P("Evidence", "h2")]
    rows = [[P(h, "th") for h in ("Ref", "File", "Location", "Quote")]]
    for (file, loc), n in sorted(cite.index.items(), key=lambda kv: kv[1]):
        rows.append([P(f"E{n}", "cell"), P(_t(file), "cell"), P(_t(loc), "cell"), P(_t(cite.quotes[n][:200]), "cell")])
    story.append(_table(rows, [12 * mm, 35 * mm, 25 * mm, CONTENT_W - 72 * mm]))
    if pcite.items:
        story.append(P("Company policies and playbooks (synthetic knowledge base)", "h2"))
        rows = [[P(h, "th") for h in ("Ref", "Section", "Quote")]]
        for n, r in sorted(pcite.items.items()):
            rows.append([P(f"P{n}", "cell"), P(_t(f"{r.doc_id} §{r.section} {r.title}"), "cell"),
                         P(_t(r.excerpt[:200]), "cell")])
        story.append(_table(rows, [12 * mm, 55 * mm, CONTENT_W - 67 * mm]))
    story.append(P("Evidence file hashes (SHA-256)", "h2"))
    story.append(_table([[P(_t(f), "cell"), P(h, "small")] for f, h in sorted(pm.file_hashes.items())],
                        [40 * mm, CONTENT_W - 40 * mm], header=False))
    story.append(P("Validation log", "h2"))
    for line in pm.validation_log or ["(empty)"]:
        story.append(P(_t(line), "small"))
    if check is not None:
        story.append(P("Independent verification", "h2"))
        rows = [[P(h, "th") for h in ("Check", "Items", "Result")]]
        for c in check.checks:
            rows.append([P(_t(c.name), "cell"), P(str(c.checked), "cell"),
                         P("ok" if c.ok else f"{len(c.failures)} failed", "cell")])
        story.append(KeepTogether(_table(rows, [CONTENT_W - 50 * mm, 20 * mm, 30 * mm])))
        story.append(P("Proves claims are grounded in the cited evidence, not that they are true.", "muted"))

    doc = SimpleDocTemplate(out, pagesize=A4, leftMargin=MARGIN, rightMargin=MARGIN, topMargin=20 * mm,
                            bottomMargin=18 * mm, title=_t(f"Incident Postmortem {pm.incident_id}"),
                            author="pmgen (draft, requires human review)", subject=_t(title))
    header = f"{pm.incident_id} | {pm.severity.value} | {pm.category.value.replace('_', ' ')}"
    doc.build(story, canvasmaker=lambda *a, **k: _NumberedCanvas(*a, header=header, **k))


def pdf_bytes(pm: Postmortem, check: VerifyResult | None = None) -> bytes:
    buf = io.BytesIO()
    build_pdf(pm, buf, check)
    return buf.getvalue()


def main(argv: list[str] | None = None) -> int:
    from .samples import find_data_dir
    from .verify import verify

    argv = sys.argv[1:] if argv is None else argv
    out_dir = None
    if "--out" in argv:
        i = argv.index("--out")
        out_dir = Path(argv[i + 1])
        argv = argv[:i] + argv[i + 2:]
    files: list[Path] = []
    for a in argv:
        p = Path(a)
        files += sorted(p.glob("*_postmortem.json")) if p.is_dir() else [p]
    if not files:
        print("usage: python -m pmgen.pdf REPORT.json|FOLDER [...] [--out DIR]", file=sys.stderr)
        return 2
    for f in files:
        pm = Postmortem.model_validate_json(f.read_text(encoding="utf-8"))
        edir = find_data_dir() / pm.incident_id
        check = verify(pm, edir) if edir.is_dir() else None
        target = (out_dir or f.parent) / pdf_filename(pm.incident_id)
        target.parent.mkdir(parents=True, exist_ok=True)
        build_pdf(pm, str(target), check)
        print(f"wrote {target}  ({datetime.now():%H:%M:%S})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
