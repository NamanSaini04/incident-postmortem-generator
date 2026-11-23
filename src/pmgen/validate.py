"""Phase 5: check every LLM claim against the evidence before it reaches a report.

Checks (each produces an Issue naming exactly where the problem is):
  1. Citation points at a record ID that exists in the evidence pack.
  2. The quoted text really appears in that record (stops made-up citations).
  3. Confirmed/probable findings, lessons and corrective actions cite at
     least one valid record.
  4. Every indicator listed as malicious was actually extracted from evidence.
  5. No IP, domain, URL, email or hash appears anywhere in the report text
     unless it appears in the evidence (stops invented IOCs).
  6. Key event IDs exist in the timeline; lesson areas are valid.

What it CANNOT check: whether a cited, correctly quoted record actually
supports the claim's meaning. "MFA was enabled [quote: 'mfa_required']" passes
checks 1-3. That gap is measured in evaluation, and later handled by a
second-pass checker (Phase 9).
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

from pydantic import BaseModel, ValidationError

from .evidence_pack import EvidencePack
from .extract import find_indicators
from .schemas import (
    Certainty,
    Citation,
    CorrectiveAction,
    DraftReport,
    EvidenceRef,
    Finding,
    Indicator,
    KBRef,
    Lesson,
    Postmortem,
)

LESSON_AREAS = {"people", "process", "technology", "governance"}
RECORD_ID = re.compile(r"\bR\d{3,}\b")
KB_ID = re.compile(r"\bK\d{2,}\b")
FINDING_REF = re.compile(r"^(what_happened|contributing_factors|detection_gaps)\[(\d+)\]$|^root_cause$")
HEDGE = re.compile(r"\b(likely|probabl[ey]|may|might|possibl[ey]|appears?|suggests?|unconfirmed|not confirmed|"
                   r"unknown|unclear|inferred|believed|consistent with|not (yet )?(established|determined|known)|"
                   r"cannot be ruled out|not ruled out)\b", re.IGNORECASE)
_RANK = {Certainty.CONFIRMED: 3, Certainty.PROBABLE: 2, Certainty.POSSIBLE: 1, Certainty.UNKNOWN: 0}


def resolve_finding(d: DraftReport, ref: str):
    m = FINDING_REF.match(ref.strip())
    if not m:
        return None
    if ref.strip() == "root_cause":
        return d.root_cause
    items = getattr(d, m.group(1))
    i = int(m.group(2))
    return items[i] if i < len(items) else None


def check_summary_point(d: DraftReport, p) -> str | None:
    if not p.based_on:
        return "summary point is not tied to any finding (based_on is empty)"
    found = [resolve_finding(d, r) for r in p.based_on]
    missing = [r for r, f in zip(p.based_on, found) if f is None]
    if missing:
        return f"summary point refers to findings that do not exist: {missing}"
    weakest = min((f.certainty for f in found), key=lambda c: _RANK[c])
    if weakest is not Certainty.CONFIRMED and not HEDGE.search(p.text):
        return (f"summary point states a {weakest.value} finding as fact; hedge it "
                f"(e.g. 'probably', 'may', 'not confirmed'): {p.text[:80]!r}")
    return None
REDACTED = "[unverified indicator removed]"


class Issue(BaseModel):
    where: str
    problem: str


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s.replace("\\\\", "\\")).strip().lower()


def check_citation(c: Citation, pack: EvidencePack) -> str | None:
    rid = c.record_id.strip()
    if rid.startswith("K"):
        chunk = pack.kb.get(rid)
        if chunk is None:
            return f"cites {rid}, which is not a knowledge-base section given to you"
        source, where = chunk.text, chunk.label
    else:
        rec = pack.records.get(rid)
        if rec is None:
            return f"cites {rid}, which does not exist"
        source, where = rec.text, f"{rec.file} {rec.locator}"
    if not 3 <= len(c.quote.strip()) <= 200:
        return f"quote for {rid} must be 3-200 characters"
    if _norm(c.quote) not in _norm(source):
        return f"quote {c.quote!r} not found in {rid} ({where})"
    return None


def _is_kb(c: Citation) -> bool:
    return c.record_id.strip().startswith("K")


def _valid(cites: list[Citation], pack: EvidencePack) -> list[Citation]:
    """Valid citations of incident EVIDENCE (knowledge-base citations never count as evidence)."""
    return [c for c in cites if not _is_kb(c) and check_citation(c, pack) is None]


def _free_text(d: DraftReport) -> list[tuple[str, str]]:
    out = [("title", d.title)] + [(f"summary_points[{i}]", p.text) for i, p in enumerate(d.summary_points)]
    out += [
           ("severity_rationale", d.severity_rationale), ("root_cause", d.root_cause.statement)]
    for name, items in (("what_happened", d.what_happened), ("contributing_factors", d.contributing_factors),
                        ("detection_gaps", d.detection_gaps)):
        out += [(f"{name}[{i}]", f.statement) for i, f in enumerate(items)]
    out += [(f"lessons[{i}]", x.lesson) for i, x in enumerate(d.lessons)]
    for i, a in enumerate(d.corrective_actions):
        out += [(f"corrective_actions[{i}]", f"{a.recommendation} {a.reason} {a.expected_benefit}")]
    out += [(f"open_questions[{i}]", q) for i, q in enumerate(d.open_questions)]
    out += [(f"remaining_risks[{i}]", r) for i, r in enumerate(d.remaining_risks)]
    return out


def validate_draft(d: DraftReport, pack: EvidencePack) -> list[Issue]:
    issues: list[Issue] = []

    def cites(where: str, cs: list[Citation], required: bool) -> None:
        for c in cs:
            err = check_citation(c, pack)
            if err:
                issues.append(Issue(where=where, problem=err))
        if required and not _valid(cs, pack):
            issues.append(Issue(where=where, problem="needs at least one valid citation"))

    def finding(where: str, f) -> None:
        cites(where, f.citations, f.certainty in (Certainty.CONFIRMED, Certainty.PROBABLE))
        if any(_is_kb(c) for c in f.citations):
            issues.append(Issue(where=where, problem="findings are facts about the incident; cite evidence records "
                                                     "(R...), not the knowledge base (K...)"))

    for i, f in enumerate(d.what_happened):
        finding(f"what_happened[{i}]", f)
    finding("root_cause", d.root_cause)
    for i, f in enumerate(d.contributing_factors):
        finding(f"contributing_factors[{i}]", f)
    for i, f in enumerate(d.detection_gaps):
        finding(f"detection_gaps[{i}]", f)
    for i, p in enumerate(d.summary_points):
        err = check_summary_point(d, p)
        if err:
            issues.append(Issue(where=f"summary_points[{i}]", problem=err))
    for i, x in enumerate(d.lessons):
        cites(f"lessons[{i}]", x.citations, True)
        if x.area.lower() not in LESSON_AREAS:
            issues.append(Issue(where=f"lessons[{i}]", problem=f"area {x.area!r} must be one of {sorted(LESSON_AREAS)}"))
    for i, a in enumerate(d.corrective_actions):
        cites(f"corrective_actions[{i}]", a.citations, True)

    known = pack.observables
    for v in d.indicators:
        if v.lower() not in known:
            issues.append(Issue(where="indicators", problem=f"{v!r} was not extracted from the evidence"))
    event_ids = {e.event_id for e in pack.timeline.events}
    for e in d.key_event_ids:
        if e not in event_ids:
            issues.append(Issue(where="key_event_ids", problem=f"{e} is not a timeline event"))
    for where, text in _free_text(d):
        for rid in sorted(set(RECORD_ID.findall(text))):
            if rid not in pack.records:
                issues.append(Issue(where=where, problem=f"mentions record {rid}, which does not exist"))
        for kid in sorted(set(KB_ID.findall(text))):
            if kid not in pack.kb:
                issues.append(Issue(where=where, problem=f"mentions knowledge-base section {kid}, which was not given"))
        for t, v in sorted(find_indicators(text)):
            if v not in known:
                issues.append(Issue(where=where, problem=f"mentions {t.value} {v!r}, which is not in the evidence"))
    return issues


# ---------------------------------------------------------------------------
# Build the final report from a draft, keeping only what passes
# ---------------------------------------------------------------------------


def _refs(cs: list[Citation], pack: EvidencePack) -> list[EvidenceRef]:
    out = []
    for c in _valid(cs, pack):
        r = pack.records[c.record_id]
        out.append(EvidenceRef(file=r.file, locator=r.locator, excerpt=c.quote.strip()[:500]))
    return out


def _kb_refs(cs: list[Citation], pack: EvidencePack) -> list[KBRef]:
    out, seen = [], set()
    for c in cs:
        if _is_kb(c) and check_citation(c, pack) is None and c.record_id not in seen:
            seen.add(c.record_id)
            ch = pack.kb[c.record_id.strip()]
            out.append(KBRef(doc_id=ch.doc_id, section=ch.section, title=ch.title, excerpt=c.quote.strip()[:300]))
    return out


def _redact(text: str, known: dict) -> tuple[str, list[str]]:
    removed = []
    for _, v in find_indicators(text):
        if v not in known:
            text = re.sub(re.escape(v), REDACTED, text, flags=re.IGNORECASE)
            removed.append(v)
    return text, removed


def defang(value: str) -> str:
    """Standard defanging so an unverified indicator can't be clicked or pasted into a blocklist by mistake."""
    return value.replace("http", "hxxp").replace(".", "[.]").replace("@", "[@]")


def defang_unknown(text: str, known: dict) -> str:
    for _, v in sorted(find_indicators(text), key=lambda x: -len(x[1])):
        if v not in known:
            text = re.sub(re.escape(v), defang(v), text, flags=re.IGNORECASE)
    return text


def build_postmortem(d: DraftReport, pack: EvidencePack, model: str, issues: list[Issue]) -> Postmortem:
    known = pack.observables
    log = [f"{i.where}: {i.problem}" for i in issues]

    def readable_ids(text: str) -> str:
        # Readers can't look up R007; replace with the file and location it stands for.
        def sub(m):
            r = pack.records.get(m.group(0))
            return f"{r.file} {r.locator}" if r else "[unknown record]"
        text = RECORD_ID.sub(sub, text)
        return KB_ID.sub(lambda m: (f"{pack.kb[m.group(0)].doc_id} §{pack.kb[m.group(0)].section}"
                                    if m.group(0) in pack.kb else "[unknown policy section]"), text)

    def clean(text: str, where: str) -> str:
        text = readable_ids(text)
        text, removed = _redact(text, known)
        for v in removed:
            log.append(f"{where}: removed unverified indicator {v!r}")
        return text

    survived: set[str] = set()

    def to_finding(f, where: str) -> Finding | None:
        try:
            out = Finding(statement=clean(f.statement, where), certainty=f.certainty, evidence=_refs(f.citations, pack))
            survived.add(where)
            return out
        except ValidationError:
            log.append(f"{where}: DROPPED, {f.certainty.value} claim with no valid evidence: {f.statement[:80]!r}")
            return None

    def findings(items, name):
        return [x for i, f in enumerate(items) if (x := to_finding(f, f"{name}[{i}]")) is not None]

    lessons = []
    for i, x in enumerate(d.lessons):
        try:
            lessons.append(Lesson(area=x.area.lower(), lesson=clean(x.lesson, f"lessons[{i}]"),
                                  evidence=_refs(x.citations, pack), policy_refs=_kb_refs(x.citations, pack)))
        except ValidationError:
            log.append(f"lessons[{i}]: DROPPED, no valid evidence or bad area: {x.lesson[:80]!r}")

    actions = []
    for i, a in enumerate(d.corrective_actions):
        try:
            actions.append(CorrectiveAction(
                recommendation=clean(a.recommendation, f"corrective_actions[{i}]"), priority=a.priority,
                reason=clean(a.reason, f"corrective_actions[{i}]"), supporting_evidence=_refs(a.citations, pack),
                owner_team=a.owner_team, timeframe=a.timeframe,
                expected_benefit=clean(a.expected_benefit, f"corrective_actions[{i}]"),
                policy_refs=_kb_refs(a.citations, pack)))
        except ValidationError:
            log.append(f"corrective_actions[{i}]: DROPPED, no valid evidence: {a.recommendation[:80]!r}")

    first_seen = {}
    for e in pack.entities:
        first_seen.setdefault(e.value.lower(), e)
    indicators = []
    for v in dict.fromkeys(x.lower() for x in d.indicators):
        if v in known:
            e = first_seen[v]
            indicators.append(Indicator(value=e.value, entity_type=e.entity_type,
                                        first_seen=EvidenceRef(file=e.source.file, locator=e.source.locator,
                                                               excerpt=e.source.excerpt)))
    event_ids = {e.event_id for e in pack.timeline.events}

    rc = to_finding(d.root_cause, "root_cause")
    what = findings(d.what_happened, "what_happened")
    cfs = findings(d.contributing_factors, "contributing_factors")
    gaps = findings(d.detection_gaps, "detection_gaps")
    summary = []
    for i, p in enumerate(d.summary_points):
        where = f"summary_points[{i}]"
        err = check_summary_point(d, p)
        lost = [r for r in p.based_on if r.strip() not in survived]
        if err:
            log.append(f"{where}: DROPPED, {err}")
        elif lost:
            log.append(f"{where}: DROPPED, based on findings that failed validation: {lost}")
        else:
            summary.append(clean(p.text, where))

    return Postmortem(
        incident_id=pack.incident_id,
        title=clean(d.title, "title"),
        category=d.category, severity=d.severity,
        severity_rationale=clean(d.severity_rationale, "severity_rationale"),
        classification_confidence=d.classification_confidence,
        executive_summary=" ".join(summary) or "No summary point passed validation; see the findings below.",
        what_happened=what,
        key_event_ids=[e for e in d.key_event_ids if e in event_ids],
        indicators=indicators,
        root_cause=rc,
        contributing_factors=cfs,
        detection_gaps=gaps,
        lessons=lessons, corrective_actions=actions,
        open_questions=[clean(q, "open_questions") for q in d.open_questions],
        remaining_risks=[clean(r, "remaining_risks") for r in d.remaining_risks],
        timeline=pack.timeline, validation_log=[defang_unknown(x, known) for x in log], model=model,
        kb_used=[c.key for c in pack.kb.values()],
        generated_at=datetime.now(timezone.utc), file_hashes=pack.file_hashes,
    )
