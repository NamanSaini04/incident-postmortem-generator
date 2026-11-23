"""Phase 4 evaluation: score a generated timeline against ground truth.

Metrics (per incident):
  key_event_recall    share of ground-truth key events found in the timeline.
                      An event matches if it cites the same source record
                      (file + locator) as the ground truth.
  timestamp_accuracy  of the matched events, share whose time is correct
                      (to the second for logs, to the minute for HH:MM notes).
  order_accuracy      of all pairs of matched events, share placed in the
                      same order as the ground truth.
  noise_ratio         timeline events per key event. Not an error: the
                      timeline is meant to include benign context (the
                      user's normal login, the newsletter). Reported so the
                      reader knows how much there is to read.

What this does NOT measure yet: whether descriptions are right, whether the
right events are flagged as important, or anything the LLM writes.

Run:  python -m pmgen.evaluate            (bundled incidents + messy variants)
"""
from __future__ import annotations

import sys
import tempfile
from itertools import combinations
from pathlib import Path

from pydantic import BaseModel

from .ingest import ingest_folder
from .samples import DATA_DIR, list_incidents, load_ground_truth
from .schemas import GroundTruth, Timeline
from datetime import timedelta

from .timeline import MERGE_WINDOW, build_timeline


class TimelineScore(BaseModel):
    case: str
    key_events: int
    matched: int
    key_event_recall: float
    timestamp_accuracy: float
    order_accuracy: float
    noise_ratio: float
    missed: list[str]
    wrong_time: list[str]


def score_timeline(gt: GroundTruth, tl: Timeline, case: str | None = None) -> TimelineScore:
    position: dict[str, int] = {}
    wrong_time: list[str] = []
    for i, ev in enumerate(tl.events):
        for src in ev.sources:
            for g in gt.timeline:
                if g.key not in position and (src.file, src.locator) == (g.source.file, g.source.locator):
                    position[g.key] = i
                    precise = not g.source.file.endswith(".txt")
                    a = ev.timestamp.replace(microsecond=0) if precise else ev.timestamp.replace(second=0, microsecond=0)
                    b = g.timestamp if precise else g.timestamp.replace(second=0)
                    # A merged event (same action seen in several logs within MERGE_WINDOW) carries
                    # the earliest source time; any source time within the window is correct.
                    tol = MERGE_WINDOW if len(ev.sources) > 1 else timedelta(0)
                    if abs(a - b) > tol:
                        wrong_time.append(g.key)

    matched = [g.key for g in gt.timeline if g.key in position]
    missed = [g.key for g in gt.timeline if g.key not in position]
    pairs = list(combinations(matched, 2))  # ground-truth order: earlier key first
    in_order = sum(position[a] <= position[b] for a, b in pairs)
    n = len(gt.timeline)
    return TimelineScore(
        case=case or gt.incident_id,
        key_events=n,
        matched=len(matched),
        key_event_recall=len(matched) / n,
        timestamp_accuracy=(len(matched) - len(wrong_time)) / len(matched) if matched else 0.0,
        order_accuracy=in_order / len(pairs) if pairs else 1.0,
        noise_ratio=len(tl.events) / n,
        missed=missed,
        wrong_time=wrong_time,
    )


def score_folder(folder: Path, gt: GroundTruth, case: str) -> TimelineScore:
    return score_timeline(gt, build_timeline(ingest_folder(folder, incident_id=gt.incident_id)), case)


def run_all(include_variants: bool = True) -> list[TimelineScore]:
    from .variants import VARIANTS, make_variant

    scores = []
    for inc in list_incidents():
        gt = load_ground_truth(inc)
        scores.append(score_folder(DATA_DIR / inc, gt, f"{inc} original"))
        if include_variants:
            with tempfile.TemporaryDirectory() as tmp:
                for name in VARIANTS:
                    folder, vgt = make_variant(inc, name, Path(tmp))
                    scores.append(score_folder(folder, vgt, f"{inc} {name}"))
    return scores


def _table(scores: list[TimelineScore]) -> str:
    head = f"{'case':<30} {'recall':>7} {'time':>7} {'order':>7} {'noise':>6}  problems"
    rows = [head, "-" * len(head)]
    for s in scores:
        probs = ", ".join([f"missed:{k}" for k in s.missed] + [f"time:{k}" for k in s.wrong_time]) or "-"
        rows.append(f"{s.case:<30} {s.key_event_recall:>7.0%} {s.timestamp_accuracy:>7.0%} "
                    f"{s.order_accuracy:>7.0%} {s.noise_ratio:>5.1f}x  {probs}")
    n = len(scores)
    rows.append("-" * len(head))
    rows.append(f"{f'MEAN over {n} cases':<30} {sum(s.key_event_recall for s in scores)/n:>7.0%} "
                f"{sum(s.timestamp_accuracy for s in scores)/n:>7.0%} "
                f"{sum(s.order_accuracy for s in scores)/n:>7.0%} "
                f"{sum(s.noise_ratio for s in scores)/n:>5.1f}x")
    return "\n".join(rows)


if __name__ == "__main__":
    print(_table(run_all(include_variants="--no-variants" not in sys.argv)))


# ---------------------------------------------------------------------------
# Phase 5: score a generated postmortem against ground truth
# ---------------------------------------------------------------------------


class ReportScore(BaseModel):
    incident_id: str
    category_correct: bool
    severity_correct: bool
    severity_off_by: int           # levels between predicted and true severity (SEV1 vs SEV2 = 1)
    root_cause_grounded: bool      # root cause cites the same record as the ground-truth root cause
    contributing_factor_recall: float  # share of GT contributing factors whose record is cited somewhere
    indicator_recall: float        # share of GT IOCs listed as indicators
    indicator_precision: float | None  # share of listed indicators that are GT IOCs; None if none listed
    claims_removed: int            # items dropped by the validator
    policy_recall: float | None    # share of expected KB sections cited in actions/lessons (None if none expected)
    actions_with_policy: float | None  # share of corrective actions citing at least one KB section
    attack_recall_strict: float | None   # required techniques mapped with the exact ID
    attack_recall_lenient: float | None  # ... or with its parent / a sub-technique of it
    attack_precision: float | None       # mapped techniques that are required or acceptable (lenient); None if none
    attack_forbidden_hits: list[str]     # mapped techniques the answer key says the evidence does NOT support
    attack_removed: int                  # mappings dropped by the validator
    must_not_claim: list[str]      # for MANUAL check: these must not appear as confirmed facts


def _attack_scores(gt: GroundTruth, pm) -> dict:
    from .attack import parent, related
    req = [a.technique_id for a in gt.attack]
    ok = req + gt.attack_acceptable
    got = [a.technique_id for a in getattr(pm, "attack", [])]
    forbidden = [g for g in got if g in gt.attack_forbidden or parent(g) in gt.attack_forbidden]
    return {
        "attack_recall_strict": sum(r in got for r in req) / len(req) if req else None,
        "attack_recall_lenient": sum(any(related(r, g) for g in got) for r in req) / len(req) if req else None,
        "attack_precision": sum(any(related(g, o) for o in ok) for g in got) / len(got) if got else None,
        "attack_forbidden_hits": forbidden,
        "attack_removed": sum(x.startswith("attack[") and "DROPPED" in x for x in pm.validation_log),
    }


def _policy_recall(gt: GroundTruth, pm) -> float | None:
    if not gt.expected_kb_sections:
        return None
    cited = {f"{r.doc_id}#{r.section}" for a in pm.corrective_actions for r in a.policy_refs}
    cited |= {f"{r.doc_id}#{r.section}" for x in pm.lessons for r in x.policy_refs}
    return sum(e in cited for e in gt.expected_kb_sections) / len(gt.expected_kb_sections)


def score_report(gt: GroundTruth, pm) -> ReportScore:
    loc = lambda refs: {(r.file, r.locator) for r in refs}  # noqa: E731
    gt_rc = loc(gt.root_cause.evidence)
    rc = loc(pm.root_cause.evidence) if pm.root_cause else set()
    cited = set()
    for f in [*pm.what_happened, *pm.contributing_factors, *pm.detection_gaps]:
        cited |= loc(f.evidence)
    if pm.root_cause:
        cited |= rc
    for a in pm.corrective_actions:
        cited |= loc(a.supporting_evidence)
    cf = gt.contributing_factors
    cf_hit = sum(bool(loc(f.evidence) & cited) for f in cf)
    from .evidence_pack import INDICATOR_TYPES
    # Only indicator types the system can list (IP/domain/URL/email/hash) are scored.
    gt_iocs = {v.lower() for t, vals in gt.iocs.items() if t in INDICATOR_TYPES for v in vals}
    listed = {i.value.lower() for i in pm.indicators}
    return ReportScore(
        incident_id=gt.incident_id,
        category_correct=pm.category == gt.category or pm.category in gt.acceptable_categories,
        severity_correct=pm.severity == gt.severity,
        severity_off_by=abs(int(pm.severity.value[-1]) - int(gt.severity.value[-1])),
        root_cause_grounded=bool(rc & gt_rc),
        contributing_factor_recall=cf_hit / len(cf) if cf else 1.0,
        indicator_recall=len(listed & gt_iocs) / len(gt_iocs) if gt_iocs else 1.0,
        indicator_precision=len(listed & gt_iocs) / len(listed) if listed else None,
        claims_removed=sum("DROPPED" in x or "removed unverified" in x for x in pm.validation_log),
        policy_recall=_policy_recall(gt, pm),
        actions_with_policy=(sum(bool(a.policy_refs) for a in pm.corrective_actions) / len(pm.corrective_actions)
                             if pm.corrective_actions else None),
        **_attack_scores(gt, pm),
        must_not_claim=gt.must_not_claim,
    )
