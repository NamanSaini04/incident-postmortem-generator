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
from .timeline import build_timeline


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
                    if a != b:
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
