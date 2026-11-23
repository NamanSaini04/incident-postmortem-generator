"""Summarise an A/B run (with vs without knowledge base) from saved report JSON.

Usage:  python -m pmgen.abtest reports      -> prints a table and writes reports/ab_summary.md
"""
from __future__ import annotations

import sys
from pathlib import Path

from .evaluate import ReportScore, score_report
from .samples import list_incidents, load_ground_truth
from .schemas import Postmortem

METRICS = ["category_correct", "severity_correct", "root_cause_grounded", "contributing_factor_recall",
           "indicator_recall", "claims_removed", "policy_recall", "actions_with_policy"]


def load_scores(folder: Path) -> dict[tuple[str, str], ReportScore]:
    out = {}
    for inc in list_incidents():
        gt = load_ground_truth(inc)
        for arm, suffix in (("no_rag", "_norag"), ("rag", "")):
            f = folder / f"{inc}_postmortem{suffix}.json"
            if f.exists():
                out[(inc, arm)] = score_report(gt, Postmortem.model_validate_json(f.read_text(encoding="utf-8")))
    return out


def _fmt(v) -> str:
    if v is None:
        return "n/a"
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, float):
        return f"{v:.0%}"
    return str(v)


def summary(scores: dict[tuple[str, str], ReportScore]) -> str:
    incs = sorted({i for i, _ in scores})
    lines = ["# A/B summary: without vs with knowledge base", "",
             "| Incident | Metric | Without RAG | With RAG |", "|---|---|---|---|"]
    for inc in incs:
        a, b = scores.get((inc, "no_rag")), scores.get((inc, "rag"))
        for m in METRICS:
            lines.append(f"| {inc} | {m} | {_fmt(getattr(a, m, None))} | {_fmt(getattr(b, m, None))} |")
    lines += ["", "## Means (incidents with both arms)", "", "| Metric | Without RAG | With RAG |", "|---|---|---|"]
    both = [i for i in incs if (i, "no_rag") in scores and (i, "rag") in scores]
    for m in METRICS:
        vals = {}
        for arm in ("no_rag", "rag"):
            xs = [getattr(scores[(i, arm)], m) for i in both]
            xs = [float(x) for x in xs if x is not None]
            vals[arm] = sum(xs) / len(xs) if xs else None
        lines.append(f"| {m} | {_fmt(vals['no_rag'])} | {_fmt(vals['rag'])} |")
    lines += ["", f"Incidents compared: {len(both)}. Hallucination traps must still be checked by hand in each report."]
    return "\n".join(lines)


if __name__ == "__main__":
    folder = Path(sys.argv[1] if len(sys.argv) > 1 else "reports")
    text = summary(load_scores(folder))
    (folder / "ab_summary.md").write_text(text + "\n", encoding="utf-8")
    print(text)
    print(f"\nwrote {folder / 'ab_summary.md'}")
