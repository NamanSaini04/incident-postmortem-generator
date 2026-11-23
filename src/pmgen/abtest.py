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
           "indicator_recall", "claims_removed", "policy_recall", "actions_with_policy",
           "attack_recall_strict", "attack_recall_lenient", "attack_precision", "attack_forbidden_hits"]


COUNT_METRICS = {"claims_removed", "attack_forbidden_hits"}


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
    if isinstance(v, list):
        return ", ".join(v) or "none"
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
            xs = [float(len(x)) if isinstance(x, list) else float(x) for x in xs if x is not None]
            vals[arm] = sum(xs) / len(xs) if xs else None
        if m in COUNT_METRICS:  # averages of counts, not percentages
            show = lambda v: "n/a" if v is None else f"{v:.2f} per report"  # noqa: E731
            lines.append(f"| {m} | {show(vals['no_rag'])} | {show(vals['rag'])} |")
        else:
            lines.append(f"| {m} | {_fmt(vals['no_rag'])} | {_fmt(vals['rag'])} |")
    lines += ["", f"Incidents compared: {len(both)}. Hallucination traps must still be checked by hand in each report."]
    return "\n".join(lines)





def attack_review(folder: Path) -> str:
    """Per-incident ATT&CK detail for one arm (files without the _norag suffix), including
    every mapped technique that is neither required nor acceptable, for manual review."""
    from .attack import full_name, related

    lines = ["# ATT&CK mapping review", "",
             "| Incident | Strict recall | Lenient recall | Precision | Forbidden hits | Removed | Missed (required) "
             "| Extras to review |", "|---|---|---|---|---|---|---|---|"]
    totals = {"strict": [], "lenient": [], "prec": [], "forbidden": 0}
    for inc in list_incidents():
        f = folder / f"{inc}_postmortem.json"
        if not f.exists():
            continue
        gt = load_ground_truth(inc)
        pm = Postmortem.model_validate_json(f.read_text(encoding="utf-8"))
        s = score_report(gt, pm)
        got = [a.technique_id for a in pm.attack]
        req = [a.technique_id for a in gt.attack]
        ok = req + gt.attack_acceptable
        missed = [r for r in req if not any(related(r, g) for g in got)]
        extras = [g for g in got if not any(related(g, o) for o in ok)]
        lines.append(f"| {inc} | {_fmt(s.attack_recall_strict)} | {_fmt(s.attack_recall_lenient)} "
                     f"| {_fmt(s.attack_precision)} | {_fmt(s.attack_forbidden_hits)} | {s.attack_removed} "
                     f"| {', '.join(missed) or '-'} | {'; '.join(f'{e} {full_name(e)}' for e in extras) or '-'} |")
        totals["strict"].append(s.attack_recall_strict)
        totals["lenient"].append(s.attack_recall_lenient)
        if s.attack_precision is not None:
            totals["prec"].append(s.attack_precision)
        totals["forbidden"] += len(s.attack_forbidden_hits)
    mean = lambda xs: f"{sum(xs) / len(xs):.0%}" if xs else "n/a"  # noqa: E731
    lines += ["", f"**Means:** strict recall {mean(totals['strict'])}, lenient recall {mean(totals['lenient'])}, "
                  f"precision {mean(totals['prec'])}, forbidden hits {totals['forbidden']} in total.",
              "", "Extras are not automatically wrong: check each against the evidence (the answer key may be "
                  "incomplete) before counting it as an error."]
    return "\n".join(lines)


if __name__ == "__main__":
    folder = Path(sys.argv[1] if len(sys.argv) > 1 else "reports")
    if "--attack" in sys.argv:
        text, out = attack_review(folder), folder / "attack_review.md"
    else:
        text, out = summary(load_scores(folder)), folder / "ab_summary.md"
    out.write_text(text + "\n", encoding="utf-8")
    print(text)
    print(f"\nwrote {out}")
