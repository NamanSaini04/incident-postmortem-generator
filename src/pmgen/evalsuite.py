"""Phase 12: one evaluation over everything, from saved reports. No API calls.

Usage:  python -m pmgen.evalsuite reports/phase7 reports/phase8 [--out docs/evaluation.md]
Each folder is one *run*: one report per incident (*_postmortem.json; the *_norag A/B files are skipped).
Two or more runs of the same incidents are needed for the consistency measures.

The 10 measures from the project spec, and how each is computed:
  1  Evidence extraction accuracy  - code only: answer-key IOCs found by extraction, on 36 cases
  2  Timeline accuracy             - code only: event recall, timestamp and order accuracy, 36 cases
  3  Classification accuracy       - category and severity vs the answer key
  4  MITRE mapping accuracy        - lenient recall, precision, forbidden techniques
  5  Root cause grounding          - root cause cites the answer key's record; contributing-factor recall
  6  Citation correctness          - share of citations the independent verifier confirms
  7  Unsupported claim rate        - claims the validator had to remove / all claims made
  8  Severity consistency          - same severity (and category, root-cause record) across runs
  9  Recommendation relevance      - PROXY: actions that cite a record behind a finding; policy recall
  10 Report completeness           - required sections present and non-empty
Hallucination traps (statements that must not appear as fact) are checked by hand; see results.md.
"""
from __future__ import annotations

import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from statistics import mean

from .evaluate import ReportScore, run_all, score_report
from .extract import extract_bundle
from .ingest import ingest_folder
from .samples import DATA_DIR, list_incidents, load_ground_truth
from .schemas import GroundTruth, Postmortem
from .verify import REMOVAL, VerifyResult, verify

CITATION_CHECKS = ("citations resolve and quotes match", "policy quotes found in the knowledge base",
                   "indicators appear in their cited record")


# ---------------------------------------------------------------- code-only measures (1, 2)

def _gt_iocs(gt: GroundTruth) -> list[str]:
    return [v for values in gt.iocs.values() for v in values]


def extraction_recall(include_variants: bool = True) -> tuple[int, int, list[str]]:
    """Answer-key IOCs that deterministic extraction finds, over originals and messy variants."""
    from .variants import VARIANTS, make_variant

    found = total = 0
    misses: list[str] = []

    def check(folder: Path, gt: GroundTruth, case: str) -> None:
        nonlocal found, total
        ents = {e.value.lower() for e in extract_bundle(ingest_folder(folder, incident_id=gt.incident_id))}
        for v in _gt_iocs(gt):
            total += 1
            if v.lower() in ents:
                found += 1
            else:
                misses.append(f"{case}: {v}")

    for inc in list_incidents():
        gt = load_ground_truth(inc)
        check(DATA_DIR / inc, gt, f"{inc} original")
        if include_variants:
            with tempfile.TemporaryDirectory() as tmp:
                for name in VARIANTS:
                    folder, vgt = make_variant(inc, name, Path(tmp))
                    check(folder, vgt, f"{inc} {name}")
    return found, total, misses


# ---------------------------------------------------------------- per-report measures

def has_attack_stage(pm: Postmortem) -> bool:
    """ATT&CK mapping arrived in Phase 7; every report since then records the catalogue version."""
    return bool(pm.attack_catalog)


def has_phase8_stage(pm: Postmortem) -> bool:
    """Impact, immediate cause and response timing arrived in Phase 8."""
    imp = pm.impact
    return (pm.response is not None or pm.immediate_cause is not None or
            bool(imp.systems_involved or imp.accounts_involved or imp.data_affected
                 or imp.operational_impact or imp.business_impact))


def first_draft_problems(pm: Postmortem) -> int:
    """Problems the validator found in the first draft (fixed by the retry, or removed)."""
    import re
    for line in pm.validation_log:
        m = re.match(r"attempt 1: (\d+) validation problem", line)
        if m:
            return int(m.group(1))
    return 0


def claim_count(pm: Postmortem) -> int:
    """Claims that survived validation: findings, actions, lessons, mappings, indicators, summary-level items."""
    n = len(pm.what_happened) + len(pm.contributing_factors) + len(pm.detection_gaps)
    n += sum(f is not None for f in (pm.root_cause, pm.immediate_cause, pm.impact.data_affected,
                                     pm.impact.operational_impact, pm.impact.business_impact))
    n += len(pm.lessons) + len(pm.corrective_actions) + len(pm.attack) + len(pm.indicators)
    n += len(pm.impact.systems_involved) + len(pm.impact.accounts_involved)
    return n


def removed_count(pm: Postmortem) -> int:
    """Claims the validator removed. Before Phase 12 a dropped indicator was not logged as DROPPED; for those
    older reports, the final attempt's unresolved 'was not extracted' lines (no 'attempt' prefix) stand in."""
    n = sum(1 for line in pm.validation_log if REMOVAL.search(line))
    if not any(line.startswith("indicators: DROPPED") for line in pm.validation_log):
        n += sum(1 for line in pm.validation_log
                 if line.startswith("indicators: ") and "was not extracted from the evidence" in line)
    return n


def action_relevance(pm: Postmortem) -> float | None:
    """PROXY for relevance: share of corrective actions citing at least one record that also backs a finding
    (root cause, immediate cause, contributing factor or detection gap). An action tied to no finding is
    probably generic advice. This cannot judge whether the action is a *good* fix."""
    if not pm.corrective_actions:
        return None
    finding_refs = set()
    for f in [pm.root_cause, pm.immediate_cause, *pm.contributing_factors, *pm.detection_gaps]:
        if f:
            finding_refs |= {(r.file, r.locator) for r in f.evidence}
    tied = sum(any((r.file, r.locator) in finding_refs for r in a.supporting_evidence) for a in pm.corrective_actions)
    return tied / len(pm.corrective_actions)


REQUIRED_SECTIONS = ("executive summary", "timeline", "what happened", "root cause", "contributing factors",
                     "impact", "response timing", "detection gaps", "lessons", "corrective actions",
                     "open questions or risks", "ATT&CK (if the answer key has techniques)",
                     "indicators (if the answer key has IOCs)")


def completeness(pm: Postmortem, gt: GroundTruth) -> tuple[float, list[str]]:
    """Sections the report's own version could produce; later-phase sections are not counted against older runs."""
    imp = pm.impact
    present = {
        "executive summary": bool(pm.executive_summary.strip()),
        "timeline": bool(pm.timeline.events),
        "what happened": bool(pm.what_happened),
        "root cause": pm.root_cause is not None,
        "contributing factors": bool(pm.contributing_factors),
        "impact": bool(imp.systems_involved or imp.accounts_involved or imp.data_affected),
        "response timing": pm.response is not None and bool(pm.response.durations),
        "detection gaps": bool(pm.detection_gaps),
        "lessons": bool(pm.lessons),
        "corrective actions": bool(pm.corrective_actions),
        "open questions or risks": bool(pm.open_questions or pm.remaining_risks),
        "ATT&CK (if the answer key has techniques)": bool(pm.attack) or not gt.attack,
        "indicators (if the answer key has IOCs)": bool(pm.indicators) or not _gt_iocs(gt),
    }
    if not has_phase8_stage(pm):
        present.pop("impact"); present.pop("response timing")
    if not has_attack_stage(pm):
        present.pop("ATT&CK (if the answer key has techniques)")
    missing = [k for k, ok in present.items() if not ok]
    return sum(present.values()) / len(present), missing


@dataclass
class ReportEval:
    run: str
    incident_id: str
    score: ReportScore
    check: VerifyResult
    claims: int
    removed: int
    relevance: float | None
    complete: float
    missing: list[str]
    root_cause_records: frozenset = field(default_factory=frozenset)
    severity: str = ""
    category: str = ""
    first_draft_problems: int = 0
    stages: str = ""

    @property
    def citations_checked(self) -> int:
        return sum(c.checked for c in self.check.checks if c.name in CITATION_CHECKS)

    @property
    def citations_failed(self) -> int:
        return sum(len(c.failures) for c in self.check.checks if c.name in CITATION_CHECKS)


def evaluate_report(run: str, pm: Postmortem, incidents_dir: Path = DATA_DIR) -> ReportEval:
    gt = load_ground_truth(pm.incident_id)
    comp, missing = completeness(pm, gt)
    rc = frozenset((r.file, r.locator) for r in pm.root_cause.evidence) if pm.root_cause else frozenset()
    score = score_report(gt, pm)
    # a stage the report's version did not have is "not applicable", never 0%
    if not has_attack_stage(pm):
        score = score.model_copy(update={"attack_recall_strict": None, "attack_recall_lenient": None,
                                         "attack_precision": None})
    if not has_phase8_stage(pm):
        score = score.model_copy(update={"milestone_accuracy": None, "milestone_errors": [], "systems_recall": None,
                                         "systems_precision": None, "accounts_recall": None,
                                         "accounts_precision": None})
    stages = "base" + (" +ATT&CK" if has_attack_stage(pm) else "") + (" +impact/timing" if has_phase8_stage(pm) else "")
    return ReportEval(run, pm.incident_id, score, verify(pm, Path(incidents_dir) / pm.incident_id),
                      claim_count(pm), removed_count(pm), action_relevance(pm), comp, missing, rc,
                      pm.severity.value, pm.category.value, first_draft_problems(pm), stages)


def load_runs(folders: list[Path]) -> dict[str, dict[str, Postmortem]]:
    runs: dict[str, dict[str, Postmortem]] = {}
    for folder in folders:
        reports = {}
        for f in sorted(Path(folder).glob("*_postmortem.json")):
            pm = Postmortem.model_validate_json(f.read_text(encoding="utf-8"))
            reports[pm.incident_id] = pm
        if reports:
            runs[Path(folder).name] = reports
    return runs


# ---------------------------------------------------------------- consistency (8)

def consistency(evals: list[ReportEval]) -> dict[str, tuple[int, int]]:
    """For incidents with 2+ runs: how many gave the same answer in every run. Returns {measure: (same, n)}."""
    by_inc: dict[str, list[ReportEval]] = {}
    for e in evals:
        by_inc.setdefault(e.incident_id, []).append(e)
    multi = {k: v for k, v in by_inc.items() if len(v) >= 2}
    out: dict[str, tuple[int, int]] = {}
    # compare the answers themselves, not whether each was right: SEV1 and SEV3 are both wrong but not consistent
    for name, get in (("severity", lambda e: e.severity),
                      ("category", lambda e: e.category),
                      ("root cause record", lambda e: e.root_cause_records)):
        same = sum(len({get(e) for e in v}) == 1 for v in multi.values())
        out[name] = (same, len(multi))
    return out


def severity_values(runs: dict[str, dict[str, Postmortem]]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for reports in runs.values():
        for inc, pm in reports.items():
            out.setdefault(inc, []).append(pm.severity.value)
    return out


# ---------------------------------------------------------------- the report

def _pct(xs) -> str:
    xs = [x for x in xs if x is not None]
    return f"{mean(xs):.0%}" if xs else "n/a"


def build_markdown(runs: dict[str, dict[str, Postmortem]], include_variants: bool = True) -> str:
    evals = [evaluate_report(run, pm) for run, reports in runs.items() for pm in reports.values()]
    ext_found, ext_total, ext_miss = extraction_recall(include_variants)
    tl = run_all(include_variants)
    cons = consistency(evals)
    sev = severity_values(runs)
    S = [e.score for e in evals]
    claims, removed = sum(e.claims for e in evals), sum(e.removed for e in evals)
    cit_n, cit_bad = sum(e.citations_checked for e in evals), sum(e.citations_failed for e in evals)
    att = [s for s in S if s.attack_recall_lenient is not None]
    ms = [s.milestone_accuracy for s in S if s.milestone_accuracy is not None]
    retried = sum(e.first_draft_problems > 0 for e in evals)

    L = ["# Evaluation", "",
         f"Generated by `python -m pmgen.evalsuite`. Runs: {', '.join(f'`{r}` ({len(v)} reports)' for r, v in runs.items())}. "
         f"{len(evals)} reports in total. No API calls are made by this evaluation.", "",
         "**Read this first:** all incidents are synthetic and the answer keys were written by the same author "
         "as the evidence. The generator and the development reviewer are the same model family. Small samples: "
         "treat every number as a sanity check, not a benchmark.", "",
         "## Summary (the 10 measures in the project spec)", "",
         "| # | Measure | Result | How |", "|---|---|---|---|",
         f"| 1 | Evidence extraction | {ext_found}/{ext_total} answer-key IOCs found | code only, {len(tl)} cases incl. messy variants |",
         f"| 2 | Timeline | event recall {_pct([t.key_event_recall for t in tl])}, timestamps {_pct([t.timestamp_accuracy for t in tl])}, "
         f"order {_pct([t.order_accuracy for t in tl])} | code only, {len(tl)} cases |",
         f"| 3 | Classification | category {sum(s.category_correct for s in S)}/{len(S)}, severity exact "
         f"{sum(s.severity_correct for s in S)}/{len(S)} (max off by {max((s.severity_off_by for s in S), default=0)}) | vs answer key |",
         f"| 4 | ATT&CK mapping | lenient recall {_pct([s.attack_recall_lenient for s in att])}, precision "
         f"{_pct([s.attack_precision for s in att])}, forbidden {sum(len(s.attack_forbidden_hits) for s in S)} | "
         f"vs answer key; {len(att)} reports with this stage |",
         f"| 5 | Root cause grounding | {sum(s.root_cause_grounded for s in S)}/{len(S)} cite the key's record; "
         f"contributing factors {_pct([s.contributing_factor_recall for s in S])} | vs answer key |",
         f"| 6 | Citation correctness | {cit_n - cit_bad}/{cit_n} confirmed | independent verifier |",
         f"| 7 | Unsupported claim rate | {removed}/{claims + removed} removed by the validator "
         f"({(removed / (claims + removed)) if claims + removed else 0:.1%}); first drafts with problems: "
         f"{retried}/{len(evals)} ({sum(e.first_draft_problems for e in evals)} problems, fixed on retry or removed) "
         f"| validation logs |",
         f"| 8 | Severity consistency | {cons['severity'][0]}/{cons['severity'][1]} incidents same in every run | "
         f"needs 2+ runs |",
         f"| 9 | Recommendation relevance (proxy) | {_pct([e.relevance for e in evals])} of actions tied to a finding; "
         f"policy recall {_pct([s.policy_recall for s in S])} | proxy, see below |",
         f"| 10 | Report completeness | {_pct([e.complete for e in evals])} of required sections | "
         f"checklist; only sections the report's version could produce |",
         ""]
    if ms:
        L.insert(-1, f"\nAlso (Phase 8 stage): response milestones right {_pct(ms)} over {len(ms)} reports.")

    L += ["## Per report", "",
          "| Run | Stages | Incident | Cat | Sev | Root cause | ATT&CK R/P | Milestones | Citations | 1st-draft problems "
          "| Removed | Actions tied | Complete |",
          "|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    yn = lambda b: "yes" if b else "**no**"  # noqa: E731
    for e in sorted(evals, key=lambda x: (x.incident_id, x.run)):
        s = e.score
        L.append(f"| {e.run} | {e.stages} | {e.incident_id} | {yn(s.category_correct)} | "
                 f"{'yes' if s.severity_correct else f'**off by {s.severity_off_by}**'} | {yn(s.root_cause_grounded)} | "
                 f"{_pct([s.attack_recall_lenient])}/{_pct([s.attack_precision])} | {_pct([s.milestone_accuracy])} | "
                 f"{e.citations_checked - e.citations_failed}/{e.citations_checked} | {e.first_draft_problems} | {e.removed} | "
                 f"{_pct([e.relevance])} | {e.complete:.0%} |")
    L.append("")

    L += ["## Consistency across runs", "",
          "| Incident | Severity per run |", "|---|---|"]
    for inc, vals in sorted(sev.items()):
        L.append(f"| {inc} | {', '.join(vals)}{'' if len(set(vals)) == 1 else ' (**differs**)'} |")
    L += ["", f"- Same category in every run: {cons['category'][0]}/{cons['category'][1]} incidents.",
          f"- Same root-cause record in every run: {cons['root cause record'][0]}/{cons['root cause record'][1]} incidents "
          "(different records can still describe the same cause).", ""]

    missing = sorted({f"{e.run} {e.incident_id}: {', '.join(e.missing)}" for e in evals if e.missing})
    L += ["## What is missing or weak", ""]
    L += [f"- Incomplete: {m}" for m in missing] or ["- No report is missing a required section."]
    L += [f"- Extraction miss: {m}" for m in ext_miss[:10]]
    L += [f"- Verifier failure: {e.run} {e.incident_id}: {c.name}: {f}"
          for e in evals for c in e.check.checks for f in c.failures][:20]
    L += ["", "## Measures that need care", "",
          "- **Recommendation relevance is a proxy.** It checks an action is tied to evidence behind a finding. "
          "It cannot tell a good fix from a weak one; that needs a security reviewer.",
          "- **Unsupported claim rate counts what the validator caught**, not what it missed. Claims that cite a real "
          "record but misread it pass the validator; the hand-checked hallucination traps cover part of that gap.",
          "- **Older runs predate later stages** (ATT&CK in Phase 7; impact and response timing in Phase 8). Those "
          "measures are n/a for them and left out of the means and of completeness, instead of counting as 0%.",
          "- **Consistency from a few runs** shows whether answers move, not how often.", ""]
    return "\n".join(L)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    out = None
    if "--out" in argv:
        i = argv.index("--out")
        out = Path(argv[i + 1])
        argv = argv[:i] + argv[i + 2:]
    runs = load_runs([Path(a) for a in argv])
    if not runs:
        print("usage: python -m pmgen.evalsuite RUN_FOLDER [RUN_FOLDER ...] [--out docs/evaluation.md]",
              file=sys.stderr)
        return 2
    md = build_markdown(runs)
    print(md)
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(md + "\n", encoding="utf-8")
        print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
