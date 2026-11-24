"""Phase 10: data for the dashboard. No Streamlit here, so all of it is unit-tested.

The dashboard runs in demo mode by default: it shows saved reports (JSON) and the
evidence they cite. Nothing here calls the LLM.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .evaluate import ReportScore, score_report
from .ingest import ingest_folder
from .schemas import GroundTruth, Postmortem, Priority
from .verify import VerifyResult, verify

ENV_REPORTS = "PMGEN_REPORTS_DIR"
PRIORITY_ORDER = {Priority.CRITICAL: 0, Priority.HIGH: 1, Priority.MEDIUM: 2, Priority.LOW: 3}
SEVERITY_LABEL = {"SEV1": "SEV1 (critical)", "SEV2": "SEV2 (high)", "SEV3": "SEV3 (medium)", "SEV4": "SEV4 (low)"}


def find_reports_dir() -> Path:
    """$PMGEN_REPORTS_DIR, then docs/sample_reports/phase8 under the current folder, then next to the code."""
    env = os.environ.get(ENV_REPORTS)
    if env:
        return Path(env).expanduser().resolve()
    for base in (Path.cwd(), Path(__file__).resolve().parents[2]):
        candidate = base / "docs" / "sample_reports" / "phase8"
        if candidate.is_dir() and any(candidate.glob("*_postmortem.json")):
            return candidate
    return Path.cwd() / "docs" / "sample_reports" / "phase8"


def load_reports(folder: Path) -> dict[str, Postmortem]:
    """Incident ID -> report. Only the main reports (the *_norag A/B files are skipped)."""
    out: dict[str, Postmortem] = {}
    for f in sorted(Path(folder).glob("*_postmortem.json")):
        pm = Postmortem.model_validate_json(f.read_text(encoding="utf-8"))
        out[pm.incident_id] = pm
    return out


@dataclass
class Bundle:
    """Everything one incident page needs."""
    report: Postmortem
    evidence_dir: Path
    check: VerifyResult
    score: ReportScore | None


def load_bundle(pm: Postmortem, incidents_dir: Path) -> Bundle:
    edir = Path(incidents_dir) / pm.incident_id
    gt_file = edir / "ground_truth.json"
    score = None
    if gt_file.is_file():
        score = score_report(GroundTruth.model_validate_json(gt_file.read_text(encoding="utf-8")), pm)
    return Bundle(pm, edir, verify(pm, edir), score)


def overview(pm: Postmortem) -> dict[str, str]:
    imp = pm.impact
    return {
        "Incident ID": pm.incident_id,
        "Category": pm.category.value.replace("_", " "),
        "Severity": SEVERITY_LABEL.get(pm.severity.value, pm.severity.value),
        "Classification confidence": f"{pm.classification_confidence:.0%}",
        "Status": "Draft: requires human review",
        "Systems involved": ", ".join(imp.systems_involved) or "none identified",
        "Accounts involved": ", ".join(imp.accounts_involved) or "none identified",
        "Model": pm.model,
        "Generated (UTC)": pm.generated_at.strftime("%Y-%m-%d %H:%M"),
    }


def timeline_rows(pm: Postmortem) -> list[dict]:
    key = set(pm.key_event_ids)
    milestones = {m.event_id: name.replace("_", " ") for name, m in (pm.response.milestones.items()
                                                                     if pm.response else []) if m}
    rows = []
    for e in pm.timeline.events:
        if e.timestamp is None:
            continue
        rows.append({
            "event_id": e.event_id,
            "time": e.timestamp,
            "event": e.description,
            "source": ", ".join(sorted({s.file for s in e.sources})) or "-",
            "cited_at": "; ".join(f"{s.file} {s.locator}" for s in e.sources),
            "time_basis": e.time_basis.value.replace("_", " "),
            "key": e.event_id in key,
            "milestone": milestones.get(e.event_id, ""),
            "kind": ("response milestone" if e.event_id in milestones
                     else "key event" if e.event_id in key else "other event"),
        })
    return rows


def _cited(pm: Postmortem) -> dict[tuple[str, str], int]:
    from .verify import _all_refs
    counts: dict[tuple[str, str], int] = {}
    for where, r in _all_refs(pm):
        if where.startswith("timeline "):
            continue  # every record feeds the timeline; count only report claims
        counts[(r.file, r.locator)] = counts.get((r.file, r.locator), 0) + 1
    return counts


def evidence_rows(pm: Postmortem, evidence_dir: Path) -> list[dict]:
    """Every evidence record, with how many report claims cite it."""
    cited = _cited(pm)
    bundle = ingest_folder(Path(evidence_dir))
    rows = []
    for doc in bundle.documents:
        for rec in doc.records:
            rows.append({"file": doc.file_name, "locator": rec.locator, "text": rec.text,
                         "cited_by_claims": cited.get((doc.file_name, rec.locator), 0)})
    return rows


def uncited_share(rows: list[dict]) -> float:
    return sum(r["cited_by_claims"] == 0 for r in rows) / len(rows) if rows else 0.0


def attack_rows(pm: Postmortem) -> list[dict]:
    return [{"tactic": a.tactic, "technique": a.technique_name, "id": a.technique_id,
             "certainty": a.certainty.value, "behaviour": a.rationale,
             "evidence": "; ".join(f"{r.file} {r.locator}" for r in a.evidence)} for a in pm.attack]


def finding_rows(findings) -> list[dict]:
    return [{"certainty": f.certainty.value, "statement": f.statement,
             "evidence": "; ".join(f"{r.file} {r.locator}" for r in f.evidence) or "-"} for f in findings if f]


def duration_rows(pm: Postmortem) -> list[dict]:
    if not pm.response:
        return []
    return [{"measure": d.name.replace("_", " "), "minutes": round(d.seconds / 60, 2), "seconds": d.seconds,
             "from_to": f"{d.start.replace('_', ' ')} -> {d.end.replace('_', ' ')}",
             "approximate": d.approximate,
             "timing": "approximate (inferred time)" if d.approximate else "exact"} for d in pm.response.durations]


def action_rows(pm: Postmortem) -> list[dict]:
    acts = sorted(pm.corrective_actions, key=lambda a: PRIORITY_ORDER[a.priority])
    return [{"priority": a.priority.value, "action": a.recommendation, "why": a.reason,
             "owner": a.owner_team, "timeframe": a.timeframe,
             "evidence": "; ".join(f"{r.file} {r.locator}" for r in a.supporting_evidence),
             "policy": "; ".join(f"{p.doc_id} §{p.section}" for p in a.policy_refs) or "-"} for a in acts]


def score_rows(s: ReportScore | None) -> list[dict]:
    """Selected ground-truth scores for display. None values mean 'nothing to score'."""
    if s is None:
        return []
    pick = [("Category correct", s.category_correct), ("Severity correct", s.severity_correct),
            ("Root cause grounded", s.root_cause_grounded),
            ("Contributing-factor recall", s.contributing_factor_recall),
            ("Indicator recall", s.indicator_recall), ("ATT&CK recall (lenient)", s.attack_recall_lenient),
            ("ATT&CK forbidden techniques", len(s.attack_forbidden_hits)),
            ("Response milestones right", s.milestone_accuracy),
            ("Forbidden systems/accounts", len(s.scope_forbidden_hits))]
    out = []
    for name, v in pick:
        if isinstance(v, bool):
            shown = "yes" if v else "no"
        elif isinstance(v, float):
            shown = f"{v:.0%}"
        elif v is None:
            shown = "n/a"
        else:
            shown = str(v)
        out.append({"metric": name, "value": shown})
    return out


def live_generation_enabled() -> bool:
    """Live LLM runs only on a machine where the owner turned them on and set a key."""
    return os.environ.get("PMGEN_LIVE") == "1" and bool(os.environ.get("ANTHROPIC_API_KEY"))
