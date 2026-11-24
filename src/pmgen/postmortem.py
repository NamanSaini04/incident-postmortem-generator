"""Phase 5: generate a validated incident postmortem (Markdown).

Flow:
  evidence files -> ingest -> extract -> timeline -> evidence pack
  -> LLM draft (structured JSON) -> validate
  -> if problems: one retry with the problems listed
  -> keep only claims that pass -> Markdown report

The timeline, indicators table and evidence index come from code. The LLM
writes the analysis (summary, root cause, lessons, actions), and only claims
that cite real records with real quotes survive.

Run:
  python -m pmgen.postmortem data/incidents/INC-2026-001 --dry-run   # no API call, shows prompt size
  python -m pmgen.postmortem data/incidents/INC-2026-001             # needs ANTHROPIC_API_KEY
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from pydantic import ValidationError

from .evidence_pack import EvidencePack, build_pack
from .ingest import ingest_folder
from .llm import AnthropicClient, LLMClient, LLMError, LLMOutputError
from .schemas import DraftReport, Postmortem, TimeBasis
from .validate import Issue, build_postmortem, validate_draft

MAX_RETRIES = 1

SYSTEM_PROMPT = """You are a senior incident responder writing a blameless security incident postmortem.
You are working on a DEFENSIVE review of an incident that already happened. Do not give offensive or exploit guidance.

Hard rules:
1. Use ONLY the evidence pack. Never use outside knowledge about this incident.
2. Every factual claim must cite records: give the record ID and copy a short exact quote (3-200 characters) from that record.
3. Certainty: "confirmed" = directly stated in evidence; "probable" = strongly supported, small inference;
   "possible" = plausible but weakly supported; "unknown" = not determinable. Confirmed and probable MUST cite records.
4. Analyst notes that say "may", "possibly", "not checked", "not confirmed" or "open question" are NOT confirmed facts.
   Report them as open questions, or as "possible"/"unknown".
5. Indicators: list only malicious ones, copied exactly from the OBSERVABLES list. Internal domains, company
   VPN/egress IPs and benign services are not indicators. Never write any IP, domain, URL, email or hash that is
   not in the evidence.
6. Timeline times are already computed by code; refer to events by ID (EV001...) rather than restating times
   where possible.
7. Corrective actions and lessons must each cite the evidence that shows why they are needed.
8. The executive summary is a list of short points. Each point lists in based_on the findings it restates
   ("what_happened[2]", "root_cause", "contributing_factors[0]", "detection_gaps[1]") and must not say more than
   them. If any of those findings is not "confirmed", the point must hedge ("probably", "may", "not confirmed").
   The severity rationale must not say more than your findings either.
9. Category: choose it from CONFIRMED events. If the category depends on a step the evidence does not confirm
   (e.g. "phishing" when no email delivery is recorded), use the category of what is confirmed and say what is
   unconfirmed in open questions.
10. Severity (use this scale; do not invent your own):
   SEV1 critical: confirmed access to or exposure of sensitive personal/customer data or credentials at scale,
        likely legal or regulatory notification, ransomware, or widespread business disruption.
   SEV2 high: confirmed compromise of a user account or host with attacker activity, contained, with no
        confirmed large-scale sensitive data exposure.
   SEV3 medium: attempted or minor compromise, quickly contained, minimal impact.
   SEV4 low: suspicious activity with no confirmed compromise.
   How quickly an exposure was closed after it was reported does not lower severity if data was already taken.
11. Refer to evidence in free text by record ID (e.g. R012) only; code converts these for readers.
12. KNOWLEDGE BASE sections (K01...) are company policies and playbooks, not evidence. In corrective actions and
   lessons, also cite the K section that the action follows or that was not followed (quote it exactly). Every
   action and lesson must still cite at least one evidence record (R...) showing why it applies here. Never cite
   K sections for facts about this incident. Only use K sections that actually apply.
13. MITRE ATT&CK: in "attack", list the Enterprise ATT&CK techniques (or sub-techniques, when the evidence is
   specific enough) that the evidence SHOWS the attacker or insider performing. Each needs certainty confirmed or
   probable and evidence citations (R...). Do not map behaviour that analysts only suspect, that the attacker
   claims, or that is "not checked"/"not confirmed". Do not map responder actions. Code checks every ID against
   the official ATT&CK catalogue and fills in names, so give IDs only.
14. Root cause analysis: "immediate_cause" is what directly triggered the incident (e.g. a password typed into a
   fake page); "root_cause" is the underlying weakness that let it succeed. Both are findings with certainty.
15. Impact: list systems_involved and accounts_involved exactly as named in the evidence (code rejects names that
   are not in it). Include only those the attacker or insider used, compromised, or that held affected data;
   not responder accounts, and not systems that were only suspected. Give data_affected, operational_impact and
   business_impact as findings; use certainty "unknown" with no citations when the evidence does not say
   (e.g. financial cost).
16. Response milestones: give the timeline event ID (EV...) for attack_start, first_detection (first alert or
   report), response_start (a responder starts working on it) and containment (first containment action), or
   null if the evidence has no such event. Do NOT compute durations; code does that from the timestamps.
17. Be concise and specific. No filler."""


def build_user_prompt(pack: EvidencePack, issues: list[Issue] | None = None, previous: dict | None = None) -> str:
    parts = [pack.to_prompt(), "",
             "Write the postmortem draft as JSON matching the schema below. "
             "Use empty lists where a section has nothing supported by evidence."]
    if issues:
        parts += ["", "YOUR PREVIOUS DRAFT FAILED THESE CHECKS. Fix every one and resubmit the full draft:"]
        parts += [f"- {i.where}: {i.problem}" for i in issues]
        if previous is not None:
            parts += ["", "PREVIOUS DRAFT:", json.dumps(previous, indent=1)[:20000]]
    return "\n".join(parts)


_ENUM_CASE = {"category": str.lower, "severity": str.upper, "certainty": str.lower, "priority": str.lower,
              "area": str.lower}


def normalise_enums(node):
    """Structured outputs may return enum values that differ only in letter case
    (documented API behaviour); fix that before validation."""
    if isinstance(node, dict):
        return {k: (_ENUM_CASE[k](v) if k in _ENUM_CASE and isinstance(v, str) else normalise_enums(v))
                for k, v in node.items()}
    if isinstance(node, list):
        return [normalise_enums(x) for x in node]
    return node


def generate(pack: EvidencePack, client: LLMClient, max_retries: int = MAX_RETRIES) -> Postmortem:
    schema = DraftReport.model_json_schema()
    issues: list[Issue] | None = None
    raw: dict | None = None
    history: list[str] = []
    best: tuple[DraftReport, list[Issue]] | None = None  # latest draft that parsed, with its problems
    for attempt in range(max_retries + 1):
        try:
            raw = normalise_enums(client.generate_json(SYSTEM_PROMPT, build_user_prompt(pack, issues, raw), schema))
        except LLMOutputError as e:
            issues = [Issue(where="reply", problem=str(e))]
            history.append(f"attempt {attempt + 1}: reply could not be parsed ({e})")
            raw = None
            continue
        try:
            draft = DraftReport.model_validate(raw)
        except ValidationError as e:
            issues = [Issue(where="draft", problem=f"invalid structure: {err['loc']} {err['msg']}")
                      for err in e.errors()[:20]]
            history.append(f"attempt {attempt + 1}: draft did not match the schema ({len(issues)} errors)")
            continue
        issues = validate_draft(draft, pack)
        best = (draft, issues)
        history.append(f"attempt {attempt + 1}: {len(issues)} validation problem(s)")
        if issues and attempt < max_retries:
            # Keep the details: the final attempt's problems are logged by build_postmortem,
            # but earlier ones would otherwise be lost (gap found in run 2).
            history += [f"attempt {attempt + 1} problem: {i.where}: {i.problem}" for i in issues]
        if not issues:
            break
    if best is None:
        raise LLMError("no draft matched the required structure after retries:\n"
                       + "\n".join(f"{i.where}: {i.problem}" for i in issues or []))
    draft, final_issues = best
    pm = build_postmortem(draft, pack, client.model, final_issues)
    from .validate import defang_unknown
    pm.validation_log = [defang_unknown(x, pack.observables) for x in history] + pm.validation_log
    return pm


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------


class _PolicyCites:
    """Numbers knowledge-base references [P1], [P2]... for the policy index."""

    def __init__(self):
        self.index: dict[tuple[str, str], int] = {}
        self.items: dict[int, object] = {}

    def __call__(self, refs) -> str:
        nums = []
        for r in refs:
            key = (r.doc_id, r.section)
            if key not in self.index:
                self.index[key] = len(self.index) + 1
                self.items[self.index[key]] = r
            nums.append(self.index[key])
        return " " + "".join(f"[P{n}]" for n in sorted(set(nums))) if nums else ""


class _Cites:
    """Numbers evidence references [E1], [E2]... and builds the evidence index."""

    def __init__(self):
        self.index: dict[tuple[str, str], int] = {}
        self.quotes: dict[int, str] = {}

    def __call__(self, refs) -> str:
        nums = []
        for r in refs:
            key = (r.file, r.locator)
            if key not in self.index:
                self.index[key] = len(self.index) + 1
                self.quotes[self.index[key]] = r.excerpt or ""
            nums.append(self.index[key])
        return " " + "".join(f"[E{n}]" for n in sorted(set(nums))) if nums else ""


def fmt_duration(seconds: int) -> str:
    s = abs(seconds)
    d, rem = divmod(s, 86400)
    h, rem = divmod(rem, 3600)
    m, sec = divmod(rem, 60)
    parts = [f"{d}d"] * bool(d) + [f"{h}h"] * bool(h) + [f"{m}m"] * bool(m) + [f"{sec}s"] * (bool(sec) and not d)
    return ("-" if seconds < 0 else "") + (" ".join(parts) or "0s")


def _esc(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ")


def render_markdown(pm: Postmortem) -> str:
    cite = _Cites()
    pcite = _PolicyCites()
    key = set(pm.key_event_ids)
    L: list[str] = []
    title = re.sub(rf"^\s*{re.escape(pm.incident_id)}\s*[:\-]\s*", "", pm.title)
    L += [f"# Incident Postmortem: {pm.incident_id}: {title}", "",
          "> **DRAFT: requires human review.** Generated from evidence by code plus an LLM. "
          "Every claim below cites its source record; claims that failed validation were removed "
          "(see Validation log).", "",
          "| Field | Value |", "|---|---|",
          f"| Incident ID | {pm.incident_id} |",
          f"| Category | {pm.category.value} |",
          f"| Severity | {pm.severity.value} |",
          f"| Classification confidence | {pm.classification_confidence:.0%} |",
          f"| Generated | {pm.generated_at:%Y-%m-%d %H:%M} UTC |",
          f"| Model | {pm.model} |", ""]
    L += ["## 1. Executive summary", "", pm.executive_summary, "",
          f"**Severity rationale:** {pm.severity_rationale}", ""]

    L += ["## 2. Timeline (UTC)", "", "Built by code from the evidence. **Bold** = key event.", "",
          "| ID | Time | Event | Time basis | Sources |", "|---|---|---|---|---|"]
    for e in pm.timeline.events:
        row = f"{e.event_id} | {e.timestamp:%Y-%m-%d %H:%M:%S} | {_esc(e.description[:110])}"
        if e.event_id in key:
            row = f"**{e.event_id}** | **{e.timestamp:%Y-%m-%d %H:%M:%S}** | **{_esc(e.description[:110])}**"
        basis = "exact" if e.time_basis is TimeBasis.EXACT else e.time_basis.value.replace("_", " ")
        L.append(f"| {row} | {basis} |{cite(e.sources)} |")
    L.append("")

    def findings(title: str, items, empty: str) -> None:
        L.extend([title, ""])
        if not items:
            L.extend([f"_{empty}_", ""])
            return
        for f in items:
            L.append(f"- **[{f.certainty.value}]** {f.statement}{cite(f.evidence)}")
        L.append("")

    findings("## 3. What happened", pm.what_happened, "No validated findings.")

    L += ["## 4. Indicators of compromise", ""]
    if pm.indicators:
        L += ["| Indicator | Type | First seen |", "|---|---|---|"]
        L += [f"| `{i.value}` | {i.entity_type.value} |{cite([i.first_seen])} |" for i in pm.indicators]
    else:
        L.append("_None identified._")
    L.append("")

    L += ["## 5. MITRE ATT&CK mapping", ""]
    if pm.attack:
        L += ["| Tactic | Technique | ID | Certainty | Behaviour | Evidence |", "|---|---|---|---|---|---|"]
        for a in pm.attack:
            L.append(f"| {a.tactic} | {_esc(a.technique_name)} | {a.technique_id} | {a.certainty.value} "
                     f"| {_esc(a.rationale)} |{cite(a.evidence)} |")
        L += ["", f"_Technique IDs checked against {pm.attack_catalog}. "
                  "ATT&CK® is a registered trademark of The MITRE Corporation._"]
    else:
        L.append("_No techniques passed validation._")
    L.append("")

    L += ["## 6. Root cause", ""]
    if pm.immediate_cause:
        ic = pm.immediate_cause
        L += [f"**Immediate cause [{ic.certainty.value}]:** {ic.statement}{cite(ic.evidence)}", ""]
    if pm.root_cause:
        L.append(f"**[{pm.root_cause.certainty.value}]** {pm.root_cause.statement}{cite(pm.root_cause.evidence)}")
    else:
        L.append("_Not determined. The draft root cause failed validation (see log)._")
    L.append("")
    findings("### Contributing factors", pm.contributing_factors, "None validated.")

    L += ["## 7. Impact assessment", "",
          f"- **Systems involved:** {', '.join(f'`{s}`' for s in pm.impact.systems_involved) or 'none identified'}",
          f"- **Accounts involved:** {', '.join(f'`{a}`' for a in pm.impact.accounts_involved) or 'none identified'}"]
    for label, f in (("Data affected", pm.impact.data_affected), ("Operational impact", pm.impact.operational_impact),
                     ("Business impact", pm.impact.business_impact)):
        L.append(f"- **{label}:** " + (f"[{f.certainty.value}] {f.statement}{cite(f.evidence)}" if f else "_not assessed_"))
    L.append("")

    L += ["## 8. Response analysis", "",
          "Milestones chosen by the model from the timeline; durations computed by code from timestamps.", ""]
    if pm.response:
        L += ["| Milestone | Event | Time (UTC) | Time basis |", "|---|---|---|---|"]
        for name, m in pm.response.milestones.items():
            label = name.replace("_", " ")
            L.append(f"| {label} | {m.event_id} | {m.timestamp:%Y-%m-%d %H:%M:%S} | {m.time_basis.value.replace('_', ' ')} |"
                     if m else f"| {label} | - | not in evidence | - |")
        L += ["", "| Measure | From → to | Duration |", "|---|---|---|"]
        for dd in pm.response.durations:
            approx = " (approximate: inferred time)" if dd.approximate else ""
            L.append(f"| {dd.name.replace('_', ' ')} | {dd.start.replace('_', ' ')} → {dd.end.replace('_', ' ')} "
                     f"| {fmt_duration(dd.seconds)}{approx} |")
    else:
        L.append("_Not computed: the milestones failed validation (see log)._")
    L.append("")
    findings("## 9. Detection gaps", pm.detection_gaps, "None validated.")

    L += ["## 10. Lessons learned", ""]
    for area in ("people", "process", "technology", "governance"):
        items = [x for x in pm.lessons if x.area == area]
        if items:
            L.append(f"**{area.title()}**")
            L += [f"- {x.lesson}{cite(x.evidence)}{pcite(x.policy_refs)}" for x in items]
            L.append("")
    if not pm.lessons:
        L += ["_None validated._", ""]

    L += ["## 11. Corrective actions", ""]
    if pm.corrective_actions:
        L += ["| Priority | Action | Why | Policy | Owner | Timeframe | Expected benefit |",
              "|---|---|---|---|---|---|---|"]
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        for a in sorted(pm.corrective_actions, key=lambda a: order[a.priority.value]):
            L.append(f"| {a.priority.value} | {_esc(a.recommendation)} | {_esc(a.reason)}{cite(a.supporting_evidence)} "
                     f"|{pcite(a.policy_refs) or ' -'} | {_esc(a.owner_team)} | {_esc(a.timeframe)} "
                     f"| {_esc(a.expected_benefit)} |")
    else:
        L.append("_None validated._")
    L.append("")

    L += ["## 12. Open questions and remaining risks", ""]
    L += [f"- **Open:** {q}" for q in pm.open_questions]
    L += [f"- **Risk:** {r}" for r in pm.remaining_risks]
    if not (pm.open_questions or pm.remaining_risks):
        L.append("_None recorded._")
    L.append("")

    L += ["## 13. Validation log", ""]
    L += [f"- {x}" for x in pm.validation_log] or ["- No problems found."]
    L.append("")

    L += ["## Evidence index", "", "| Ref | File | Location | Quote |", "|---|---|---|---|"]
    for (file, loc), n in sorted(cite.index.items(), key=lambda kv: kv[1]):
        L.append(f"| E{n} | {file} | {loc} | {_esc(cite.quotes[n][:120])} |")
    if pcite.index:
        L += ["", "## Policy and playbook references", "",
              "Company knowledge base (synthetic). These support recommendations, not facts about the incident.", "",
              "| Ref | Section | Quote |", "|---|---|---|"]
        for (_, _), n in sorted(pcite.index.items(), key=lambda kv: kv[1]):
            r = pcite.items[n]
            L.append(f"| P{n} | {r.doc_id} §{r.section} {_esc(r.title)} | {_esc(r.excerpt[:120])} |")
    if pm.kb_used:
        L += ["", f"_Knowledge-base sections given to the model: {', '.join(pm.kb_used)}_"]
    L += ["", "**Evidence file hashes (SHA-256)**", ""]
    L += [f"- `{f}`: `{h}`" for f, h in sorted(pm.file_hashes.items())]
    L.append("")
    return "\n".join(L)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Generate a validated incident postmortem.")
    ap.add_argument("incident_folder", type=Path)
    ap.add_argument("--out", type=Path, default=Path("reports"))
    ap.add_argument("--model", default=None)
    ap.add_argument("--dry-run", action="store_true", help="build the prompt only; no API call")
    ap.add_argument("--no-rag", action="store_true", help="do not give the model knowledge-base sections (A/B testing)")
    ap.add_argument("--mode", choices=["prompt", "structured"], default=None,
                    help="how JSON is obtained (default: prompt; structured may fail on large schemas)")
    args = ap.parse_args(argv)

    pack = build_pack(ingest_folder(args.incident_folder), use_kb=not args.no_rag)
    prompt = build_user_prompt(pack)
    if args.dry_run:
        from .llm import schema_instructions
        prompt = prompt + "\n\n" + schema_instructions(DraftReport.model_json_schema())
        print(prompt)
        print(f"\n--- {len(pack.records)} records, {len(pack.timeline.events)} events, {len(pack.kb)} KB sections, "
              f"~{(len(SYSTEM_PROMPT) + len(prompt)) // 4} input tokens (rough estimate) ---")
        return 0
    try:
        opts = {}
        if args.model:
            opts["model"] = args.model
        if args.mode:
            opts["mode"] = args.mode
        client = AnthropicClient(**opts)
        pm = generate(pack, client)
    except LLMError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    args.out.mkdir(parents=True, exist_ok=True)
    suffix = "_norag" if args.no_rag else ""
    md = args.out / f"{pm.incident_id}_postmortem{suffix}.md"
    md.write_text(render_markdown(pm), encoding="utf-8")
    (args.out / f"{pm.incident_id}_postmortem{suffix}.json").write_text(pm.model_dump_json(indent=2), encoding="utf-8")
    print(f"wrote {md}")
    usage = getattr(client, "last_usage", None)
    if usage:
        print(f"tokens (last call): {usage}")
    print("validation: " + "; ".join(pm.validation_log[:3]) + (" ..." if len(pm.validation_log) > 3 else ""))
    gt_file = args.incident_folder / "ground_truth.json"
    if gt_file.exists():
        from .evaluate import score_report
        from .schemas import GroundTruth
        s = score_report(GroundTruth.model_validate_json(gt_file.read_text(encoding="utf-8")), pm)
        print("\nSCORE vs ground truth:")
        for k, v in s.model_dump().items():
            if k != "must_not_claim":
                print(f"  {k:<28} {v:.0%}" if isinstance(v, float) else f"  {k:<28} {'n/a (none listed)' if v is None else v}")
        print("  CHECK BY HAND - the report must NOT state these as fact:")
        for x in s.must_not_claim:
            print(f"    - {x}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
