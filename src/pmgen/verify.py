"""Phase 9: independent verification of a finished postmortem.

The validator (validate.py) checks the LLM draft while the report is being made.
This module checks the *saved report* afterwards, from scratch, against the
original evidence files. A reviewer does not have to trust that the validator ran,
or that the report was not edited later.

It re-reads the evidence with the same readers as ingestion and checks:
  1. evidence files     - same files, same SHA-256 hashes as when the report was made
  2. citations          - every cited location exists and contains the quoted excerpt
  3. policy citations   - every knowledge-base quote exists in that section
  4. indicators         - every IOC appears in the record it says it was first seen in
  5. ATT&CK             - every technique ID exists and is current in the bundled catalogue
  6. response timing    - milestones are timeline events, in order, and durations recompute
  7. impact scope       - every system/account named appears in the evidence
  8. certainty          - confirmed/probable findings have evidence
It does not judge whether a claim is *true*: a correct quote can still be read
wrongly. That part stays with the human reviewer (and the ground-truth scoring).

Usage:  python -m pmgen.verify reports/phase8/INC-2026-001_postmortem.json [more.json ...]
        python -m pmgen.verify reports/phase8/            (every *_postmortem*.json in it)
        --evidence-root DIR   folder holding one sub-folder per incident (default: data/incidents)
Exit code 1 if any check fails.
"""
from __future__ import annotations

import hashlib
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

from .attack import check_id
from .kb import load_chunks
from .provenance import LocatorError, resolve
from .samples import find_data_dir
from .schemas import Certainty, EvidenceRef, Postmortem
from .validate import _in_corpus, _norm


@dataclass
class Check:
    name: str
    checked: int = 0
    failures: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.failures

    def fail(self, msg: str) -> None:
        self.failures.append(msg)


@dataclass
class VerifyResult:
    incident_id: str
    checks: list[Check]
    claims_removed: int  # claims the validator dropped or redacted while building the report

    @property
    def ok(self) -> bool:
        return all(c.ok for c in self.checks)


REMOVAL = re.compile(r"\b(DROPPED|removed unverified indicator|REDACTED)\b")


def _all_refs(pm: Postmortem) -> list[tuple[str, EvidenceRef]]:
    out: list[tuple[str, EvidenceRef]] = []
    singles = {"root_cause": pm.root_cause, "immediate_cause": pm.immediate_cause,
               "impact.data_affected": pm.impact.data_affected,
               "impact.operational_impact": pm.impact.operational_impact,
               "impact.business_impact": pm.impact.business_impact}
    for where, f in singles.items():
        if f:
            out += [(where, r) for r in f.evidence]
    for name in ("what_happened", "contributing_factors", "detection_gaps"):
        for i, f in enumerate(getattr(pm, name)):
            out += [(f"{name}[{i}]", r) for r in f.evidence]
    for i, x in enumerate(pm.lessons):
        out += [(f"lessons[{i}]", r) for r in x.evidence]
    for i, a in enumerate(pm.corrective_actions):
        out += [(f"corrective_actions[{i}]", r) for r in a.supporting_evidence]
    for a in pm.attack:
        out += [(f"attack {a.technique_id}", r) for r in a.evidence]
    for x in pm.indicators:
        out.append((f"indicator {x.value}", x.first_seen))
    for e in pm.timeline.events:
        out += [(f"timeline {e.event_id}", r) for r in e.sources]
    return out


def _findings(pm: Postmortem):
    yield from (("root_cause", pm.root_cause), ("immediate_cause", pm.immediate_cause))
    for k in ("data_affected", "operational_impact", "business_impact"):
        yield f"impact.{k}", getattr(pm.impact, k)
    for name in ("what_happened", "contributing_factors", "detection_gaps"):
        for i, f in enumerate(getattr(pm, name)):
            yield f"{name}[{i}]", f


def verify(pm: Postmortem, evidence_dir: Path, kb_dir: Path | None = None) -> VerifyResult:
    evidence_dir = Path(evidence_dir)
    cache: dict[tuple[str, str], str | None] = {}

    def text_of(ref: EvidenceRef) -> str | None:
        key = (ref.file, ref.locator)
        if key not in cache:
            try:
                cache[key] = resolve(ref, evidence_dir)
            except LocatorError:
                cache[key] = None
        return cache[key]

    # 1. evidence files
    files = Check("evidence files unchanged (SHA-256)")
    present = {p.name for p in evidence_dir.iterdir() if p.is_file() and p.name != "ground_truth.json"}
    for name, h in sorted(pm.file_hashes.items()):
        files.checked += 1
        p = evidence_dir / name
        if not p.is_file():
            files.fail(f"{name}: missing")
        elif hashlib.sha256(p.read_bytes()).hexdigest() != h:
            files.fail(f"{name}: contents changed since the report was generated")
    for extra in sorted(present - set(pm.file_hashes)):
        files.fail(f"{extra}: in the evidence folder but not used by the report")

    # 2. citations
    cites = Check("citations resolve and quotes match")
    for where, ref in _all_refs(pm):
        cites.checked += 1
        t = text_of(ref)
        if t is None:
            cites.fail(f"{where}: {ref.file} {ref.locator} does not exist")
        elif ref.excerpt and _norm(ref.excerpt) not in _norm(t):
            cites.fail(f"{where}: quote {ref.excerpt[:60]!r} not found in {ref.file} {ref.locator}")

    # 3. policy citations
    kb = Check("policy quotes found in the knowledge base")
    sections = {(c.doc_id, c.section): c.text for c in load_chunks(kb_dir)}
    refs = [(f"corrective_actions[{i}]", r) for i, a in enumerate(pm.corrective_actions) for r in a.policy_refs]
    refs += [(f"lessons[{i}]", r) for i, x in enumerate(pm.lessons) for r in x.policy_refs]
    for where, r in refs:
        kb.checked += 1
        body = sections.get((r.doc_id, r.section))
        if body is None:
            kb.fail(f"{where}: {r.doc_id} §{r.section} does not exist")
        elif _norm(r.excerpt) not in _norm(body):
            kb.fail(f"{where}: quote {r.excerpt[:60]!r} not in {r.doc_id} §{r.section}")

    # 4. indicators
    iocs = Check("indicators appear in their cited record")
    for x in pm.indicators:
        iocs.checked += 1
        t = text_of(x.first_seen)
        if t is None or x.value.lower() not in t.lower():
            iocs.fail(f"{x.value}: not in {x.first_seen.file} {x.first_seen.locator}")

    # 5. ATT&CK
    attack = Check("ATT&CK technique IDs exist and are current")
    for a in pm.attack:
        attack.checked += 1
        if err := check_id(a.technique_id):
            attack.fail(err)

    # 6. response timing
    timing = Check("response milestones and durations recompute")
    if pm.response:
        events = {e.event_id: e for e in pm.timeline.events}
        got = {k: m for k, m in pm.response.milestones.items() if m}
        for k, m in got.items():
            timing.checked += 1
            e = events.get(m.event_id)
            if e is None or e.timestamp != m.timestamp:
                timing.fail(f"{k}: {m.event_id} does not match the timeline")
        order = [got[k] for k in ("attack_start", "first_detection", "response_start", "containment") if k in got]
        for a, b in zip(order, order[1:]):
            if b.timestamp < a.timestamp:
                timing.fail(f"{b.event_id} is before {a.event_id}")
        for d in pm.response.durations:
            timing.checked += 1
            s, e = got.get(d.start), got.get(d.end)
            if not (s and e) or int((e.timestamp - s.timestamp).total_seconds()) != d.seconds:
                timing.fail(f"{d.name}: stated {d.seconds}s does not recompute")

    # 7. impact scope
    scope = Check("impact systems/accounts appear in the evidence")
    corpus = "\n".join(text_of(r) or "" for _, r in _all_refs(pm))
    corpus += "\n" + "\n".join((evidence_dir / f).read_text(encoding="utf-8", errors="replace").lower()
                               for f in pm.file_hashes if (evidence_dir / f).is_file())
    corpus = corpus.lower()
    for name in pm.impact.systems_involved + pm.impact.accounts_involved:
        scope.checked += 1
        if not _in_corpus(name, corpus):
            scope.fail(f"{name!r} not found in the evidence")

    # 8. certainty
    cert = Check("confirmed/probable findings have evidence")
    for where, f in _findings(pm):
        if f is None:
            continue
        cert.checked += 1
        if f.certainty in (Certainty.CONFIRMED, Certainty.PROBABLE) and not f.evidence:
            cert.fail(f"{where}: {f.certainty.value} with no evidence")

    removed = sum(1 for line in pm.validation_log if REMOVAL.search(line))
    return VerifyResult(pm.incident_id, [files, cites, kb, iocs, attack, timing, scope, cert], removed)


def render(r: VerifyResult) -> str:
    lines = [f"## {r.incident_id}: {'PASS' if r.ok else 'FAIL'}", "", "| Check | Items | Result |", "|---|---|---|"]
    for c in r.checks:
        lines.append(f"| {c.name} | {c.checked} | {'ok' if c.ok else f'{len(c.failures)} failed'} |")
    for c in r.checks:
        lines += [f"- FAIL ({c.name}): {m}" for m in c.failures]
    lines += ["", f"Claims removed by the validator while building this report: {r.claims_removed}", ""]
    return "\n".join(lines)


def _report_files(args: list[str]) -> list[Path]:
    out: list[Path] = []
    for a in args:
        p = Path(a)
        out += sorted(p.glob("*_postmortem*.json")) if p.is_dir() else [p]
    return out


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    evidence_root = None
    if "--evidence-root" in argv:
        i = argv.index("--evidence-root")
        evidence_root = Path(argv[i + 1])
        argv = argv[:i] + argv[i + 2:]
    files = _report_files(argv)
    if not files:
        print("usage: python -m pmgen.verify REPORT.json|FOLDER [...] [--evidence-root DIR]", file=sys.stderr)
        return 2
    root = evidence_root or find_data_dir()
    results = []
    for f in files:
        pm = Postmortem.model_validate_json(f.read_text(encoding="utf-8"))
        r = verify(pm, root / pm.incident_id)
        results.append(r)
        print(render(r).replace(f"## {r.incident_id}", f"## {r.incident_id} ({f.name})", 1))
    items = sum(c.checked for r in results for c in r.checks)
    bad = sum(len(c.failures) for r in results for c in r.checks)
    print(f"**Total:** {len(results)} report(s), {items} items checked, {bad} failure(s), "
          f"{sum(r.claims_removed for r in results)} claim(s) removed by the validator during generation.")
    return 0 if all(r.ok for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
