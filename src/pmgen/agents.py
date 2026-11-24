"""Phase 13: a small multi-agent version, built around the one gap the code checks cannot close.

The validator (validate.py) and the verifier (verify.py) prove that every quote exists where it is cited.
Neither can tell whether the cited record actually SUPPORTS the claim, or supports it at the stated
certainty. The Reviewer agent does that: an independent LLM call that sees each claim next to the full
text of the records it cites (not the draft's reasoning) and returns supported / overstated / unsupported.
It only flags. Nothing is deleted or changed automatically; a human decides.

Pipeline (each stage logs time, tokens and cost to a trace):
    ingest -> extract -> timeline -> KB retrieval     code
    draft                                             LLM (existing generator)
    validate                                          code (inside the generator)
    review                                            LLM (this module)
    verify                                            code

Usage:
    python -m pmgen.agents review reports/phase8 [--plant] [--model M] [--dry-run]
        Reviews saved reports (no regeneration). --plant adds known errors to measure the reviewer.
    python -m pmgen.agents run data/incidents/INC-2026-001 [--dry-run]
        The whole pipeline for one incident, with a stage trace.
"""
from __future__ import annotations

import json
import random
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import BaseModel, Field

from .provenance import LocatorError, resolve
from .samples import find_data_dir
from .schemas import EntityType, Postmortem

PRICE_PER_MTOK = {"claude-sonnet-5-5": (2.0, 10.0)}  # (input, output) USD; others: cost shown as unknown

REVIEW_SYSTEM = """You are an independent reviewer of a cybersecurity incident postmortem draft.
You did not write it. For each claim you get the claim's stated certainty and the FULL text of the
evidence records it cites. Judge ONLY from those records: no outside knowledge, no assumptions about
what "usually" happens.

Verdicts:
- "supported": the cited records state it, at the stated certainty.
- "overstated": the records support a weaker version: the claim is labelled confirmed but the records
  only make it probable/possible, or it generalises beyond them. Give suggested_certainty.
- "understated": the records support MORE than the stated certainty: e.g. labelled probable while a cited
  record states it directly. Give suggested_certainty.
- "unsupported": the cited records do not say it, or contradict it (wrong person, host, time, count,
  or event).
Certainty rules: confirmed = directly stated in the records; probable = a strong inference from them;
possible = consistent with them but not shown.
Review every claim exactly once. reason: at most 30 words, naming what the records do or do not say."""


class ClaimReview(BaseModel):
    claim_id: str
    verdict: str = Field(pattern=r"^(supported|overstated|understated|unsupported)$")
    suggested_certainty: str | None = Field(default=None, pattern=r"^(confirmed|probable|possible|unknown)$")
    reason: str = Field(max_length=400)


class ReviewReply(BaseModel):
    reviews: list[ClaimReview]


@dataclass
class Claim:
    claim_id: str
    where: str
    certainty: str
    statement: str
    records: list[tuple[str, str, str]]  # (file, locator, full text)
    planted: str | None = None           # benchmark only: the kind of error deliberately introduced


@dataclass
class TraceStep:
    stage: str
    kind: str  # "code" or "LLM"
    seconds: float
    detail: str = ""
    input_tokens: int | None = None
    output_tokens: int | None = None


@dataclass
class Trace:
    model: str = ""
    steps: list[TraceStep] = field(default_factory=list)

    def add(self, stage, kind, t0, detail="", usage: dict | None = None):
        u = usage or {}
        self.steps.append(TraceStep(stage, kind, round(time.perf_counter() - t0, 2), detail,
                                    u.get("input_tokens"), u.get("output_tokens")))

    def cost(self) -> float | None:
        price = PRICE_PER_MTOK.get(self.model)
        tokens = [(s.input_tokens or 0, s.output_tokens or 0) for s in self.steps if s.kind == "LLM"]
        if price is None or not tokens:
            return None
        return sum(i * price[0] + o * price[1] for i, o in tokens) / 1e6

    def markdown(self) -> str:
        L = ["| Stage | Kind | Seconds | Tokens in/out | Detail |", "|---|---|---|---|---|"]
        for s in self.steps:
            tok = f"{s.input_tokens}/{s.output_tokens}" if s.input_tokens is not None else "-"
            L.append(f"| {s.stage} | {s.kind} | {s.seconds} | {tok} | {s.detail} |")
        c = self.cost()
        L.append(f"\nEstimated LLM cost: {'unknown for ' + self.model if c is None else f'${c:.3f}'}")
        return "\n".join(L)


# ---------------------------------------------------------------- claims

def collect_claims(pm: Postmortem, evidence_dir: Path) -> list[Claim]:
    """Factual claims that cite evidence. Recommendations (lessons, actions) are not facts and are skipped."""
    items = []
    for name in ("what_happened", "contributing_factors", "detection_gaps"):
        items += [(f"{name}[{i}]", f) for i, f in enumerate(getattr(pm, name))]
    for name in ("immediate_cause", "root_cause"):
        if getattr(pm, name):
            items.append((name, getattr(pm, name)))
    for k in ("data_affected", "operational_impact", "business_impact"):
        if getattr(pm.impact, k):
            items.append((f"impact.{k}", getattr(pm.impact, k)))
    claims: list[Claim] = []
    for where, f in items:
        if not f.evidence:
            continue
        claims.append(Claim("", where, f.certainty.value, f.statement, _records(f.evidence, evidence_dir)))
    for a in pm.attack:
        claims.append(Claim("", f"attack {a.technique_id}", a.certainty.value,
                            f"{a.technique_id} {a.technique_name}: {a.rationale}", _records(a.evidence, evidence_dir)))
    return claims


def _records(refs, evidence_dir: Path) -> list[tuple[str, str, str]]:
    out = []
    for r in refs:
        try:
            text = resolve(r, evidence_dir)
        except LocatorError:
            text = "(record not found)"
        out.append((r.file, r.locator, text))
    return out


def incident_names(evidence_dir: Path) -> list[str]:
    """Accounts, hosts and IPs extracted from the incident's evidence: the pool for entity swaps."""
    from .extract import extract_bundle
    from .ingest import ingest_folder
    keep = {EntityType.USER, EntityType.HOST, EntityType.IP}
    return sorted({e.value for e in extract_bundle(ingest_folder(Path(evidence_dir))) if e.entity_type in keep})


def plant_errors(claims: list[Claim], pm: Postmortem, seed: int = 13, names: list[str] | None = None) -> list[Claim]:
    """Known errors for measuring the reviewer. Each planted claim keeps real citations, so the code
    checks (quote exists) would all pass; only reading for meaning can catch it.
      certainty  - a probable claim relabelled confirmed                       -> expect overstated
      swap       - a statement moved onto another claim's unrelated citations  -> expect unsupported
      entity     - an account/host in the statement replaced by another one    -> expect unsupported
                   from the same incident that the cited records do not mention
    """
    rng = random.Random(seed)
    planted: list[Claim] = []
    probable = [c for c in claims if c.certainty == "probable"]
    for c in rng.sample(probable, min(2, len(probable))):
        planted.append(Claim("", c.where + " (planted)", "confirmed", c.statement, c.records, "certainty"))
    pool = [c for c in claims if not c.where.startswith("attack")]
    for _ in range(2):
        if len(pool) < 2:
            break
        a, b = rng.sample(pool, 2)
        if {x[:2] for x in a.records} & {x[:2] for x in b.records}:
            continue  # shared citations: the swap might still be supported
        planted.append(Claim("", b.where + " (planted)", "confirmed", a.statement, b.records, "swap"))
    if names is None:
        names = sorted({*pm.impact.accounts_involved, *pm.impact.systems_involved,
                        *(i.value for i in pm.indicators if i.entity_type is EntityType.IP)})
    word = lambda n, s: re.search(rf"(?<![\w.-]){re.escape(n.lower())}(?![\w-])", s.lower())  # noqa: E731
    for c in pool:
        if len([p for p in planted if p.planted == "entity"]) >= 2:
            break
        text_all = " ".join(r[2] for r in c.records).lower()
        here = [n for n in names if word(n, c.statement)]
        others = [n for n in names if not word(n, text_all) and n not in here and type_of(n) == type_of(here[0])] if here else []
        if here and others:
            stmt = re.sub(re.escape(here[0]), others[0], c.statement, flags=re.IGNORECASE)
            planted.append(Claim("", c.where + " (planted)", c.certainty, stmt, c.records, "entity"))
    return planted


def type_of(name: str) -> str:
    """Swap like for like (IP for IP, account for account) so the planted claim stays plausible."""
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", name):
        return "ip"
    return "host" if re.search(r"[A-Z]{2,}-\d", name) else "account"


def number(claims: list[Claim], seed: int = 7) -> list[Claim]:
    """Shuffle (so planted claims are not grouped) and give neutral IDs."""
    out = list(claims)
    random.Random(seed).shuffle(out)
    for i, c in enumerate(out, 1):
        c.claim_id = f"C{i:02d}"
    return out


def review_prompt(claims: list[Claim]) -> str:
    blocks = []
    for c in claims:
        recs = "\n".join(f"  [{f} {loc}] {text}" for f, loc, text in c.records)
        blocks.append(f"{c.claim_id} (stated certainty: {c.certainty})\n  CLAIM: {c.statement}\n  CITED RECORDS:\n{recs}")
    return ("Review each claim against its cited records only.\n\n" + "\n\n".join(blocks) +
            f"\n\nReturn one review per claim: {', '.join(c.claim_id for c in claims)}.")


def run_review(claims: list[Claim], client, max_retries: int = 1) -> tuple[dict[str, ClaimReview], list[str], dict]:
    """Returns reviews by claim_id, problems, and token usage summed over attempts."""
    want = {c.claim_id for c in claims}
    got: dict[str, ClaimReview] = {}
    problems: list[str] = []
    usage = {"input_tokens": 0, "output_tokens": 0}
    todo = claims
    for _ in range(max_retries + 1):
        raw = client.generate_json(REVIEW_SYSTEM, review_prompt(todo), ReviewReply.model_json_schema())
        u = getattr(client, "last_usage", None) or {}
        for k in usage:
            usage[k] += u.get(k) or 0
        try:
            reply = ReviewReply.model_validate(raw)
        except Exception as e:  # noqa: BLE001 - any malformed reply is retried once, then reported
            problems.append(f"malformed review reply: {str(e)[:200]}")
            continue
        for r in reply.reviews:
            if r.claim_id not in want:
                problems.append(f"review for unknown claim {r.claim_id} ignored")
            elif r.claim_id not in got:
                got[r.claim_id] = r
        todo = [c for c in claims if c.claim_id not in got]
        if not todo:
            break
    problems += [f"{c.claim_id} ({c.where}) not reviewed" for c in claims if c.claim_id not in got]
    return got, problems, usage


# ---------------------------------------------------------------- benchmark scoring

EXPECTED = {"certainty": {"overstated", "unsupported"}, "swap": {"unsupported", "overstated"},
            "entity": {"unsupported"}}


@dataclass
class ReviewScore:
    planted: int = 0
    caught: int = 0
    by_kind: dict = field(default_factory=dict)        # kind -> [caught, total]
    originals: int = 0
    flagged_originals: list = field(default_factory=list)  # (claim, review) for a human to judge


def score_review(claims: list[Claim], reviews: dict[str, ClaimReview]) -> ReviewScore:
    s = ReviewScore()
    for c in claims:
        r = reviews.get(c.claim_id)
        if c.planted:
            s.planted += 1
            k = s.by_kind.setdefault(c.planted, [0, 0])
            k[1] += 1
            if r and r.verdict in EXPECTED[c.planted]:
                s.caught += 1
                k[0] += 1
        else:
            s.originals += 1
            if r and r.verdict != "supported":
                s.flagged_originals.append((c, r))
    return s


# ---------------------------------------------------------------- CLI

def _client(model: str | None):
    from .llm import DEFAULT_MODEL, AnthropicClient
    return AnthropicClient(model=model or DEFAULT_MODEL, max_tokens=8000)


def review_folder(folder: Path, client, plant: bool, incidents_dir: Path, out_dir: Path) -> str:
    out_dir.mkdir(parents=True, exist_ok=True)
    total = ReviewScore()
    L = ["# Reviewer agent results", "", f"Reports: `{folder}`. Model: {client.model}. "
         f"Planted errors: {'yes' if plant else 'no'}.", ""]
    trace = Trace(model=client.model)
    for f in sorted(Path(folder).glob("*_postmortem.json")):
        pm = Postmortem.model_validate_json(f.read_text(encoding="utf-8"))
        t0 = time.perf_counter()
        originals = collect_claims(pm, incidents_dir / pm.incident_id)
        names = incident_names(incidents_dir / pm.incident_id)
        claims = number(originals + (plant_errors(originals, pm, names=names) if plant else []))
        reviews, problems, usage = run_review(claims, client)
        trace.add(f"review {pm.incident_id}", "LLM", t0, f"{len(claims)} claims", usage)
        s = score_review(claims, reviews)
        total.planted += s.planted
        total.caught += s.caught
        total.originals += s.originals
        total.flagged_originals += [(pm.incident_id, c, r) for c, r in s.flagged_originals]
        for k, (a, b) in s.by_kind.items():
            tk = total.by_kind.setdefault(k, [0, 0])
            tk[0] += a
            tk[1] += b
        (out_dir / f"{pm.incident_id}_review.json").write_text(json.dumps({
            "incident_id": pm.incident_id, "model": client.model, "problems": problems,
            "claims": [{"id": c.claim_id, "where": c.where, "certainty": c.certainty, "statement": c.statement,
                        "planted": c.planted, "review": reviews[c.claim_id].model_dump() if c.claim_id in reviews
                        else None} for c in claims]}, indent=2), encoding="utf-8")
        L.append(f"- {pm.incident_id}: {len(claims)} claims, {sum(r.verdict != 'supported' for r in reviews.values())} "
                 f"flagged{'; ' + '; '.join(problems) if problems else ''}")
    L += ["", "## Summary", ""]
    if plant:
        L.append(f"- Planted errors caught: **{total.caught}/{total.planted}**")
        for k, (a, b) in sorted(total.by_kind.items()):
            L.append(f"  - {k}: {a}/{b}")
    L.append(f"- Unmodified claims flagged: **{len(total.flagged_originals)}/{total.originals}**. "
             "Not automatically false alarms: each needs a human to judge (table below).")
    kinds = {}
    for _, _, r in total.flagged_originals:
        kinds[r.verdict] = kinds.get(r.verdict, 0) + 1
    if kinds:
        L.append("  - by verdict: " + ", ".join(f"{k} {v}" for k, v in sorted(kinds.items()))
                 + " (understated = certainty set lower than the records support: over-hedging)")
    L += ["", "| Incident | Where | Stated | Verdict | Suggested | Claim | Reviewer's reason |",
          "|---|---|---|---|---|---|---|"]
    for inc, c, r in total.flagged_originals:
        L.append(f"| {inc} | {c.where} | {c.certainty} | {r.verdict} | {r.suggested_certainty or '-'} | "
                 f"{c.statement[:120].replace('|', '/')} | {r.reason.replace('|', '/')} |")
    L += ["", "## Trace", "", trace.markdown(), "",
          "Limits: the reviewer is the same model family as the drafter; planted errors are simple and of 3 kinds; "
          "a planted claim in the same batch may make the reviewer more suspicious overall."]
    md = "\n".join(L)
    (out_dir / "review_summary.md").write_text(md + "\n", encoding="utf-8")
    return md


def run_pipeline(evidence_dir: Path, draft_client, review_client) -> tuple[Postmortem, dict, Trace]:
    """The whole pipeline as named stages, with a trace."""
    from .evidence_pack import build_pack
    from .extract import extract_bundle
    from .ingest import ingest_folder
    from .postmortem import generate
    from .verify import verify

    trace = Trace(model=draft_client.model)
    t0 = time.perf_counter()
    bundle = ingest_folder(Path(evidence_dir))
    trace.add("ingest", "code", t0, f"{sum(len(d.records) for d in bundle.documents)} records from {len(bundle.documents)} files")
    t0 = time.perf_counter()
    ents = extract_bundle(bundle)
    trace.add("extract", "code", t0, f"{len(ents)} observables")
    t0 = time.perf_counter()
    pack = build_pack(bundle)
    trace.add("timeline + KB retrieval", "code", t0, f"{len(pack.timeline.events)} events, {len(pack.kb)} policy sections")
    t0 = time.perf_counter()
    pm = generate(pack, draft_client)
    trace.add("draft + validate", "LLM", t0, "; ".join(pm.validation_log[:1]), getattr(draft_client, "last_usage", None))
    t0 = time.perf_counter()
    claims = number(collect_claims(pm, Path(evidence_dir)))
    reviews, problems, usage = run_review(claims, review_client)
    flagged = sum(r.verdict != "supported" for r in reviews.values())
    trace.add("review", "LLM", t0, f"{len(claims)} claims, {flagged} flagged", usage)
    t0 = time.perf_counter()
    check = verify(pm, Path(evidence_dir))
    trace.add("verify", "code", t0, "PASS" if check.ok else "FAIL")
    review = {"claims": [{"id": c.claim_id, "where": c.where, "review": reviews[c.claim_id].model_dump()
                          if c.claim_id in reviews else None} for c in claims], "problems": problems}
    return pm, review, trace


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] not in ("review", "run") or len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    cmd, target, rest = argv[0], Path(argv[1]), argv[2:]
    if not target.exists():
        print(f"not found: {target}  (saved reports in the repository are in docs/sample_reports/phase8/)",
              file=sys.stderr)
        return 2
    model = rest[rest.index("--model") + 1] if "--model" in rest else None
    incidents = find_data_dir()
    if "--dry-run" in rest:
        files = sorted(target.glob("*_postmortem.json")) if cmd == "review" else []
        for f in files[:1]:
            pm = Postmortem.model_validate_json(f.read_text(encoding="utf-8"))
            originals = collect_claims(pm, incidents / pm.incident_id)
            names = incident_names(incidents / pm.incident_id)
            claims = number(originals + (plant_errors(originals, pm, names=names) if "--plant" in rest else []))
            print(REVIEW_SYSTEM, "\n\n", review_prompt(claims))
            print(f"\n--- {pm.incident_id}: {len(claims)} claims ({len(claims) - len(originals)} planted); "
                  f"{len(files)} report(s) in the folder; no API call made")
        if cmd == "run":
            print(f"would run the full pipeline on {target}; no API call made")
        return 0
    client = _client(model)
    if cmd == "review":
        print(review_folder(target, client, "--plant" in rest, incidents, Path("reports/review")))
        return 0
    pm, review, trace = run_pipeline(target, client, client)
    out = Path("reports/agents")
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{pm.incident_id}_postmortem.json").write_text(pm.model_dump_json(indent=2), encoding="utf-8")
    (out / f"{pm.incident_id}_review.json").write_text(json.dumps(review, indent=2), encoding="utf-8")
    (out / f"{pm.incident_id}_trace.md").write_text(trace.markdown() + "\n", encoding="utf-8")
    print(trace.markdown())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
