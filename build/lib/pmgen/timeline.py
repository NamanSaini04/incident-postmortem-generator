"""Phase 4: build a chronological incident timeline from extracted observables.

Rules:
  * One candidate event per evidence record that carries a timestamp.
  * Time-only notes ("09:52 Revoked sessions") get their date from the other
    evidence. If every dated event falls on one day, that day is used
    (confidence 0.8). If the evidence spans several days, the date is a
    guess and confidence drops to 0.4, with the reason recorded.
  * Timestamps without a timezone are assumed UTC, and this is recorded in
    `time_basis`, never hidden.
  * The same event seen in two logs (e.g. EDR network connection + proxy
    request in the same second) is merged into one event with both sources,
    but only if they are within MERGE_WINDOW, share a strong observable
    (IP/URL/domain/hash/email) and don't name different users or hosts.

Descriptions here are plain and mechanical on purpose. Readable wording is the
LLM's job (Phase 5); this layer's job is correct times, order and sources.

Run:  python -m pmgen.timeline data/incidents/INC-2026-001
"""
from __future__ import annotations

import re
import sys
from collections import defaultdict
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from .extract import extract_bundle
from .ingest import ingest_folder
from .schemas import (
    EntityType,
    EventStatus,
    EvidenceBundle,
    EvidenceRef,
    ExtractedEntity,
    TimeBasis,
    Timeline,
    TimelineEvent,
    UndatedNote,
)

MERGE_WINDOW = timedelta(seconds=2)
_DATE = re.compile(r"\b(\d{4}-\d{2}-\d{2})\b")
_TIME_ONLY_START = re.compile(r"^\s*\d{1,2}:\d{2}\b")
STRONG = {EntityType.IP, EntityType.URL, EntityType.DOMAIN, EntityType.SHA256,
          EntityType.SHA1, EntityType.MD5, EntityType.EMAIL}
IDENTITY = {EntityType.USER, EntityType.HOST}

# Fields worth showing in a mechanical description, in priority order.
DESC_FIELDS = ["rule", "event", "eventName", "operation", "subject", "action", "result",
               "method", "app", "process", "cmdline", "url", "dest", "key", "user", "userName",
               "src_host", "src_ip", "remote_ip", "recipient", "severity"]
CONFIDENCE = {TimeBasis.EXACT: 0.95, TimeBasis.TIMEZONE_ASSUMED: 0.8, TimeBasis.DATE_INFERRED: 0.8}


class _Candidate:
    def __init__(self, ts: datetime, basis: TimeBasis, desc: str, ref: EvidenceRef,
                 entities: list[ExtractedEntity], confidence: float, rationale: str | None):
        self.ts, self.basis, self.desc = ts, basis, desc
        self.sources = [ref]
        self.entities = entities
        self.confidence, self.rationale = confidence, rationale

    def values(self, types: set[EntityType]) -> set[tuple[EntityType, str]]:
        return {(e.entity_type, e.value.lower()) for e in self.entities if e.entity_type in types}


def _describe(fields: dict | None, text: str) -> str:
    if fields is None:
        return text.strip()
    flat: dict[str, str] = {}
    for k, v in fields.items():
        if isinstance(v, dict):
            for k2, v2 in v.items():
                if not isinstance(v2, (dict, list)):
                    flat[k2] = str(v2)
        elif not isinstance(v, list):
            flat[k] = str(v)
    parts = [f"{k}={flat[k]}" for k in DESC_FIELDS if flat.get(k) not in (None, "", "-")]
    return "; ".join(parts[:6]) or text[:200]


def _parse(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def build_timeline(bundle: EvidenceBundle, entities: list[ExtractedEntity] | None = None) -> Timeline:
    entities = entities if entities is not None else extract_bundle(bundle)
    by_record: dict[tuple[str, str], list[ExtractedEntity]] = defaultdict(list)
    for e in entities:
        by_record[(e.source.file, e.source.locator)].append(e)

    warnings: list[str] = []
    candidates: list[_Candidate] = []
    # (stamp, description, entities, anchor date or None, anchor line)
    time_only: list[tuple[ExtractedEntity, str, list[ExtractedEntity], date | None, str | None]] = []

    for doc in bundle.documents:
        # Notes often carry a date heading ("Log date 2026-11-10") or a dated line;
        # later HH:MM lines in the same file belong to that date, rolling to the
        # next day if the clock goes backwards (e.g. 23:58 then 00:10).
        anchor: date | None = None
        anchor_line: str | None = None
        last_time: tuple[int, int] | None = None
        for rec in doc.records:
            if rec.fields is None and not _TIME_ONLY_START.match(rec.text):
                m = _DATE.search(rec.text)
                if m:
                    anchor, anchor_line, last_time = date.fromisoformat(m.group(1)), rec.locator, None
            ents = by_record.get((doc.file_name, rec.locator), [])
            stamps = [e for e in ents if e.entity_type is EntityType.TIMESTAMP]
            if not stamps:
                continue
            stamp = stamps[0]
            if len(stamps) > 1:
                warnings.append(f"{doc.file_name} {rec.locator}: {len(stamps)} timestamps, used the first")
            ref = EvidenceRef(file=doc.file_name, locator=rec.locator, excerpt=stamp.source.excerpt)
            desc = _describe(rec.fields, rec.text)
            if stamp.attributes.get("precision") == "time_only":
                hm = tuple(map(int, stamp.value.split(":")))
                if anchor is not None and last_time is not None and hm < last_time:
                    anchor = anchor + timedelta(days=1)
                    anchor_line = f"{anchor_line} (+1 day: clock went past midnight)"
                last_time = hm
                time_only.append((stamp, desc, ents, anchor, anchor_line))
                continue
            if stamp.attributes.get("timezone") == "missing":
                ts = _parse(stamp.value).replace(tzinfo=timezone.utc)
                basis, rationale = TimeBasis.TIMEZONE_ASSUMED, "timestamp had no timezone; assumed UTC"
            else:
                ts, basis, rationale = _parse(stamp.value), TimeBasis.EXACT, None
            candidates.append(_Candidate(ts, basis, desc, ref, ents, CONFIDENCE[basis], rationale))

    # Resolve time-only notes against the dates seen in the rest of the evidence.
    days: set[date] = {c.ts.astimezone(timezone.utc).date() for c in candidates}
    undated: list[UndatedNote] = []
    for stamp, desc, ents, anchor_day, anchor_from in time_only:
        ref = EvidenceRef(file=stamp.source.file, locator=stamp.source.locator, excerpt=stamp.source.excerpt)
        hh, mm = map(int, stamp.value.split(":"))
        if anchor_day is not None:
            ts = datetime(anchor_day.year, anchor_day.month, anchor_day.day, hh, mm, tzinfo=timezone.utc)
            why = f"note gave time only; date {anchor_day} taken from {stamp.source.file} {anchor_from}; timezone assumed UTC"
            candidates.append(_Candidate(ts, TimeBasis.DATE_INFERRED, desc, ref, ents, 0.8, why))
            continue
        if not days:
            undated.append(UndatedNote(text=desc, source=ref, reason="time only, and no dated evidence to anchor it"))
            continue
        day = max(days)
        ts = datetime(day.year, day.month, day.day, hh, mm, tzinfo=timezone.utc)
        if len(days) == 1:
            conf, why = 0.8, f"note gave time only; date {day} is the only date in the evidence; timezone assumed UTC"
        else:
            conf, why = 0.4, (f"note gave time only; evidence spans {len(days)} dates, latest ({day}) assumed; "
                              "verify manually")
            warnings.append(f"{ref.file} {ref.locator}: date guessed from {len(days)} possible days")
        candidates.append(_Candidate(ts, TimeBasis.DATE_INFERRED, desc, ref, ents, conf, why))

    candidates.sort(key=lambda c: (c.ts, c.sources[0].file, c.sources[0].locator))
    merged = _merge(candidates)

    events = []
    for i, c in enumerate(merged, start=1):
        desc = c.desc if len(c.sources) == 1 else f"{c.desc} (seen in {len(c.sources)} sources)"
        events.append(TimelineEvent(
            event_id=f"EV{i:03d}", timestamp=c.ts, time_basis=c.basis, description=desc,
            status=EventStatus.CONFIRMED, confidence=c.confidence, sources=c.sources, rationale=c.rationale,
        ))
    return Timeline(incident_id=bundle.incident_id, events=events, undated=undated, warnings=warnings)


def _merge(candidates: list[_Candidate]) -> list[_Candidate]:
    out: list[_Candidate] = []
    for c in candidates:
        target = None
        for prev in reversed(out):
            if c.ts - prev.ts > MERGE_WINDOW:
                break
            shares = c.values(STRONG) & prev.values(STRONG)
            # Conflict = both name a user (or both a host) and the names differ.
            # A user in one log and a host in the other is NOT a conflict.
            conflict = False
            for t in IDENTITY:
                a, b = c.values({t}), prev.values({t})
                if a and b and not (a & b):
                    conflict = True
            if shares and not conflict:
                target = prev
                break
        if target is None:
            out.append(c)
        else:
            target.sources += c.sources
            target.entities += c.entities
            target.confidence = max(target.confidence, c.confidence)
    return out


def _render(tl: Timeline) -> str:
    lines = [f"Timeline {tl.incident_id}: {len(tl.events)} events"]
    for e in tl.events:
        flag = "" if e.time_basis is TimeBasis.EXACT else f" [{e.time_basis.value}]"
        src = ", ".join(f"{s.file}:{s.locator}" for s in e.sources)
        lines.append(f"  {e.timestamp:%Y-%m-%d %H:%M:%S}Z  {e.description[:70]:<70}  <- {src}{flag}")
    lines += [f"  undated: {u.source.file}:{u.source.locator} ({u.reason})" for u in tl.undated]
    lines += [f"  warning: {w}" for w in tl.warnings]
    return "\n".join(lines)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: python -m pmgen.timeline <incident_folder>")
    print(_render(build_timeline(ingest_folder(Path(sys.argv[1])))))
