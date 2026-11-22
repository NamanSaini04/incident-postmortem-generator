"""Phase 5: the evidence pack, i.e. everything the LLM is allowed to see.

Every record gets a short ID (R001...) so the LLM can cite it, and every
citation can be mapped back to the exact file and locator. The LLM never sees
raw files, only this pack, so it cannot cite something we can't check.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .extract import extract_bundle
from .schemas import EntityType, EvidenceBundle, ExtractedEntity, Timeline
from .timeline import build_timeline

INDICATOR_TYPES = {EntityType.IP, EntityType.DOMAIN, EntityType.URL, EntityType.EMAIL,
                   EntityType.SHA256, EntityType.SHA1, EntityType.MD5}


@dataclass
class PackRecord:
    record_id: str
    file: str
    locator: str
    text: str


@dataclass
class EvidencePack:
    incident_id: str
    records: dict[str, PackRecord]
    by_location: dict[tuple[str, str], str]  # (file, locator) -> record_id
    timeline: Timeline
    entities: list[ExtractedEntity]
    file_hashes: dict[str, str] = field(default_factory=dict)

    @property
    def observables(self) -> dict[str, EntityType]:
        """Every indicator-type value seen in the evidence, lower-cased."""
        return {e.value.lower(): e.entity_type for e in self.entities if e.entity_type in INDICATOR_TYPES}

    def to_prompt(self) -> str:
        lines = [f"INCIDENT: {self.incident_id}", "", "EVIDENCE RECORDS (cite by ID):"]
        for r in self.records.values():
            lines.append(f"[{r.record_id}] {r.file} | {r.locator} | {r.text}")
        lines += ["", "TIMELINE (built by code from the records above; times are UTC):"]
        for e in self.timeline.events:
            ids = ",".join(self.by_location[(s.file, s.locator)] for s in e.sources)
            basis = "" if e.time_basis.value == "exact" else f" [time {e.time_basis.value}]"
            lines.append(f"{e.event_id} {e.timestamp:%Y-%m-%d %H:%M:%S} | {e.description} | records {ids}{basis}")
        for u in self.timeline.undated:
            lines.append(f"UNDATED {self.by_location[(u.source.file, u.source.locator)]}: {u.text}")
        lines += ["", "OBSERVABLES (extracted by code; NOT all are malicious):"]
        by_type: dict[EntityType, list[str]] = {}
        for v, t in sorted(self.observables.items()):
            by_type.setdefault(t, []).append(v)
        for t, vals in by_type.items():
            lines.append(f"{t.value}: {', '.join(vals)}")
        return "\n".join(lines)


def build_pack(bundle: EvidenceBundle) -> EvidencePack:
    entities = extract_bundle(bundle)
    timeline = build_timeline(bundle, entities)
    records: dict[str, PackRecord] = {}
    by_location: dict[tuple[str, str], str] = {}
    n = 0
    for doc in bundle.documents:
        for rec in doc.records:
            n += 1
            rid = f"R{n:03d}"
            records[rid] = PackRecord(rid, doc.file_name, rec.locator, rec.text)
            by_location[(doc.file_name, rec.locator)] = rid
    return EvidencePack(
        incident_id=bundle.incident_id, records=records, by_location=by_location,
        timeline=timeline, entities=entities,
        file_hashes={d.file_name: d.sha256 for d in bundle.documents},
    )
