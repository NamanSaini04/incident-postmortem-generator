"""Phase 3: deterministic extraction of observables from evidence records.

Three methods, all traceable to an exact record:
  regex         IPs, URLs, domains, emails, hashes, timestamps in free text
  field         known column/key names in CSV/JSON (user, host, process, ...)
  known_entity  users/hosts seen in structured data, re-found in free text
                (e.g. "Revoked sessions for j.patel" in analyst notes)

Important: this module finds OBSERVABLES, not IOCs. It will find the
company's own domain and its VPN IP. Deciding what is malicious is analysis
(Phase 5+), done with context and shown with evidence. Extraction must be
complete (high recall) and exact (no junk); it must not judge.

Run:  python -m pmgen.extract data/incidents/INC-2026-001
"""
from __future__ import annotations

import ipaddress
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from .ingest import ingest_folder
from .schemas import EntityType, EvidenceBundle, EvidenceRecord, EvidenceRef, ExtractedEntity

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

_IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.]*\d)")
_URL = re.compile(r"\bhttps?://[^\s\"'<>,\\]+", re.IGNORECASE)
_EMAIL = re.compile(r"(?<![\w.%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,24}\b")
_DOMAIN = re.compile(
    r"(?<![\w@.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})(?![\w-])", re.IGNORECASE
)
_HASHES = [
    (EntityType.SHA256, re.compile(r"(?<![a-f0-9])[a-f0-9]{64}(?![a-f0-9])", re.IGNORECASE)),
    (EntityType.SHA1, re.compile(r"(?<![a-f0-9])[a-f0-9]{40}(?![a-f0-9])", re.IGNORECASE)),
    (EntityType.MD5, re.compile(r"(?<![a-f0-9])[a-f0-9]{32}(?![a-f0-9])", re.IGNORECASE)),
]
_TS_FULL = re.compile(r"\b(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}(?::\d{2})?)(Z|[+-]\d{2}:?\d{2})?")
_TS_TIME_AT_START = re.compile(r"^\s*(\d{1,2}:\d{2})\b")

# A bare word.word is only a domain if it ends in a real TLD. Without this,
# "j.patel", "upd.dll" and "powershell.exe" all look like domains.
# Kept deliberately short; extend as needed (or swap for the public suffix list).
TLDS = {
    "com", "net", "org", "io", "co", "uk", "gov", "edu", "info", "biz", "us", "eu", "de", "fr",
    "nl", "ru", "cn", "in", "jp", "br", "au", "ca", "app", "dev", "xyz", "top", "online", "site",
    "club", "shop", "cloud", "ai", "me", "tk", "ml", "ga", "cf", "gq",
    "test", "example", "invalid", "localhost",  # reserved (RFC 2606), used in synthetic data
}
_TRAILING_PUNCT = ".,;:!?)]}'"

# Field names (leaf keys, case-insensitive) that hold a known entity type.
FIELD_MAP: dict[str, EntityType] = {
    "user": EntityType.USER, "username": EntityType.USER,
    "host": EntityType.HOST, "src_host": EntityType.HOST, "hostname": EntityType.HOST,
    "process": EntityType.PROCESS, "parent": EntityType.PROCESS,
    "app": EntityType.APPLICATION, "application": EntityType.APPLICATION,
    "bucket": EntityType.CLOUD_RESOURCE, "bucketname": EntityType.CLOUD_RESOURCE,
    "file": EntityType.FILE_PATH, "key": EntityType.FILE_PATH,
    "timestamp": EntityType.TIMESTAMP, "time": EntityType.TIMESTAMP, "eventtime": EntityType.TIMESTAMP,
}
_EMPTY = {"", "-", "none", "null", "n/a"}

_DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
_RFC1918 = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def ip_scope(ip: ipaddress.IPv4Address) -> str:
    if any(ip in n for n in _DOC_NETS):
        return "documentation"
    if any(ip in n for n in _RFC1918):
        return "private"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link_local"
    return "public"


def is_domain(candidate: str) -> bool:
    return candidate.rsplit(".", 1)[-1].lower() in TLDS


def normalise_timestamp(raw: str) -> tuple[str, dict[str, str]] | None:
    """Return (value, attributes). Timezone-aware -> UTC ISO 'Z'.
    Naive -> kept as-is and flagged, never silently assumed to be UTC."""
    try:
        dt = datetime.fromisoformat(raw.strip().replace(" ", "T", 1))
    except ValueError:
        return None
    if dt.tzinfo is None:
        return dt.isoformat(), {"timezone": "missing"}
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), {}


def _flatten(d: dict, prefix: str = "") -> list[tuple[str, object]]:
    out: list[tuple[str, object]] = []
    for k, v in d.items():
        if isinstance(v, dict):
            out += _flatten(v, f"{prefix}{k}.")
        else:
            out.append((f"{prefix}{k}", v))
    return out


class _Collector:
    """Collects entities for one record, dropping exact duplicates."""

    def __init__(self, file: str, rec: EvidenceRecord):
        self.file, self.rec = file, rec
        self.seen: set[tuple[EntityType, str]] = set()
        self.out: list[ExtractedEntity] = []

    def add(self, etype: EntityType, value: str, excerpt: str, method: str, **attrs: str) -> None:
        if (etype, value) in self.seen:
            return
        self.seen.add((etype, value))
        ref = EvidenceRef(file=self.file, locator=self.rec.locator, excerpt=excerpt[:500])
        self.out.append(ExtractedEntity(entity_type=etype, value=value, source=ref, method=method,
                                        attributes=attrs))


# ---------------------------------------------------------------------------
# Extractors
# ---------------------------------------------------------------------------


def _regex_pass(c: _Collector, text: str, is_structured: bool) -> None:
    for m in _URL.finditer(text):
        url = m.group(0).rstrip(_TRAILING_PUNCT)
        c.add(EntityType.URL, url, url, "regex")
        host = urlsplit(url).hostname
        if host:
            try:
                ip = ipaddress.ip_address(host)
                c.add(EntityType.IP, str(ip), host, "regex", scope=ip_scope(ip))
            except ValueError:
                if is_domain(host):
                    c.add(EntityType.DOMAIN, host.lower(), host, "regex")

    for m in _EMAIL.finditer(text):
        email = m.group(0)
        c.add(EntityType.EMAIL, email.lower(), email, "regex")
        domain = email.split("@", 1)[1]
        if is_domain(domain):
            c.add(EntityType.DOMAIN, domain.lower(), domain, "regex")

    for m in _DOMAIN.finditer(text):
        d = m.group(1)
        if is_domain(d):
            c.add(EntityType.DOMAIN, d.lower(), d, "regex")

    for m in _IPV4.finditer(text):
        try:
            ip = ipaddress.ip_address(m.group(1))
        except ValueError:
            continue  # e.g. 999.1.1.1
        c.add(EntityType.IP, str(ip), m.group(1), "regex", scope=ip_scope(ip))

    for etype, pattern in _HASHES:
        for m in pattern.finditer(text):
            c.add(etype, m.group(0).lower(), m.group(0), "regex")

    if not is_structured:  # structured records get timestamps from fields instead
        for m in _TS_FULL.finditer(text):
            norm = normalise_timestamp(m.group(0))
            if norm:
                c.add(EntityType.TIMESTAMP, norm[0], m.group(0), "regex", **norm[1])
        m = _TS_TIME_AT_START.match(text)
        if m and not _TS_FULL.search(text[: m.end() + 1]):
            c.add(EntityType.TIMESTAMP, m.group(1), m.group(1), "regex", precision="time_only")


def _field_pass(c: _Collector, fields: dict) -> None:
    for path, value in _flatten(fields):
        etype = FIELD_MAP.get(path.rsplit(".", 1)[-1].lower())
        if etype is None or not isinstance(value, str) or value.strip().lower() in _EMPTY:
            continue
        if etype is EntityType.TIMESTAMP:
            norm = normalise_timestamp(value)
            if norm:
                c.add(etype, norm[0], value, "field", field=path, **norm[1])
        else:
            c.add(etype, value, value, "field", field=path)


def _known_entity_pass(c: _Collector, text: str, known: dict[EntityType, set[str]]) -> None:
    for etype, values in known.items():
        for v in values:
            # whole-token match; "j.patel" must not match inside "j.patel@corp" or "xj.patel"
            pat = rf"(?<![\w.@-]){re.escape(v)}(?![\w@-])(?!\.\w)"
            m = re.search(pat, text, re.IGNORECASE)
            if m:
                c.add(etype, v, m.group(0), "known_entity")


def extract_bundle(bundle: EvidenceBundle) -> list[ExtractedEntity]:
    entities: list[ExtractedEntity] = []
    collectors: list[tuple[_Collector, bool]] = []

    # Pass 1: regex + structured fields
    for doc in bundle.documents:
        for rec in doc.records:
            c = _Collector(doc.file_name, rec)
            structured = rec.fields is not None
            _regex_pass(c, rec.text, structured)
            if structured:
                _field_pass(c, rec.fields)
            collectors.append((c, structured))

    # Pass 2: link users/hosts from structured data into free text
    known: dict[EntityType, set[str]] = defaultdict(set)
    for c, structured in collectors:
        for e in c.out:
            if structured and e.entity_type in (EntityType.USER, EntityType.HOST) and len(e.value) >= 3:
                known[e.entity_type].add(e.value)
    for c, structured in collectors:
        if not structured:
            _known_entity_pass(c, c.rec.text, known)
        entities += c.out
    return entities


def unique_values(entities: list[ExtractedEntity]) -> dict[EntityType, set[str]]:
    out: dict[EntityType, set[str]] = defaultdict(set)
    for e in entities:
        out[e.entity_type].add(e.value)
    return dict(out)


def _summary(incident: str, entities: list[ExtractedEntity]) -> str:
    lines = [f"Incident {incident}: {len(entities)} observations"]
    for etype, values in sorted(unique_values(entities).items(), key=lambda kv: kv[0].value):
        shown = sorted(values)
        tail = f" (+{len(shown) - 6} more)" if len(shown) > 6 else ""
        lines.append(f"  {etype.value:<15} {len(shown):>3}  {', '.join(shown[:6])}{tail}")
    return "\n".join(lines)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: python -m pmgen.extract <incident_folder>")
    folder = Path(sys.argv[1])
    print(_summary(folder.name, extract_bundle(ingest_folder(folder))))
