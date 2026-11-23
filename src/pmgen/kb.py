"""Phase 6: knowledge base retrieval (RAG) over company policies and playbooks.

Documents:  data/knowledge_base/*.md, one policy/playbook per file.
Chunking:   one chunk per "## §n Title" section, so every chunk is citable as
            "POL-07 §3" and never mixes two rules.
Retrieval:  BM25 keyword ranking, implemented here (no dependencies).

Why BM25 and not embeddings + a vector database: the knowledge base is ~60
short sections full of specific terms (MFA, RDP, DLP, iam:*), which keyword
ranking handles well. A vector DB adds setup without a measured benefit at this
size. Embeddings are a possible upgrade; they should be adopted only if they
beat BM25 on `python -m pmgen.kb --eval`.

Run:
  python -m pmgen.kb --eval                      retrieval recall@k on all incidents
  python -m pmgen.kb --query "MFA exception"     show top sections for a query
"""
from __future__ import annotations

import argparse
import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from .schemas import EvidenceBundle

DEFAULT_K = 8  # chosen on the 6 bundled incidents: k=6 gave 76% mean recall, k=8 84.7%, a per-doc cap 72-81%
_SECTION = re.compile(r"^##\s+§(\d+)\s+(.+)$", re.MULTILINE)
_TOKEN = re.compile(r"[a-z0-9][a-z0-9:*.\-]*[a-z0-9*]|[a-z0-9]")
STOPWORDS = set("""a an and are as at be by for from has have in into is it its of on or that the this to was were
will with not no all any can must may only than then there their they which who whom per via""".split())


@dataclass(frozen=True)
class Chunk:
    doc_id: str
    section: str  # "3"
    title: str    # section heading
    doc_title: str
    text: str

    @property
    def key(self) -> str:
        return f"{self.doc_id}#{self.section}"

    @property
    def label(self) -> str:
        return f"{self.doc_id} §{self.section} {self.title}"


def tokenize(text: str) -> list[str]:
    toks = []
    for t in _TOKEN.findall(text.lower()):
        t = t.strip(".-")
        if t and t not in STOPWORDS:
            toks.append(t)
            if t.endswith("s") and len(t) > 4:  # crude plural folding: alerts -> alert
                toks.append(t[:-1])
    return toks


def kb_dir(data_dir: Path | None = None) -> Path:
    from .samples import DATA_DIR
    return (data_dir or DATA_DIR).parent / "knowledge_base"


def load_chunks(folder: Path | None = None) -> list[Chunk]:
    folder = folder or kb_dir()
    chunks: list[Chunk] = []
    if not folder.is_dir():
        return chunks
    for path in sorted(folder.glob("*.md")):
        text = path.read_text(encoding="utf-8")
        first = text.splitlines()[0].lstrip("# ").strip() if text else path.stem
        doc_id = first.split()[0]
        doc_title = first[len(doc_id):].strip()
        matches = list(_SECTION.finditer(text))
        for i, m in enumerate(matches):
            end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
            body = text[m.end():end].strip()
            chunks.append(Chunk(doc_id, m.group(1), m.group(2).strip(), doc_title, body))
    return chunks


class BM25:
    def __init__(self, chunks: list[Chunk], k1: float = 1.5, b: float = 0.75):
        self.chunks, self.k1, self.b = chunks, k1, b
        # Title words are indexed with the body so "Service accounts" matches its section.
        self.docs = [tokenize(f"{c.doc_title} {c.title} {c.title} {c.text}") for c in chunks]
        self.tf = [Counter(d) for d in self.docs]
        self.avgdl = sum(map(len, self.docs)) / max(len(self.docs), 1)
        df = Counter(t for d in self.docs for t in set(d))
        n = len(self.docs)
        self.idf = {t: math.log(1 + (n - f + 0.5) / (f + 0.5)) for t, f in df.items()}

    def scores(self, query: str) -> list[float]:
        q = Counter(tokenize(query))
        out = []
        for tf, d in zip(self.tf, self.docs):
            s = 0.0
            for t in q:
                if t in tf:
                    f = tf[t]
                    s += self.idf[t] * f * (self.k1 + 1) / (f + self.k1 * (1 - self.b + self.b * len(d) / self.avgdl))
            out.append(s)
        return out

    def search(self, query: str, k: int = DEFAULT_K) -> list[tuple[Chunk, float]]:
        ranked = sorted(zip(self.chunks, self.scores(query)), key=lambda x: -x[1])
        return [(c, s) for c, s in ranked[:k] if s > 0]


# Field names whose values describe what happened (alert names, actions, findings).
_QUERY_FIELDS = {"rule", "alert", "policy", "event", "eventname", "operation", "action", "detail", "category",
                 "process", "cmdline", "mode", "subject"}


def build_query(bundle: EvidenceBundle) -> str:
    """Query = free-text notes (where findings live) + descriptive fields from logs.
    IPs, hashes, names and timestamps are left out: they never appear in policies."""
    parts: list[str] = []
    for doc in bundle.documents:
        for rec in doc.records:
            if rec.fields is None:
                parts.append(rec.text)
            else:
                def walk(d):
                    for k, v in d.items():
                        if isinstance(v, dict):
                            walk(v)
                        elif k.lower() in _QUERY_FIELDS and isinstance(v, str):
                            parts.append(v)
                walk(rec.fields)
    return "\n".join(parts)


def retrieve(bundle: EvidenceBundle, chunks: list[Chunk] | None = None, k: int = DEFAULT_K) -> list[Chunk]:
    chunks = load_chunks() if chunks is None else chunks
    if not chunks:
        return []
    return [c for c, _ in BM25(chunks).search(build_query(bundle), k)]


def retrieval_recall(expected: list[str], got: list[Chunk]) -> float | None:
    if not expected:
        return None
    keys = {c.key for c in got}
    return sum(e in keys for e in expected) / len(expected)


def _eval(k: int) -> None:
    from .ingest import ingest_folder
    from .samples import DATA_DIR, list_incidents, load_ground_truth

    chunks = load_chunks()
    print(f"{len(chunks)} knowledge-base sections; top-{k} retrieval")
    print(f"{'incident':<14} {'recall':>7}  missed / retrieved")
    total = []
    for inc in list_incidents():
        gt = load_ground_truth(inc)
        got = retrieve(ingest_folder(DATA_DIR / inc), chunks, k)
        r = retrieval_recall(gt.expected_kb_sections, got)
        if r is None:
            continue
        total.append(r)
        missed = [e for e in gt.expected_kb_sections if e not in {c.key for c in got}]
        print(f"{inc:<14} {r:>7.0%}  missed={missed or '-'}  got={[c.key for c in got]}")
    if total:
        print(f"{'MEAN':<14} {sum(total) / len(total):>7.0%}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--eval", action="store_true")
    ap.add_argument("--query")
    ap.add_argument("-k", type=int, default=DEFAULT_K)
    a = ap.parse_args()
    if a.query:
        for c, s in BM25(load_chunks()).search(a.query, a.k):
            print(f"{s:6.2f}  {c.label}")
    else:
        _eval(a.k)
