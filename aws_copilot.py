#!/usr/bin/env python3
"""aws_copilot.py — Slice 2 · grounded RAG copilot over OverWatch's OWN scan output.

Answers questions using ONLY the scan's finding_catalog + attack paths + choke points
(the "remediation" is the per-finding steps + the choke-point hints). Pure, boto3-free,
and OFFLINE-first: the default answer mode is EXTRACTIVE — it composes the reply purely
from retrieved corpus fields, so it cannot hallucinate facts that are not in the scan.
An optional LLM is an INJECTED seam (``llm(system, question, context) -> str``): the
context handed to it is strictly the retrieved corpus and the system prompt forbids
outside knowledge, so grounding holds either way. If nothing relevant is retrieved the
copilot ABSTAINS rather than inventing an answer.

Retrieval is a self-contained BM25 (no embeddings, no network), deterministic and testable.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from typing import Callable, Dict, List, Optional, Tuple

_STOP = frozenset((
    "a an the of to in on is are be for and or with how do i my me you your our we "
    "what which who where when why show list give tell all any can could should that "
    "this it its into about most more please help find get see"
).split())

_SEV_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1, "": 0}

# On-topic / structural query vocabulary. A question whose content words are ALL in here
# (or appear in the scan corpus) is treated as about-the-scan; a content word outside this
# set AND absent from the corpus is a "foreign topic" signal that forces an ABSTAIN — so
# "reach the airport" / "top tourist attractions in Paris" do not return scan data.
_QUERY_ALLOW = frozenset((
    "top biggest worst most critical severe important high highest low priority prioritize "
    "riskiest overview summarise prioritise prioritisation "
    "riskiest risk risks issue issues problem problems finding findings vuln vulnerability "
    "vulnerabilities cve cves attack attacks path paths breach breached compromise compromised "
    "reach reachable exposure exposed public internet choke chokepoint fix fixes fixed remediate "
    "remediation resolve mitigate close first start begin next single change sever severed "
    "security secure posture account accounts scan resource resources data secret secrets "
    "credential credentials role roles permission permissions least privilege overprivileged "
    "encryption encrypted mfa summarize summary explain why fewest step steps blast radius "
    "crown jewel jewels bucket buckets s3 iam ec2 rds admin recommend recommendation").split())

COPILOT_SYSTEM_PROMPT = (
    "You are OverWatch's security copilot. Answer the user's question using ONLY the "
    "CONTEXT below, which is drawn from this AWS account's own scan results (findings, "
    "attack paths, choke points). Cite the check IDs / path IDs you use. If the answer "
    "is not in the CONTEXT, say you don't have that in the scan — never invent findings, "
    "resources, CVEs, or remediation."
)


def _tok(text: Optional[str]) -> List[str]:
    toks = re.findall(r"[a-z0-9][a-z0-9._:/-]*", (text or "").lower())
    return [t for t in toks if len(t) > 1 and t not in _STOP]


def _first_sentence(s: str) -> str:
    s = (s or "").strip()
    m = re.search(r"(.+?[.!?])(\s|$)", s)
    return (m.group(1) if m else s).strip()


# ─── corpus ──────────────────────────────────────────────────────────────────
def build_corpus(findings: Optional[List[dict]] = None,
                 paths: Optional[List[dict]] = None,
                 chokes: Optional[List[dict]] = None) -> List[dict]:
    """Turn the scan's finding_catalog + attack_paths + choke_points into retrievable
    documents ``{id, kind, title, text, meta}``. ``id`` is the natural id (check_id /
    ``path:<n>`` / choke node_id); ``text`` is what BM25 indexes; ``meta`` carries the
    structured fields the extractive synthesizer renders."""
    docs: List[dict] = []
    seen: set = set()               # dedup by id (an org merge repeats a check_id across accounts)

    def _add(doc):
        if doc["id"] not in seen:
            seen.add(doc["id"])
            docs.append(doc)

    # which findings drive an attack path (so 'top risk' can prioritize them). Drivers may
    # carry a ':CVE-…' suffix; index by the base check_id so they line up with finding ids.
    on_path = set()
    for p in paths or []:
        for cid in p.get("driving_findings", []) or []:
            on_path.add((cid or "").split(":")[0])

    for f in findings or []:
        cid = f.get("check_id", "")
        if not cid:
            continue
        frameworks = " ".join((f.get("compliance") or {}).keys())
        affected = " ".join(str(a) for a in (f.get("affected") or [])[:8])
        text = " ".join([cid, f.get("section", ""), f.get("severity", ""), f.get("status", ""),
                         f.get("risk", ""), f.get("impact", ""),
                         " ".join(f.get("steps", []) or []), affected, frameworks])
        _add({"id": cid, "kind": "finding",
                     "title": f"{cid} · {f.get('section','')} · {f.get('severity','')}",
                     "text": text,
                     "meta": {"severity": f.get("severity", ""), "status": f.get("status", ""),
                              "on_path": cid in on_path, "risk": f.get("risk", ""),
                              "impact": f.get("impact", ""), "steps": f.get("steps", []) or [],
                              "remediation_cmd": f.get("remediation_cmd", ""),
                              "affected": f.get("affected", []) or [], "count": f.get("count", 0),
                              "distinct": f.get("distinct", 0),
                              "compliance": f.get("compliance", {}) or {}}})

    for i, p in enumerate(paths or []):
        drv = p.get("driving_findings", []) or []
        # NOTE: no static boilerplate is indexed — only real scan content — so a generic
        # English word (reach/exposure/point/sever) can never produce a spurious retrieval
        # match that defeats the off-topic abstain guard.
        text = " ".join([p.get("rationale", ""), p.get("severity", ""),
                         p.get("terminal_kind", ""), p.get("entry", ""), p.get("terminal", ""),
                         " ".join(drv)])
        _add({"id": f"path:{i}", "kind": "path",
                     "title": f"{p.get('severity','')} attack path → {p.get('terminal_kind','')}",
                     "text": text,
                     "meta": {"severity": p.get("severity", ""), "score": p.get("score", 0),
                              "rationale": p.get("rationale", ""), "driving_findings": drv,
                              "entry": p.get("entry", ""), "terminal": p.get("terminal", ""),
                              "kev": p.get("kev", False), "active_threat": p.get("active_threat", False)}})

    for c in chokes or []:
        nid = c.get("node_id", "")
        if not nid:
            continue
        text = " ".join([c.get("label", ""), c.get("remediation_hint", ""),
                         str(c.get("node_kind", ""))])
        _add({"id": nid, "kind": "choke",
                     "title": f"choke point · {c.get('label', nid)}",
                     "text": text,
                     "meta": {"label": c.get("label", nid),
                              "remediation_hint": c.get("remediation_hint", ""),
                              "paths_severed": c.get("paths_severed", 0),
                              "total_paths": c.get("total_paths", 0),
                              "is_true_choke": c.get("is_true_choke", False)}})
    return docs


# ─── retrieval (BM25, pure) ──────────────────────────────────────────────────
class Retriever:
    def __init__(self, docs: List[dict]):
        self.docs = docs
        self._toks = [_tok(d.get("text")) for d in docs]
        lens = [len(t) for t in self._toks]
        self._len = lens
        self._avg = (sum(lens) / len(lens)) if lens else 0.0
        self._tf = [Counter(t) for t in self._toks]
        self._df: Counter = Counter()
        for t in self._toks:
            for w in set(t):
                self._df[w] += 1
        self.N = len(docs)

    def search(self, query: str, k: int = 5, k1: float = 1.5, b: float = 0.75
               ) -> List[Tuple[dict, float]]:
        q = _tok(query)
        out: List[Tuple[dict, float]] = []
        for i, d in enumerate(self.docs):
            s = 0.0
            for w in q:
                df = self._df.get(w, 0)
                tf = self._tf[i].get(w, 0)
                if not df or not tf:
                    continue
                idf = math.log(1 + (self.N - df + 0.5) / (df + 0.5))
                denom = tf + k1 * (1 - b + b * (self._len[i] / (self._avg or 1.0)))
                s += idf * (tf * (k1 + 1)) / denom
            if s > 0:
                out.append((d, round(s, 4)))
        out.sort(key=lambda x: (-x[1], x[0]["id"]))
        return out[:k]


# ─── intent detection ────────────────────────────────────────────────────────
_RE_TOP = re.compile(r"\b(top|biggest|worst|most (critical|severe|important)|priorit|riski|"
                     r"critical (findings|risks|issues))\b")
_RE_PATH = re.compile(r"\b(attack path|attack-path|breach|how (could|would|can).*(compromis|"
                      r"breach|reach)|paths?\b|kill chain)\b")
_RE_CHOKE = re.compile(r"\b(fix first|where.*(start|begin)|choke|single (fix|change)|"
                       r"biggest bang|most impact.*fix)\b")
_RE_FIX = re.compile(r"\b(how (do|to|can i).*(fix|remediat|resolv|close)|remediat|fix (the |this )?|"
                     r"how.*mitigat)\b")
# summary / prioritization questions map to the top-risks answer (still foreign-word gated).
# No trailing \b so prefixes match (prioriti->prioritize, summ->summarize).
_RE_SUMMARY = re.compile(r"\b(summ|overview|posture|prioriti|what matters|focus on|where.*focus)")


def detect_intent(question: str) -> str:
    q = (question or "").lower()
    if _RE_CHOKE.search(q):
        return "choke"
    if _RE_TOP.search(q) or _RE_SUMMARY.search(q):
        return "top_risks"
    if _RE_PATH.search(q):
        return "paths"
    if _RE_FIX.search(q):
        return "fix"
    return "general"


# ─── extractive synthesis (offline, grounded, deterministic) ─────────────────
def _rank_findings(docs: List[dict]) -> List[dict]:
    fs = [d for d in docs if d["kind"] == "finding"
          and d["meta"]["status"] in ("FAIL", "WARN")]
    return sorted(fs, key=lambda d: (-_SEV_RANK.get(d["meta"]["severity"], 0),
                                     not d["meta"]["on_path"], -int(d["meta"]["count"] or 0),
                                     d["id"]))


def _fmt_finding(d: dict, with_steps: bool = False) -> str:
    m = d["meta"]
    tag = " [on an attack path]" if m.get("on_path") else ""
    line = f"- **{d['id']}** ({m['severity']}){tag}: {_first_sentence(m['risk']) or d['title']}"
    if with_steps and m.get("steps"):
        line += "\n  Fix: " + m["steps"][0]
    return line


def _answer_top_risks(docs: List[dict], k: int) -> Optional[dict]:
    ranked = _rank_findings(docs)[:k]
    if not ranked:
        return None
    body = "\n".join(_fmt_finding(d, with_steps=True) for d in ranked)
    return {"answer": f"Top {len(ranked)} risk(s) in this scan (severity, attack-path first):\n{body}",
            "citations": [d["id"] for d in ranked]}


def _answer_paths(docs: List[dict], k: int) -> Optional[dict]:
    finding_ids = {d["id"] for d in docs if d["kind"] == "finding"}
    ps = sorted((d for d in docs if d["kind"] == "path"),
                key=lambda d: (-int(d["meta"]["score"] or 0), d["id"]))[:k]
    if not ps:
        return {"answer": "No ranked attack paths were found in this scan (nothing chained "
                          "internet → workload → privilege → crown-jewel).", "citations": []}
    lines = []
    cites = [d["id"] for d in ps]
    for d in ps:
        m = d["meta"]
        flags = "".join([" [KEV]" if m.get("kev") else "",
                         " [active threat]" if m.get("active_threat") else ""])
        drv = (" Driving findings: " + ", ".join(m["driving_findings"])) if m.get("driving_findings") else ""
        lines.append(f"- **{m['severity']}** (score {m['score']}){flags}: {m['rationale']}.{drv}")
        # cite a driver only by its BASE check-id and only when it resolves to a corpus finding
        # (drivers carry a ':CVE-…' suffix / may reference a check absent from the deduped catalog)
        for c in m.get("driving_findings", []):
            base = (c or "").split(":")[0]
            if base in finding_ids and base not in cites:
                cites.append(base)
    return {"answer": "Ranked attack path(s):\n" + "\n".join(lines), "citations": cites}


def _answer_choke(docs: List[dict], k: int) -> Optional[dict]:
    cs = sorted((d for d in docs if d["kind"] == "choke"),
                key=lambda d: (not d["meta"]["is_true_choke"],
                               -int(d["meta"]["paths_severed"] or 0), d["id"]))[:k]
    if not cs:
        return {"answer": "No choke points were computed for this scan (no attack paths to "
                          "sever). Fix the highest-severity findings first.", "citations": []}
    lines = []
    for d in cs:
        m = d["meta"]
        true_tag = " (true choke — severs ALL paths to its targets)" if m.get("is_true_choke") else ""
        lines.append(f"- Fix **{m['label']}** (`{d['id']}`){true_tag}: severs "
                     f"{m['paths_severed']} of {m['total_paths']} path(s). {m['remediation_hint']}")
    return {"answer": "Fix these choke points first (most paths severed per fix):\n" + "\n".join(lines),
            "citations": [d["id"] for d in cs]}


def _answer_fix(question: str, docs: List[dict], retrieved: List[Tuple[dict, float]]) -> Optional[dict]:
    # prefer an explicit check-id mentioned in the question, else the top retrieved finding
    q = (question or "").upper()
    target = None
    for d in docs:
        if d["kind"] == "finding" and d["id"].upper() in q:
            target = d
            break
    if target is None:
        target = next((d for d, _ in retrieved if d["kind"] == "finding"), None)
    if target is None:
        return None
    m = target["meta"]
    steps = m.get("steps") or ([m["remediation_cmd"]] if m.get("remediation_cmd") else [])
    if not steps:
        return None
    numbered = "\n".join(f"  {i}. {s}" for i, s in enumerate(steps, 1))
    aff = m.get("affected") or []
    aff_line = f"\nAffected: {', '.join(str(a) for a in aff[:5])}" + (" …" if len(aff) > 5 else "") if aff else ""
    return {"answer": f"To remediate **{target['id']}** ({m['severity']}): {_first_sentence(m['risk'])}"
                      f"{aff_line}\nSteps:\n{numbered}",
            "citations": [target["id"]]}


def _answer_general(retrieved: List[Tuple[dict, float]], k: int) -> Optional[dict]:
    top = [d for d, _ in retrieved][:k]
    if not top:
        return None
    lines = []
    for d in top:
        if d["kind"] == "finding":
            lines.append(_fmt_finding(d, with_steps=True))
        elif d["kind"] == "path":
            lines.append(f"- **{d['meta']['severity']}** attack path: {d['meta']['rationale']}")
        else:
            lines.append(f"- Choke point **{d['meta']['label']}** (`{d['id']}`): "
                         f"{d['meta']['remediation_hint']}")
    return {"answer": "From this scan:\n" + "\n".join(lines), "citations": [d["id"] for d in top]}


def _context_block(docs: List[dict]) -> str:
    """The grounded CONTEXT handed to an injected LLM — the selected corpus docs only."""
    return "\n\n".join(f"[{d['id']}] ({d['kind']}) {d['title']}\n{d['text']}" for d in docs)


def _select_docs(intent: str, corpus: List[dict], retrieved: List[Tuple[dict, float]],
                 k: int) -> List[dict]:
    """The docs relevant to a DIRECTED intent (top-risks/paths/choke) — the same selection the
    extractive answerers use — so an injected LLM is grounded even when the question shares no
    literal term with the docs (e.g. 'top risks' vs a finding's text). Else the BM25 hits."""
    if intent == "top_risks":
        return _rank_findings(corpus)[:k]
    if intent == "paths":
        return sorted((d for d in corpus if d["kind"] == "path"),
                      key=lambda d: (-int(d["meta"]["score"] or 0), d["id"]))[:k]
    if intent == "choke":
        return sorted((d for d in corpus if d["kind"] == "choke"),
                      key=lambda d: (not d["meta"]["is_true_choke"],
                                     -int(d["meta"]["paths_severed"] or 0), d["id"]))[:k]
    return [d for d, _ in retrieved][:k]


# ─── the entry point ─────────────────────────────────────────────────────────
def answer(question: str, corpus: List[dict], *, llm: Optional[Callable] = None,
           top_k: int = 5, min_score: float = 0.0) -> dict:
    """Answer ``question`` grounded strictly in ``corpus``. Returns
    ``{answer, citations, retrieved, abstained, mode, intent}``. With ``llm`` (an injected
    ``(system, question, context) -> str``) the reply is generated from the retrieved
    context; without it the reply is composed extractively from the corpus (offline, no
    hallucination). Abstains when there is no intent match and nothing relevant is retrieved."""
    corpus = corpus or []
    retr = Retriever(corpus)
    retrieved = retr.search(question, k=max(top_k, 5))
    intent = detect_intent(question)
    best = retrieved[0][1] if retrieved else 0.0

    # ABSTAIN (all intents): a "foreign" content word — one that is neither on-topic query
    # vocabulary nor present in the scan corpus — means the question is not about this scan, so
    # a directed intent-trigger word (top/fix/…) alone can't force a scan answer for an off-topic
    # question. Plus a general question that matched nothing in the scan also abstains.
    vocab = set(retr._df)
    foreign = [t for t in _tok(question) if t not in _QUERY_ALLOW and t not in vocab]
    if foreign or (intent == "general" and best <= min_score):
        return {"answer": "I don't have anything about that in this scan. Ask about the "
                          "findings, attack paths, choke points, or how to remediate a "
                          "specific check (e.g. \"how do I fix S3-01?\").",
                "citations": [], "retrieved": [{"id": d["id"], "score": s} for d, s in retrieved],
                "abstained": True, "mode": "extractive", "intent": intent}

    if llm is not None:
        # ground the LLM on the intent-relevant docs (a directed query has no lexical BM25
        # overlap with finding text) unioned with the BM25 hits — never an empty context.
        ctx_docs = _select_docs(intent, corpus, retrieved, top_k)
        seen_ids = {d["id"] for d in ctx_docs}
        ctx_docs += [d for d, _ in retrieved if d["id"] not in seen_ids]
        ctx = _context_block(ctx_docs) or "(no relevant scan data retrieved)"
        try:
            text = llm(COPILOT_SYSTEM_PROMPT, question, ctx)
        except Exception:
            text = None
        if text:
            return {"answer": text, "citations": [d["id"] for d in ctx_docs],
                    "retrieved": [{"id": d["id"], "score": s} for d, s in retrieved],
                    "abstained": False, "mode": "llm", "intent": intent}
        # llm failed -> fall through to the grounded extractive answer (never fail the query)

    res = None
    if intent == "top_risks":
        res = _answer_top_risks(corpus, top_k)
    elif intent == "paths":
        res = _answer_paths(corpus, top_k)
    elif intent == "choke":
        res = _answer_choke(corpus, top_k)
    elif intent == "fix":
        res = _answer_fix(question, corpus, retrieved)
    if res is None:
        res = _answer_general(retrieved, top_k)
    if res is None:
        return {"answer": "This scan produced no findings, paths, or choke points to answer from.",
                "citations": [], "retrieved": [], "abstained": True, "mode": "extractive",
                "intent": intent}
    res.update({"retrieved": [{"id": d["id"], "score": s} for d, s in retrieved],
                "abstained": False, "mode": "extractive", "intent": intent})
    return res
