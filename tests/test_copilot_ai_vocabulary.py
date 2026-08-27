"""Phase 0 · slice 0.5 — the copilot understands an AI question on any account.

The abstain rule accepts a content word present in EITHER `_QUERY_ALLOW` or the scan
corpus. Once quick win #2 filled `finding_detail` with real Bedrock and SageMaker
prose, most AI questions started answering — but only on an account that HAS AI
findings. On one that does not, the words existed nowhere and every AI question
abstained.

That made the copilot's grasp of a question depend on the account's contents. "Is my
SageMaker notebook exposed?" against a clean estate should be understood and answered
with what the scan actually found; an abstain says "I did not understand you", which is
a different claim entirely — and it is the same nothing-found/did-not-look confusion
the rest of Phase 0 was spent removing.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import aws_copilot

AI_QUESTIONS = [
    "which AI models are exposed?",
    "show me my bedrock guardrail coverage",
    "is my sagemaker notebook exposed?",
    "do I have prompt injection risk?",
    "what can my AI agent role reach?",
    "which llm endpoints lack logging?",
]

FOREIGN_QUESTIONS = [
    "top tourist attractions in Paris",
    "how do I reach the airport",
    "what is the weather tomorrow",
    "best pizza recipe",
]


def _finding(check_id, section, risk, **kw):
    base = {"check_id": check_id, "section": section, "severity": "HIGH",
            "status": "FAIL", "risk": risk, "impact": "Impact.",
            "steps": ["Do the thing."], "remediation_cmd": "aws iam get-role",
            "compliance": {}, "affected": ["r1"], "count": 1, "distinct": 1}
    base.update(kw)
    return base


@pytest.fixture()
def ai_corpus():
    from engine import aws_finding_detail
    findings = []
    for cid in ("BDR-01", "BDR-02", "AGT-02", "AISPM-01"):
        d = aws_finding_detail.FINDING_DETAIL[cid]
        findings.append(_finding(cid, "DATA", d["risk"], impact=d["impact"],
                                 steps=d["steps"]))
    return aws_copilot.build_corpus(findings=findings)


@pytest.fixture()
def no_ai_corpus():
    """An estate with no AI at all — the case that was broken."""
    return aws_copilot.build_corpus(findings=[
        _finding("S3-01", "S3", "A bucket is public.")])


# ── the vocabulary is in the allowlist, not borrowed from the corpus ────────
def test_ai_terms_are_recognised_without_the_corpus_supplying_them():
    missing = [w for w in ("ai", "model", "llm", "bedrock", "sagemaker", "guardrail",
                           "prompt", "injection", "agent", "notebook", "inference")
               if w not in aws_copilot._QUERY_ALLOW]
    assert not missing, (
        f"AI vocabulary absent from _QUERY_ALLOW: {missing}. Leaving these to the "
        f"corpus makes the copilot's comprehension depend on the account's contents.")


def test_structural_query_words_are_recognised():
    """'guardrail COVERAGE' and 'endpoints that LACK logging' failed on the query
    word, not the AI word."""
    for w in ("coverage", "lack", "missing", "without"):
        assert w in aws_copilot._QUERY_ALLOW, w


@pytest.mark.parametrize("question", AI_QUESTIONS)
def test_no_ai_question_is_treated_as_a_foreign_topic(question, no_ai_corpus):
    """The narrow, load-bearing assertion: an AI question must never be classed as
    off-topic, whatever the account happens to contain."""
    vocab = set(aws_copilot.Retriever(no_ai_corpus)._df)
    foreign = [t for t in aws_copilot._tok(question)
               if t not in aws_copilot._QUERY_ALLOW and t not in vocab]
    assert not foreign, f"{question!r} still reads as off-topic on: {foreign}"


@pytest.mark.parametrize("question", AI_QUESTIONS)
def test_every_ai_question_answers_on_an_account_that_has_ai_findings(question,
                                                                     ai_corpus):
    res = aws_copilot.answer(question, ai_corpus)
    assert not res.get("abstained"), f"{question!r} still abstains"


# ── the guard this must not break ───────────────────────────────────────────
@pytest.mark.parametrize("question", FOREIGN_QUESTIONS)
def test_genuinely_foreign_questions_still_abstain(question, ai_corpus):
    """_QUERY_ALLOW exists to stop 'top tourist attractions in Paris' returning scan
    data because it contains the intent word 'top'. Widening the vocabulary must not
    widen that hole."""
    res = aws_copilot.answer(question, ai_corpus)
    assert res.get("abstained"), f"{question!r} now returns scan data — guard broken"


def test_the_abstain_reply_never_invents_a_finding(no_ai_corpus):
    """Whatever it says, it must not claim something the scan does not contain."""
    res = aws_copilot.answer("is my sagemaker notebook exposed?", no_ai_corpus)
    text = (res.get("answer") or "").lower()
    for invented in ("sagemaker notebook is exposed", "aispm-01", "bdr-0"):
        assert invented not in text, f"the reply invented {invented!r}"
