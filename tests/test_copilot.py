"""Slice 2 · Batch 1 — pure grounded-RAG copilot (aws_copilot). No boto3, no network."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_copilot as C

F = [
    {"check_id": "S3-01", "section": "S3", "severity": "HIGH", "status": "FAIL",
     "compliance": {"CIS": "2.1.4"}, "distinct": 1, "affected": ["prod-bucket"], "count": 1,
     "risk": "The bucket allows public read access. Data can be exfiltrated by anyone.",
     "impact": "Full data exposure.",
     "steps": ["Enable account Block Public Access", "Remove the public ACL", "Re-scan"],
     "remediation_cmd": "aws s3api put-public-access-block ..."},
    {"check_id": "IAM-01", "section": "IAM", "severity": "CRITICAL", "status": "FAIL",
     "compliance": {}, "distinct": 1, "affected": ["root"], "count": 1,
     "risk": "Root account has no MFA. Full account takeover risk.",
     "impact": "Account takeover.",
     "steps": ["Enable a hardware MFA on the root user", "Rotate root credentials", "Re-scan"],
     "remediation_cmd": "aws iam ..."},
    {"check_id": "EC2-04", "section": "EC2", "severity": "LOW", "status": "WARN",
     "compliance": {}, "distinct": 1, "affected": ["i-1"], "count": 1,
     "risk": "IMDSv2 is not enforced.", "impact": "SSRF credential theft risk.",
     "steps": ["Require IMDSv2 on the instance", "Re-scan"], "remediation_cmd": "aws ec2 ..."},
]
P = [{"severity": "CRITICAL", "score": 92, "terminal_kind": "admin", "entry": "internet",
      "terminal": "cap:admin", "kev": True, "active_threat": False,
      "rationale": "Internet-exposed EC2 with a KEV CVE reaches an admin role",
      "driving_findings": ["EC2-04", "IAM-01"]}]
CH = [{"node_id": "role/app", "node_kind": "IAMRole", "label": "app-role",
       "remediation_hint": "Attach a permissions boundary to app-role",
       "paths_severed": 3, "total_paths": 4, "is_true_choke": True}]


def _corpus():
    return C.build_corpus(F, P, CH)


def test_build_corpus_shapes_and_on_path():
    docs = {d["id"]: d for d in _corpus()}
    assert docs["S3-01"]["kind"] == "finding" and docs["path:0"]["kind"] == "path"
    assert docs["role/app"]["kind"] == "choke"
    assert docs["IAM-01"]["meta"]["on_path"] is True         # drives the path
    assert docs["S3-01"]["meta"]["on_path"] is False


def test_retriever_ranks_relevant_first():
    r = C.Retriever(_corpus())
    top = r.search("public bucket read access exfiltrated", k=1)
    assert top and top[0][0]["id"] == "S3-01"
    assert C.Retriever(_corpus()).search("quantum blockchain weather") == []


def test_top_risks_intent_ranks_by_severity():
    a = C.answer("what are my top risks?", _corpus())
    assert a["intent"] == "top_risks" and a["citations"][0] == "IAM-01"   # CRITICAL first
    assert "IAM-01" in a["answer"] and not a["abstained"]


def test_fix_intent_returns_steps_for_named_check():
    a = C.answer("how do I fix S3-01?", _corpus())
    assert a["intent"] == "fix" and a["citations"] == ["S3-01"]
    assert "Block Public Access" in a["answer"]


def test_paths_intent():
    a = C.answer("show me the attack paths", _corpus())
    assert a["intent"] == "paths" and "admin role" in a["answer"]
    assert "path:0" in a["citations"] and "KEV" in a["answer"]


def test_choke_intent_fix_first():
    a = C.answer("what should I fix first?", _corpus())
    assert a["intent"] == "choke" and "app-role" in a["answer"]
    assert "severs 3 of 4" in a["answer"]


def test_general_retrieval():
    a = C.answer("tell me about the imdsv2 instance", _corpus())
    assert not a["abstained"] and "EC2-04" in a["citations"]


def test_abstains_on_off_topic():
    a = C.answer("what is the capital of France?", _corpus())
    assert a["abstained"] is True and a["citations"] == []


def test_grounding_citations_are_corpus_ids():
    ids = {d["id"] for d in _corpus()}
    a = C.answer("what are my top risks?", _corpus())
    assert all(c in ids for c in a["citations"])             # never a cite outside the scan


def test_llm_seam_receives_grounded_context():
    seen = {}

    def fake_llm(system, question, context):
        seen["system"], seen["context"] = system, context
        return "GROUNDED-ANSWER"
    a = C.answer("public bucket?", _corpus(), llm=fake_llm)
    assert a["mode"] == "llm" and a["answer"] == "GROUNDED-ANSWER"
    assert "ONLY the CONTEXT" in seen["system"]
    assert "S3-01" in seen["context"]                        # retrieved corpus is the context


def test_llm_failure_falls_back_to_extractive():
    def boom(system, question, context):
        raise RuntimeError("llm down")
    a = C.answer("how do I fix S3-01?", _corpus(), llm=boom)
    assert a["mode"] == "extractive" and "Block Public Access" in a["answer"]


def test_deterministic():
    assert C.answer("top risks", _corpus()) == C.answer("top risks", _corpus())


def test_empty_corpus_abstains():
    a = C.answer("anything?", [])
    assert a["abstained"] is True


# ── Slice 2 adversarial-verify regressions ───────────────────────────────────
def test_abstains_off_topic_with_boilerplate_words():
    # generic English words (reach/exposure/point/sever) must NOT surface scan data
    for q in ["How do I reach the airport downtown?",
              "Where can I get more exposure for my brand?",
              "What is the point of all this?",
              "How do I sever ties with a friend?"]:
        assert C.answer(q, _corpus())["abstained"] is True, q


def test_abstains_off_topic_with_intent_trigger_word():
    # an off-topic question that happens to contain a trigger word must still abstain
    for q in ["top tourist attractions in Paris?", "how do I fix dinner?",
              "where should I start my vacation?"]:
        assert C.answer(q, _corpus())["abstained"] is True, q


def test_paths_citations_only_resolvable_corpus_ids():
    corpus = C.build_corpus(
        findings=[{"check_id": "VULN-02", "section": "VULN", "severity": "HIGH", "status": "FAIL",
                   "risk": "Exploitable CVE on the host.", "steps": ["Patch"], "affected": ["i-1"]}],
        paths=[{"severity": "CRITICAL", "score": 90, "terminal_kind": "admin", "rationale": "reaches admin",
                "driving_findings": ["VULN-02:CVE-2021-44228"]}], chokes=[])
    ids = {d["id"] for d in corpus}
    a = C.answer("show attack paths", corpus)
    assert all(c in ids for c in a["citations"])            # suffixed 'VULN-02:CVE-…' never cited
    assert "VULN-02" in a["citations"]                       # cited by its base id


def test_org_merge_dedups_by_id():
    f = {"check_id": "S3-01", "section": "S3", "severity": "HIGH", "status": "FAIL",
         "risk": "public bucket", "steps": ["fix it"], "affected": ["b"]}
    corpus = C.build_corpus(findings=[f, dict(f)], paths=[], chokes=[])   # same check twice
    assert sum(1 for d in corpus if d["id"] == "S3-01") == 1


def test_llm_directed_intent_gets_nonempty_grounded_context():
    holder = {}

    def fake(system, question, ctx):
        holder["ctx"] = ctx
        return "X"
    C.answer("what are my top risks?", _corpus(), llm=fake)
    assert "IAM-01" in holder["ctx"]                          # directed intent is grounded, not empty
