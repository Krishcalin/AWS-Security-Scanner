"""Phase 4 · slice 4.2 — the RAG vector store, from configuration.

The store is the agent's memory of the organization's documents. `TFLOW-01` already
treats a writable knowledge-base source as a *proven* injection entry on exactly that
reasoning; this slice asks who can reach the store and who holds its key.

Most of these tests exist because the OpenSearch Serverless network model has three
readings that would each be wrong if guessed, and all three are load-bearing:

**Public wins, across policies.** A public rule overrides a private one wherever both
match, and `AllowFromPublic: true` makes the service ignore `SourceVPCEs` entirely.
Evaluating policies independently and keeping the last answer reports a public
collection as private.

**`collection` and `dashboard` are different doors to the same room.** A private API
endpoint with a public Dashboards endpoint is still reachable.

**`bedrock.amazonaws.com` in `SourceServices` is the correct architecture.** It is how a
knowledge base reaches its collection privately, and flagging it teaches operators to
ignore the category.

And the line the slice does not cross: `ListVectors`/`GetVectors` return embeddings of
the customer's documents. Reading them is the escalation D2 declined, so every finding
says configuration only was read.
"""
from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import aws_vectorstore as V


def netpol(name="np", public=False, resource_types=("collection",),
           targets=("collection/*",), vpce=(), services=(), as_string=True):
    doc = [{"Description": name,
            "Rules": [{"ResourceType": rt, "Resource": list(targets)}
                      for rt in resource_types],
            "AllowFromPublic": public}]
    if vpce:
        doc[0]["SourceVPCEs"] = list(vpce)
    if services:
        doc[0]["SourceServices"] = list(services)
    return {"name": name, "type": "network",
            "policy": json.dumps(doc) if as_string else doc}


def datapol(name="dp", principals=("arn:aws:iam::123456789012:role/App",),
            targets=("collection/rag-corpus",)):
    doc = [{"Rules": [{"ResourceType": "collection", "Resource": list(targets)}],
            "Principal": list(principals)}]
    return {"name": name, "type": "data", "policy": json.dumps(doc)}


# ── the policy document arrives in two shapes ───────────────────────────────
def test_a_policy_is_read_whether_it_is_a_string_or_parsed():
    """GetSecurityPolicy documents the field as a JSON string in its own example while
    the service model types it as a Document. Guessing wrong yields an empty rule list,
    which reads as 'no public access found' — a clean answer from a parse failure."""
    for as_string in (True, False):
        n = V.network_exposure("rag-corpus",
                               [netpol(public=True, as_string=as_string)])
        assert n["public_collection"] is True, as_string


def test_malformed_policy_text_does_not_read_as_private():
    """It reads as ungoverned, which the caller reports rather than passing."""
    n = V.network_exposure("rag-corpus", [{"name": "x", "policy": "{not json"}])
    assert n["governed"] is False and n["public"] is False


# ── public wins ─────────────────────────────────────────────────────────────
def test_public_overrides_private_across_policies():
    """The reference: a rule specifying public access overrides one specifying private
    access for collections common to both."""
    n = V.network_exposure("rag-corpus", [
        netpol("private", public=False, vpce=("vpce-1",)),
        netpol("public", public=True)])
    assert n["public_collection"] is True


def test_a_public_rule_makes_source_vpces_irrelevant():
    """'If you set AllowFromPublic to true but also provide one or more SourceVPCEs,
    OpenSearch Serverless ignores the VPC endpoints.'"""
    n = V.network_exposure("rag-corpus",
                           [netpol(public=True, vpce=("vpce-1",))])
    assert n["public_collection"] is True
    assert n["vpc_endpoints"] == []


def test_a_private_policy_records_its_vpc_endpoints():
    n = V.network_exposure("rag-corpus", [netpol(public=False, vpce=("vpce-1", "vpce-2"))])
    assert n["public"] is False
    assert n["vpc_endpoints"] == ["vpce-1", "vpce-2"]


# ── two doors ───────────────────────────────────────────────────────────────
def test_a_public_dashboard_is_exposure_even_with_a_private_api_endpoint():
    """'A user can access the collection data only through Dashboards' — still access."""
    n = V.network_exposure("rag-corpus",
                           [netpol(public=True, resource_types=("dashboard",))])
    assert n["public_dashboard"] is True
    assert n["public_collection"] is False
    assert n["public"] is True


def test_the_description_names_which_door_is_open():
    n = V.network_exposure("rag-corpus",
                           [netpol(public=True, resource_types=("dashboard",))])
    line = V.describe_exposure("rag-corpus", n)
    assert "Dashboards endpoint" in line and "OpenSearch API endpoint" not in line


def test_both_doors_are_named_when_both_are_open():
    n = V.network_exposure("rag-corpus",
                           [netpol(public=True, resource_types=("collection", "dashboard"))])
    line = V.describe_exposure("rag-corpus", n)
    assert "OpenSearch API endpoint" in line and "Dashboards endpoint" in line


def test_the_description_refuses_to_equate_reach_with_read():
    """'Even with public network access enabled, data access policies still control who
    can read and write data.' Saying otherwise would assert a terminal never proven."""
    n = V.network_exposure("rag-corpus", [netpol(public=True)])
    line = V.describe_exposure("rag-corpus", n)
    assert "not who can read it" in line


# ── bedrock private access is the correct architecture ──────────────────────
def test_bedrock_private_access_is_recognised_and_not_public():
    """This is how a knowledge base reaches its collection. A scanner that flags it
    teaches operators to ignore the category."""
    n = V.network_exposure("rag-corpus",
                           [netpol(public=False, services=("bedrock.amazonaws.com",))])
    assert n["public"] is False and n["bedrock_private"] is True


# ── resource pattern matching ───────────────────────────────────────────────
@pytest.mark.parametrize("pattern,name,hit", [
    ("collection/*", "rag-corpus", True),
    ("collection/rag*", "rag-corpus", True),
    ("collection/rag-corpus", "rag-corpus", True),
    ("collection/other", "rag-corpus", False),
    ("collection/logs*", "rag-corpus", False),
])
def test_resource_patterns_are_globs(pattern, name, hit):
    n = V.network_exposure(name, [netpol(public=True, targets=(pattern,))])
    assert n["public_collection"] is hit


def test_an_ungoverned_collection_is_reported_as_ungoverned():
    """No matching policy is not the same as a private one, and must not read as safe."""
    n = V.network_exposure("rag-corpus", [netpol(targets=("collection/other",))])
    assert n["governed"] is False


# ── data access ─────────────────────────────────────────────────────────────
def test_a_wildcard_principal_is_broad():
    a = V.access_policy_breadth("rag-corpus", [datapol(principals=("*",))])
    assert a["broad"] is True


def test_a_named_principal_is_not_ranked():
    """Whether a given role should hold read on the corpus is a question about that
    organization. A scanner guessing at it produces findings nobody can act on."""
    a = V.access_policy_breadth("rag-corpus", [datapol()])
    assert a["broad"] is False
    assert a["principals"] == ["arn:aws:iam::123456789012:role/App"]


def test_an_account_root_wildcard_is_broad():
    a = V.access_policy_breadth("rag-corpus",
                                [datapol(principals=("arn:aws:iam::*:root",))])
    assert a["broad"] is True


def test_a_data_policy_for_another_collection_does_not_apply():
    a = V.access_policy_breadth("rag-corpus",
                                [datapol(principals=("*",), targets=("collection/other",))])
    assert a["broad"] is False and a["governed"] is False


# ── key custody ─────────────────────────────────────────────────────────────
def test_a_vector_collection_is_told_apart_from_other_types():
    """SEARCH and TIMESERIES collections are not the agent's memory, and widening the
    net would put AI findings on every log-analytics collection in the account."""
    assert V.collection_key_custody({"type": "VECTORSEARCH"})["is_vector"] is True
    for t in ("SEARCH", "TIMESERIES", ""):
        assert V.collection_key_custody({"type": t})["is_vector"] is False


def test_an_aws_owned_key_is_not_customer_custody():
    assert V.collection_key_custody({"kmsKeyArn": "auto"})["cmk"] is False
    assert V.collection_key_custody({})["cmk"] is False


def test_a_customer_key_is_recognised():
    p = V.collection_key_custody({"kmsKeyArn": "arn:aws:kms:us-east-1:1:key/k"})
    assert p["cmk"] is True


# ── s3vectors ───────────────────────────────────────────────────────────────
def test_sse_s3_is_not_customer_custody():
    e = V.vector_bucket_encryption({"encryptionConfiguration": {"sseType": "AES256"}})
    assert e["cmk"] is False and e["sse_type"] == "AES256"


def test_kms_without_a_key_arn_is_not_customer_custody():
    """sseType aws:kms can still be an AWS-managed key; the ARN is what decides."""
    e = V.vector_bucket_encryption({"encryptionConfiguration": {"sseType": "aws:kms"}})
    assert e["cmk"] is False


def test_kms_with_a_key_arn_is_customer_custody():
    e = V.vector_bucket_encryption({"encryptionConfiguration": {
        "sseType": "aws:kms", "kmsKeyArn": "arn:aws:kms:us-east-1:1:key/k"}})
    assert e["cmk"] is True


def test_a_public_bucket_policy_is_reported():
    pol = json.dumps({"Statement": [{"Effect": "Allow", "Principal": "*",
                                     "Action": "s3vectors:GetVectors"}]})
    assert V.bucket_policy_exposure(pol)["public"] is True


def test_a_cross_account_principal_is_reported_apart_from_public():
    pol = json.dumps({"Statement": [{"Effect": "Allow",
                                     "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                                     "Action": "s3vectors:GetVectors"}]})
    e = V.bucket_policy_exposure(pol, own_account="123456789012")
    assert e["public"] is False
    assert e["cross_account"] == ["arn:aws:iam::999999999999:root"]


def test_an_own_account_principal_is_neither():
    pol = json.dumps({"Statement": [{"Effect": "Allow",
                                     "Principal": {"AWS": "arn:aws:iam::123456789012:role/App"},
                                     "Action": "s3vectors:GetVectors"}]})
    e = V.bucket_policy_exposure(pol, own_account="123456789012")
    assert e["public"] is False and e["cross_account"] == []


def test_a_deny_statement_is_not_an_exposure():
    pol = json.dumps({"Statement": [{"Effect": "Deny", "Principal": "*",
                                     "Action": "s3vectors:GetVectors"}]})
    assert V.bucket_policy_exposure(pol)["public"] is False


def test_no_policy_is_reported_as_no_policy():
    assert V.bucket_policy_exposure(None)["has_policy"] is False


# ── the line this slice does not cross ──────────────────────────────────────
def test_the_module_reads_no_vectors():
    """D2 in force. ListVectors/GetVectors return embeddings computed from the
    customer's documents, and a security product that ingests the corpus it audits has
    become a second copy of the thing at risk."""
    import ast
    import inspect

    # Docstrings and comments are STRIPPED before the check. The module names
    # GetVectors and ListVectors on purpose -- to say it does not call them -- and a
    # guard that fires on the sentence explaining the refusal would push the reasoning
    # out of the file to keep itself quiet. What is policed is executable code.
    tree = ast.parse(inspect.getsource(V))
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                             ast.AsyncFunctionDef)):
            body = node.body
            if (body and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)):
                body.pop(0)
    code = ast.unparse(tree).lower()
    # OPERATION names, not the word "embedding": the refusal constant necessarily says
    # "whether the embeddings encode sensitive material is not a question this scan
    # asks", and a guard that fires on that sentence is a guard against explaining
    # yourself. The data plane can only be reached by naming one of these.
    for banned in ("get_vectors", "list_vectors", "getvectors", "listvectors",
                   "queryvectors", "query_vectors"):
        assert banned not in code, f"{banned} appears in executable code"


def test_the_refusal_is_stated_for_the_reader_not_only_in_the_docstring():
    assert "does NOT read the stored vectors" in V.CONTENTS_NOT_READ
    assert "not a question this scan asks" in V.CONTENTS_NOT_READ


def test_the_module_makes_no_aws_calls():
    import inspect
    import re
    assert not re.findall(r"^\s*(?:import|from)\s+(boto3|botocore|requests)\b",
                          inspect.getsource(V), re.M)


@pytest.mark.parametrize("bad", [None, {}, "nope", 7, [], [None], [{"policy": 7}]])
def test_nothing_raises_on_malformed_input(bad):
    V.network_exposure("x", bad if isinstance(bad, list) else None)
    V.access_policy_breadth("x", bad if isinstance(bad, list) else None)
    V.collection_key_custody(bad if isinstance(bad, dict) else None)
    V.vector_bucket_encryption(bad if isinstance(bad, dict) else None)
    V.bucket_policy_exposure(bad)
    V.describe_exposure("x", bad if isinstance(bad, dict) else None)
