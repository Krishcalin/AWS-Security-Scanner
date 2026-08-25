#!/usr/bin/env python3
"""aws_vectorstore.py — Phase 4 · slice 4.2: the RAG vector store, from configuration.

A retrieval-augmented agent answers from what its vector store holds. That store is
therefore the agent's memory of the organization's documents, and everything OverWatch
says elsewhere about prompt injection assumes it: `TFLOW-01` treats a writable knowledge
-base source as a **proven** injection entry precisely because whoever writes the corpus
writes what the model will later say.

This slice asks the questions one layer down — who can reach the store, and who holds
its key.

THE DATA PLANE IS DECLINED, AND THAT IS A DECISION RATHER THAN AN OMISSION
--------------------------------------------------------------------------
``s3vectors`` exposes ``ListVectors`` and ``GetVectors``; ``aoss`` exposes an index API.
Those return the **embeddings themselves** — vectors computed from the customer's
documents, and partially invertible back toward them. Reading them is the escalation
**D2** declined for prompt text, and the argument is the same one: a security product
that ingests the corpus it is auditing has become a second copy of the thing at risk.

So this module reads **configuration only**, and every finding it raises says so. That
is not a gap being papered over; it is the same reasoning that made `MCP-04` state its
blind spot out loud rather than let silence read as "checked and clean".

WHAT THE NETWORK POLICY ACTUALLY MEANS, READ RATHER THAN ASSUMED
----------------------------------------------------------------
Three readings come straight from the OpenSearch Serverless reference and each one
would be wrong if guessed:

* **Public wins.** "If you set ``AllowFromPublic`` to true but also provide one or more
  ``SourceVPCEs`` or ``SourceServices``, OpenSearch Serverless ignores the VPC endpoints."
  And across policies: "a rule that specifies public access overrides a rule that
  specifies private access for any collections that are common to both rules." So the
  verdict is a UNION over every matching rule, not a per-policy answer.
* **`collection` and `dashboard` are different doors to the same room.** A collection
  whose API endpoint is private but whose Dashboards endpoint is public is still
  reachable: "a user can access the collection data only through Dashboards". Reporting
  only the API endpoint would miss half the exposure.
* **`SourceServices: ["bedrock.amazonaws.com"]` is the CORRECT architecture**, not a
  finding. It is how a Bedrock knowledge base reaches its collection privately, and a
  scanner that flags it teaches operators to ignore this category.

AND NETWORK ACCESS IS NOT DATA ACCESS
--------------------------------------
The reference is explicit: "Even with public network access enabled, data access
policies still control who can read and write data to the collection. Network access
only determines which networks can reach the collection endpoint." So a public network
policy makes the store *reachable*, not *readable*, and this module keeps those apart —
`VEC-01` reports reach, `VEC-02` reports read, and only `VEC-03` claims both, gated on
each being separately established. That is the same construction `ATT&CK-02` uses to
avoid asserting a terminal it did not prove.

Pure functions over dicts. No boto3, no network, no I/O.
"""
from __future__ import annotations

import json
from fnmatch import fnmatchcase
from typing import Dict, List, Optional, Sequence, Tuple

__all__ = [
    "VECTOR_COLLECTION_TYPE", "RESOURCE_COLLECTION", "RESOURCE_DASHBOARD",
    "PRIVATE_SERVICE_PRINCIPALS", "CMK_SSE_TYPE",
    "parse_policy", "network_exposure", "access_policy_breadth",
    "collection_key_custody", "vector_bucket_encryption", "bucket_policy_exposure",
    "describe_exposure", "CONTENTS_NOT_READ",
]

#: The collection type a RAG store uses. SEARCH and TIMESERIES collections are out of
#: scope for this slice — they are not the agent's memory, and widening the net would
#: put AI findings on every log-analytics collection in the account.
VECTOR_COLLECTION_TYPE = "VECTORSEARCH"

RESOURCE_COLLECTION = "collection"     # the OpenSearch API endpoint
RESOURCE_DASHBOARD = "dashboard"       # the Dashboards UI over the same data

#: Service principals AWS documents for private access. Reaching a collection this way
#: is the intended RAG architecture, and is never a finding.
PRIVATE_SERVICE_PRINCIPALS: Tuple[str, ...] = ("bedrock.amazonaws.com",)

#: s3vectors SseType. AES256 is SSE-S3 (AWS-owned); "aws:kms" with a kmsKeyArn is the
#: customer-managed case. Values read off the service model, not recalled.
CMK_SSE_TYPE = "aws:kms"

#: The sentence every finding in this slice carries. Without it, a reader who sees a
#: vector-store finding with no mention of contents assumes the contents were examined
#: and were clean -- a phantom pass produced by omission.
CONTENTS_NOT_READ = (
    "this check reads configuration only and does NOT read the stored vectors: whether "
    "the embeddings encode sensitive material is not a question this scan asks"
)

#: Principal values that mean "anyone".
_WILDCARDS = ("*", "arn:aws:iam::*:root")


def parse_policy(policy) -> list:
    """An aoss policy document, whether it arrives parsed or as a JSON string.

    ``GetSecurityPolicy`` documents the field as a JSON STRING in its own example
    response, while the service model types it as a Document. Both shapes are handled
    because guessing wrong yields an empty rule list, and an empty rule list reads as
    "no public access found" — a clean answer produced by a parse failure."""
    if isinstance(policy, str):
        try:
            policy = json.loads(policy)
        except ValueError:
            return []
    if isinstance(policy, dict):
        return [policy]
    return [p for p in policy] if isinstance(policy, list) else []


def _matches(patterns, name: str) -> bool:
    """Does any ``collection/<name|pattern>`` entry match this collection?"""
    for p in (patterns or []):
        if not isinstance(p, str):
            continue
        _, _, pat = p.partition("/")
        if pat and fnmatchcase(name, pat):
            return True
    return False


def network_exposure(name: str, policies: Optional[Sequence]) -> dict:
    """Whether this collection's endpoints are reachable from the public internet.

    A UNION across every rule of every matching policy, because the reference says a
    public rule overrides a private one wherever both apply. Evaluating policies
    independently and taking the last answer would report a collection as private on
    the strength of a rule that a later one overrides."""
    public_collection = public_dashboard = False
    vpce, services, matched = set(), set(), []
    for detail in (policies or []):
        if not isinstance(detail, dict):
            continue
        pname = detail.get("name") or ""
        for doc in parse_policy(detail.get("policy")):
            if not isinstance(doc, dict):
                continue
            hit_types = {r.get("ResourceType") for r in (doc.get("Rules") or [])
                         if isinstance(r, dict)
                         and _matches(r.get("Resource"), name)}
            if not hit_types:
                continue
            matched.append(pname)
            allow_public = doc.get("AllowFromPublic") is True
            if allow_public:
                public_collection |= RESOURCE_COLLECTION in hit_types
                public_dashboard |= RESOURCE_DASHBOARD in hit_types
            else:
                # Only meaningful when NOT public: the reference says a public rule
                # makes the service ignore both of these entirely.
                vpce.update(v for v in (doc.get("SourceVPCEs") or [])
                            if isinstance(v, str))
                services.update(s for s in (doc.get("SourceServices") or [])
                                if isinstance(s, str))
    return {
        "matched_policies": sorted(set(matched)),
        "governed": bool(matched),
        "public_collection": public_collection,
        "public_dashboard": public_dashboard,
        "public": public_collection or public_dashboard,
        "vpc_endpoints": sorted(vpce),
        "private_services": sorted(services),
        "bedrock_private": any(s in PRIVATE_SERVICE_PRINCIPALS for s in services),
    }


def access_policy_breadth(name: str, policies: Optional[Sequence]) -> dict:
    """Which principals a data access policy grants on this collection.

    Reports a wildcard principal as broad and everything else as scoped. It deliberately
    does NOT try to rank named principals against each other: whether a given role should
    hold read on the corpus is a question about that organization, and a scanner
    guessing at it produces findings nobody can act on."""
    broad, principals, matched = False, set(), []
    for detail in (policies or []):
        if not isinstance(detail, dict):
            continue
        for doc in parse_policy(detail.get("policy")):
            if not isinstance(doc, dict):
                continue
            if not any(_matches(r.get("Resource"), name)
                       for r in (doc.get("Rules") or []) if isinstance(r, dict)):
                continue
            matched.append(detail.get("name") or "")
            for p in (doc.get("Principal") or []):
                if isinstance(p, str):
                    principals.add(p)
                    if p.strip() in _WILDCARDS:
                        broad = True
    return {"governed": bool(matched), "broad": broad,
            "principals": sorted(principals),
            "matched_policies": sorted(set(matched))}


def collection_key_custody(detail: Optional[dict]) -> dict:
    """Whether a collection is on a key the customer can revoke.

    AWS always encrypts a collection; an AWS-owned key means the operator has no lever
    to pull. Same custody question `AGC-07` raises for the token vault and `AMEM-02` for
    agent memory — and it lands here because the corpus IS the organization's documents."""
    d = detail if isinstance(detail, dict) else {}
    arn = d.get("kmsKeyArn")
    owned = isinstance(arn, str) and arn.strip().lower() == "auto"
    return {"key_arn": arn if isinstance(arn, str) else "",
            "cmk": bool(arn) and not owned,
            "is_vector": (d.get("type") or "") == VECTOR_COLLECTION_TYPE,
            "name": d.get("name") or d.get("id") or ""}


def vector_bucket_encryption(bucket: Optional[dict]) -> dict:
    """s3vectors bucket key custody. ``AES256`` is SSE-S3; ``aws:kms`` may still be an
    AWS-managed key, so the ARN is what decides customer custody."""
    b = bucket if isinstance(bucket, dict) else {}
    enc = b.get("encryptionConfiguration")
    enc = enc if isinstance(enc, dict) else {}
    sse, arn = enc.get("sseType"), enc.get("kmsKeyArn")
    return {"sse_type": sse or "",
            "key_arn": arn if isinstance(arn, str) else "",
            "cmk": sse == CMK_SSE_TYPE and bool(arn),
            "name": b.get("vectorBucketName") or ""}


def bucket_policy_exposure(policy, own_account: str = "") -> dict:
    """Public or cross-account grants on an s3vectors bucket policy.

    The same classification S3-09 applies to a bucket policy, applied to the store that
    holds a RAG corpus. Kept here rather than reusing the S3 path because the resource
    shape differs and a wrong reading would be a claim about the wrong bucket."""
    docs = parse_policy(policy)
    public, cross, principals = False, set(), set()
    for doc in docs:
        for st in (doc.get("Statement") or []) if isinstance(doc, dict) else []:
            if not isinstance(st, dict) or st.get("Effect") != "Allow":
                continue
            pr = st.get("Principal")
            vals = []
            if isinstance(pr, str):
                vals = [pr]
            elif isinstance(pr, dict):
                for v in pr.values():
                    vals.extend(v if isinstance(v, list) else [v])
            for v in vals:
                if not isinstance(v, str):
                    continue
                principals.add(v)
                if v.strip() in _WILDCARDS:
                    public = True
                elif own_account and ":" in v and own_account not in v:
                    cross.add(v)
    return {"public": public, "cross_account": sorted(cross),
            "principals": sorted(principals), "has_policy": bool(docs)}


def describe_exposure(name: str, net: Optional[dict]) -> str:
    """One line naming which door is open, and refusing to overstate what that means."""
    n = net or {}
    doors = []
    if n.get("public_collection"):
        doors.append("its OpenSearch API endpoint")
    if n.get("public_dashboard"):
        doors.append("its Dashboards endpoint")
    if not doors:
        return ""
    return (f"Vector collection '{name}' is reachable from the public internet through "
            f"{' and '.join(doors)}. Network access decides who can REACH the "
            f"collection, not who can read it — the data access policy decides that, "
            f"which is why this is reported apart from VEC-02")
