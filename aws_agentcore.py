"""Phase 2 · slice 2.2 — Amazon Bedrock AgentCore: inventory, and every agent identity.

AgentCore is a different service from Bedrock Agents, with its own control plane
(``bedrock-agentcore-control``, API version 2023-06-05) and its own IAM prefix
(``bedrock-agentcore``, NOT ``bedrock-agentcore-control``). An account can run an entire
agent estate here — runtimes, gateways, memory stores, browsers, code interpreters,
workload identities, stored third-party credentials — and none of it appears in a Bedrock
Agents inventory. You cannot secure what you cannot list, and today nothing lists this.

Everything below was read off the API reference and off the service model shipped in the
botocore version this project pins (1.40.51), not recalled. That distinction mattered
twice while writing it:

* The published API reference is AHEAD of our pinned SDK. It documents Harnesses,
  PaymentConnectors, PolicyEngines and Registries, none of which exist in 1.40.51. Code
  written from the reference alone would raise AttributeError against the SDK we ship.
  The operation set here comes from the pinned service model's own paginator file.

* The List result keys are NOT uniform. Gateways and gateway targets return ``items``;
  browsers return ``browserSummaries``; code interpreters return
  ``codeInterpreterSummaries``; memories return ``memories``. Guessing one wrong yields a
  silently empty inventory that looks like a clean account.

WHAT THIS MODULE DELIBERATELY DOES NOT CLAIM
--------------------------------------------
*That ``networkMode: PUBLIC`` means the runtime is reachable from the internet.* The
reference gives the enum as ``PUBLIC | VPC`` and says nothing about inbound reachability;
what is observable is that the runtime is not attached to a customer VPC, so its egress is
not mediated by customer VPC controls. Who may INVOKE a runtime is governed by
``authorizerConfiguration``, which is a different field answering a different question.
Reading a network mode as an ingress claim is exactly the error AIPATH-01 shipped for two
slices, and this module is written to not repeat it.

Pure functions over dicts — no boto3, no I/O. The scanner fetches; this decides.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Tuple

#: (operation, result_key, kind) for every AgentCore resource the PINNED SDK can list.
#: Taken from botocore 1.40.51's own paginators-1.json for
#: bedrock-agentcore-control/2023-06-05 — the result keys are not uniform and are not
#: guessable, so they are recorded here rather than derived from the operation name.
LIST_OPERATIONS: Tuple[Tuple[str, str, str], ...] = (
    ("list_agent_runtimes", "agentRuntimes", "AgentCoreRuntime"),
    ("list_gateways", "items", "AgentCoreGateway"),
    ("list_memories", "memories", "AgentCoreMemory"),
    ("list_browsers", "browserSummaries", "AgentCoreBrowser"),
    ("list_code_interpreters", "codeInterpreterSummaries", "AgentCoreCodeInterpreter"),
    ("list_workload_identities", "workloadIdentities", "AgentCoreWorkloadIdentity"),
    ("list_oauth2_credential_providers", "credentialProviders",
     "AgentCoreOauth2Provider"),
    ("list_api_key_credential_providers", "credentialProviders",
     "AgentCoreApiKeyProvider"),
)

#: The IAM action each list operation needs. Prefix is ``bedrock-agentcore``; the
#: ``-control`` suffix belongs to the endpoint, not to the authorization namespace.
IAM_PREFIX = "bedrock-agentcore"

NETWORK_MODES = ("PUBLIC", "VPC")
RUNTIME_STATUSES = ("CREATING", "CREATE_FAILED", "UPDATING", "UPDATE_FAILED",
                    "READY", "DELETING")

#: Credential providers hold the agent's keys to systems OUTSIDE AWS. They are the part
#: of an agent estate least visible to a cloud-native inventory and most valuable to an
#: attacker who lands inside one.
CREDENTIAL_KINDS = ("AgentCoreOauth2Provider", "AgentCoreApiKeyProvider")


# ── identity ────────────────────────────────────────────────────────────────
def runtime_identity(runtime: Optional[dict]) -> dict:
    """The two identities an AgentCore runtime carries.

    ``roleArn`` is the AWS identity — what the agent can do in the account, and therefore
    the blast radius of a successful injection. ``workloadIdentityArn`` is AgentCore's own
    identity for the workload, which is what the credential providers and the token vault
    bind to. A CNAPP that records only the first has half the picture: the second is how
    the agent reaches systems outside AWS entirely."""
    r = runtime or {}
    wid = (r.get("workloadIdentityDetails") or {}).get("workloadIdentityArn") or ""
    return {
        "role_arn": r.get("roleArn") or "",
        "workload_identity_arn": wid,
        "has_aws_identity": bool(r.get("roleArn")),
        "has_workload_identity": bool(wid),
    }


# ── the microVM metadata service ────────────────────────────────────────────
def metadata_posture(runtime: Optional[dict]) -> dict:
    """Whether the runtime's microVM metadata service requires v2.

    This is the EC2 IMDSv1/v2 story moved inside an agent. AgentCore Runtime executes in
    a microVM with a metadata service (MMDS); with v2 not required, a request the agent
    can be persuaded to make — and persuading an agent to make a request is the whole of
    prompt injection — can read the metadata endpoint and return the execution role's
    credentials in the response. v2's session-token handshake is what makes that fail.

    ``required`` is None when the field is absent rather than False, because absent and
    "explicitly not required" are different facts and the reference does not state a
    default. Reporting an unknown as a failure invents a finding."""
    cfg = (runtime or {}).get("metadataConfiguration")
    if not isinstance(cfg, dict) or "requireMMDSV2" not in cfg:
        return {"required": None, "known": False}
    val = cfg.get("requireMMDSV2")
    return {"required": bool(val) if isinstance(val, bool) else None,
            "known": isinstance(val, bool)}


# ── network ─────────────────────────────────────────────────────────────────
def network_posture(runtime: Optional[dict]) -> dict:
    """VPC attachment, described as what it is.

    ``mode`` is echoed verbatim rather than matched against the enum, so an unrecognised
    future value is reported instead of silently bucketed. ``vpc_attached`` is derived
    from observable subnets rather than from the mode string alone.

    Note the fields this deliberately does NOT produce: nothing named "exposed",
    "public" or "internet-facing". PUBLIC here means "not attached to your VPC", which
    constrains EGRESS mediation. Inbound invocation is authorizerConfiguration's job."""
    net = (runtime or {}).get("networkConfiguration") or {}
    mode = (net.get("networkMode") or "").upper()
    cfg = net.get("networkModeConfig") or {}
    subnets = [s for s in (cfg.get("subnets") or []) if s]
    sgs = [s for s in (cfg.get("securityGroups") or []) if s]
    return {
        "mode": mode,
        "known_mode": mode in NETWORK_MODES,
        "vpc_attached": bool(subnets),
        "subnets": subnets,
        "security_groups": sgs,
        # requireServiceS3Endpoint forces S3 traffic through a VPC endpoint rather than
        # the public path — a genuine egress control, and only meaningful in VPC mode.
        "s3_endpoint_required": bool(cfg.get("requireServiceS3Endpoint")),
        "egress_unmediated": mode == "PUBLIC" or not subnets,
    }


# ── authorization (inbound), reported without overclaiming ──────────────────
def authorizer_posture(runtime: Optional[dict]) -> dict:
    """Whether an inbound authorizer is configured on the runtime.

    ``authorizerConfiguration`` is a Union in the API, so its shape varies and this makes
    no attempt to grade the configured authorizer — only to record presence. Grading
    authorizers is slice 2.3's subject, on gateways, and doing half of it here would
    produce two checks disagreeing about the same idea."""
    cfg = (runtime or {}).get("authorizerConfiguration")
    present = isinstance(cfg, dict) and bool(cfg)
    return {"configured": present,
            "kinds": sorted(cfg.keys()) if present else []}


# ── environment variables ───────────────────────────────────────────────────
def env_secret_keys(runtime: Optional[dict]) -> List[str]:
    """Secret-SHAPED environment variable names on a runtime. Names only, never values.

    Reuses ``aws_secrets.env_secret_findings``, which returns the key and a kind and
    never the value — the same primitive the Lambda and ECS surfaces use. A runtime may
    carry up to 50 variables with values up to 5000 characters, which is ample room for a
    pasted key, and unlike Lambda nothing else in the market is looking here."""
    import aws_secrets
    env = (runtime or {}).get("environmentVariables") or {}
    if not isinstance(env, dict):
        return []
    pairs = [(k, v) for k, v in env.items()]
    return sorted({f["name"] for f in
                   aws_secrets.env_secret_findings(pairs, "agentcore-runtime")})


# ── estate ──────────────────────────────────────────────────────────────────
def inventory_counts(estate: Optional[Dict[str, list]]) -> dict:
    """Counts per resource kind, plus the two roll-ups worth stating on their own.

    ``credential_providers`` is called out because it answers a question a cloud-native
    inventory normally cannot: how many sets of credentials to systems OUTSIDE this
    account does the agent estate hold."""
    e = estate or {}
    counts = {kind: len(e.get(kind) or []) for _, _, kind in LIST_OPERATIONS}
    return {
        "counts": counts,
        "total": sum(counts.values()),
        "credential_providers": sum(counts.get(k, 0) for k in CREDENTIAL_KINDS),
        "kinds_present": sorted(k for k, n in counts.items() if n),
    }


def summarize(estate: Optional[Dict[str, list]]) -> str:
    """One line an operator can read: what exists, most-numerous first."""
    inv = inventory_counts(estate)
    if not inv["total"]:
        return "no AgentCore resources"
    parts = sorted(((n, k) for k, n in inv["counts"].items() if n), reverse=True)
    return ", ".join(f"{n} {k.replace('AgentCore', '')}" for n, k in parts)
