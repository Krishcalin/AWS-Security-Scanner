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


# ── gateway authorization (slice 2.3) ───────────────────────────────────────
# Inbound: who the gateway lets in. From the GetGateway reference, verbatim.
INBOUND_AUTHORIZERS = ("CUSTOM_JWT", "AWS_IAM", "NONE", "AUTHENTICATE_ONLY")

#: Inbound modes where the GATEWAY decides authorization itself.
INBOUND_ENFORCING = ("CUSTOM_JWT", "AWS_IAM")
#: SigV4 verified, no authorization decision made. The developer guide: "the gateway
#: verifies the caller's SigV4 signature to authenticate the caller, but makes no
#: authorization decision ... any authenticated caller is forwarded to the target."
INBOUND_AUTHN_ONLY = "AUTHENTICATE_ONLY"
#: "the gateway performs no inbound authentication or authorization. Requests can be
#: unauthenticated, and any caller is forwarded to the target."
INBOUND_OPEN = "NONE"

#: Outbound credential types that carry the CALLER's identity to the target, so the
#: target's own authorization still applies. These are what make a permissive inbound
#: mode a deliberate architecture rather than a hole.
#:
#: Read off ``CredentialProviderType`` in the service model rather than recalled, after
#: the first authoring of this tuple invented all three names. The pinned 1.40.51 enum is
#: ``GATEWAY_IAM_ROLE | OAUTH | API_KEY`` -- it has NO caller-carrying value at all --
#: and 1.43.51 adds exactly ``CALLER_IAM_CREDENTIALS`` and ``JWT_PASSTHROUGH``.
#: ``OAUTH_TOKEN_EXCHANGE`` exists in neither and is gone.
#:
#: The consequence under the pin is worth stating: a gateway CANNOT be graded DELEGATED,
#: because no value the SDK can return means "the caller's identity flows onward". That
#: is a limit of what is knowable, so it resolves to UNKNOWN rather than to OPEN -- see
#: gateway_authorization.
OUTBOUND_CARRIES_CALLER = ("CALLER_IAM_CREDENTIALS", "JWT_PASSTHROUGH")
#: Outbound types that use the GATEWAY's own credentials. The developer guide is explicit
#: about what this means: "The gateway execution role is shared across all targets
#: configured with GATEWAY_IAM_ROLE. Its permissions are the upper bound for what any
#: authorized caller can exercise through the gateway."
OUTBOUND_GATEWAY_OWN = ("GATEWAY_IAM_ROLE", "OAUTH", "API_KEY", "NONE")

# verdicts
GW_ENFORCED = "ENFORCED"           # the gateway authorizes
GW_DELEGATED = "DELEGATED"         # permissive inbound, but the caller's identity flows
GW_COMPENSATED = "COMPENSATED"     # permissive inbound, a policy engine/interceptor sits in front
GW_OPEN = "OPEN"                   # permissive inbound AND the gateway's own credentials
GW_UNKNOWN = "UNKNOWN"             # permissive inbound, targets not readable
GW_VERDICTS = (GW_ENFORCED, GW_DELEGATED, GW_COMPENSATED, GW_OPEN, GW_UNKNOWN)


def _target_outbound_types(targets) -> List[str]:
    """Every outbound credential type configured across a gateway's targets.

    ``credentialProviderConfigurations`` lives on **GetGatewayTarget** and on no other
    response. ``ListGatewayTargets`` returns ``TargetSummary``, which is
    ``targetId, name, status, description, createdAt, updatedAt`` -- and nothing else, in
    every SDK version checked. Feeding this the list results, as the caller originally
    did, therefore returned ``[]`` for every gateway in existence."""
    out = []
    for t in targets or []:
        if not isinstance(t, dict):
            continue
        for cfg in t.get("credentialProviderConfigurations") or []:
            if isinstance(cfg, dict) and cfg.get("credentialProviderType"):
                out.append(str(cfg["credentialProviderType"]).upper())
    return out


def targets_are_graded(targets) -> bool:
    """Whether the targets handed in can actually decide the outbound question.

    A non-empty target list carrying no credential configuration at all is the signature
    of summaries passed where details were needed. Distinguishing that from "read in full
    and genuinely has none" is what stops a fetch mistake from being reported as a
    CRITICAL finding about the customer's architecture."""
    raw = list(targets or [])
    if not raw:
        return True                     # [] means no targets; nothing to grade
    # Filtering to dicts FIRST would be the bug this function exists to catch: a list of
    # things that are not dicts is a list we could not read, not an absence of targets.
    return any(isinstance(t, dict) and "credentialProviderConfigurations" in t
               for t in raw)


def gateway_authorization(gateway: Optional[dict],
                          targets: Optional[Sequence[dict]] = None) -> dict:
    """Grade a gateway's inbound authorization, in the light of what it does outbound.

    A boolean ``authorizerType == "NONE"`` check would be wrong, and wrong in the
    direction that gets a scanner distrusted: AWS documents both permissive inbound modes
    as deliberate architectures when authorization is handled elsewhere. AUTHENTICATE_ONLY
    exists precisely so the caller's token can be forwarded and validated downstream.

    What actually decides the verdict is whose identity reaches the target:

      * the gateway authorizes (CUSTOM_JWT / AWS_IAM)                     -> ENFORCED
      * permissive inbound, but the CALLER's identity flows onward, so the
        target authorizes                                                -> DELEGATED
      * permissive inbound, but a policy engine or interceptor sits in
        front of the targets                                             -> COMPENSATED
      * permissive inbound AND the gateway's own credentials downstream   -> OPEN

    OPEN is the finding. There, any caller the inbound mode admits exercises the gateway
    execution role, whose permissions the guide names as "the upper bound for what any
    authorized caller can exercise through the gateway" — and with NONE, "any caller"
    includes unauthenticated ones."""
    g = gateway or {}
    inbound = (g.get("authorizerType") or "").upper()
    outbound = _target_outbound_types(targets)

    # Compensating controls AWS itself points at for permissive inbound modes.
    policy_engine = bool((g.get("policyEngineConfiguration") or {}).get("arn"))
    interceptors = bool(g.get("interceptorConfigurations"))

    if inbound in INBOUND_ENFORCING:
        return {"verdict": GW_ENFORCED, "inbound": inbound, "outbound": outbound,
                "unauthenticated": False, "policy_engine": policy_engine,
                "interceptors": interceptors,
                "reason": "the gateway authorizes callers itself"}

    unauth = inbound == INBOUND_OPEN
    carries_caller = [o for o in outbound if o in OUTBOUND_CARRIES_CALLER]
    gateway_own = [o for o in outbound if o in OUTBOUND_GATEWAY_OWN]

    base = {"inbound": inbound or "(unset)", "outbound": outbound,
            "unauthenticated": unauth, "policy_engine": policy_engine,
            "interceptors": interceptors}

    # `targets is None` means we could not read them; `[]` means the gateway has none.
    # Collapsing the two would report OPEN on the strength of a refused API call, which
    # is the phantom-finding mirror of a phantom pass.
    if targets is None:
        return dict(base, verdict=GW_UNKNOWN,
                    reason=(f"inbound {inbound} makes no authorization decision, and the "
                            f"gateway's targets could not be enumerated — whether the "
                            f"caller's identity reaches them is unknown, not benign"))

    # Summaries where details were needed: every target lacks the credential field
    # entirely. Grading OPEN on that is a claim about the customer's architecture built
    # on a fetch mistake, and OPEN is this module's CRITICAL. It is the phantom finding
    # -- the mirror of the phantom pass -- so it resolves to UNKNOWN, which is what the
    # refused-read path above already does for the same reason.
    if not targets_are_graded(targets):
        return dict(base, verdict=GW_UNKNOWN,
                    reason=(f"inbound {inbound} makes no authorization decision, and the "
                            f"targets carry no credential configuration to grade — "
                            f"whether the caller's identity reaches them is unknown, not "
                            f"benign and not proven open"))

    if carries_caller and not gateway_own:
        return dict(base, verdict=GW_DELEGATED,
                    reason=(f"inbound {inbound} forwards the caller's own identity "
                            f"({', '.join(sorted(set(carries_caller)))}), so the target "
                            f"still authorizes"))
    if policy_engine or interceptors:
        which = " and ".join(x for x in (
            "a policy engine" if policy_engine else "",
            "an interceptor" if interceptors else "") if x)
        return dict(base, verdict=GW_COMPENSATED,
                    reason=(f"inbound {inbound} makes no authorization decision, but "
                            f"{which} sits in front of the targets — confirm it covers "
                            f"every target"))
    return dict(base, verdict=GW_OPEN,
                reason=(f"inbound {inbound} makes no authorization decision and the "
                        f"targets use the gateway's own credentials"
                        f"{' (' + ', '.join(sorted(set(gateway_own))) + ')' if gateway_own else ''}"
                        f", whose permissions bound what any caller can exercise"))


def gateway_debug_errors(gateway: Optional[dict]) -> bool:
    """``exceptionLevel: DEBUG`` returns granular exception messages to the caller.

    From the reference: "If the value is DEBUG, granular exception messages are returned
    to help a user debug the gateway. If the value is omitted, a generic error message is
    returned to the end user." On a gateway whose callers are not all trusted, those
    messages describe the targets behind it."""
    return (((gateway or {}).get("exceptionLevel") or "").upper() == "DEBUG")


# ── credential exposure (slice 2.5) ─────────────────────────────────────────
#: GetTokenVault.kmsConfiguration.keyType, from the pinned service model.
KEY_TYPES = ("CustomerManagedKey", "ServiceManagedKey")


def token_vault_posture(vault: Optional[dict]) -> dict:
    """Who holds the key to the store that holds every agent credential.

    The token vault is where AgentCore keeps the OAuth2 client secrets and API keys an
    agent uses to reach systems outside AWS. ``ServiceManagedKey`` is not an encryption
    failure — the data is encrypted either way — it is a CUSTODY one. With a
    customer-managed key the operator can revoke access by disabling the key, can see
    every decrypt in CloudTrail through their own key policy, and can bound who decrypts
    with a key policy. With a service-managed key none of those levers exist, and for the
    store holding credentials to systems AWS controls nothing about, that asymmetry is
    the point."""
    v = vault or {}
    cfg = v.get("kmsConfiguration") or {}
    ktype = cfg.get("keyType") or ""
    return {
        "vault_id": v.get("tokenVaultId") or "",
        "key_type": ktype,
        "known_key_type": ktype in KEY_TYPES,
        "customer_managed": ktype == "CustomerManagedKey",
        "kms_key_arn": cfg.get("kmsKeyArn") or "",
        # Absent rather than assumed: an empty kmsConfiguration is a response we could
        # not interpret, not a service-managed key.
        "known": bool(ktype),
    }


def unsafe_return_urls(identity: Optional[dict]) -> List[str]:
    """OAuth2 return URLs that carry the authorization code over plaintext.

    ``allowedResourceOauth2ReturnUrls`` is where an OAuth flow may hand the code back.
    An ``http://`` entry means that hand-back is unencrypted, and an authorization code
    observed in transit is an authorization code an attacker can redeem.

    Only the scheme is judged. It would be easy to also flag a URL containing ``*`` as a
    wildcard, but whether AgentCore matches these by prefix, pattern or equality is not
    documented in the API reference, and a finding whose severity depends on undocumented
    matching semantics is a guess about someone else's implementation."""
    urls = (identity or {}).get("allowedResourceOauth2ReturnUrls") or []
    if not isinstance(urls, (list, tuple)):
        return []
    return sorted({u for u in urls
                   if isinstance(u, str) and u.lower().startswith("http://")})
