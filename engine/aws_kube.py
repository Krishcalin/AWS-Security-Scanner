#!/usr/bin/env python3
"""aws_kube.py — pure core for the agentless KSPM + KIEM slice (Phase 3).

OverWatch reads Kubernetes posture WITHOUT an in-cluster agent, in two layers:

  * **Layer A (always on, no grant, no cluster reachability):** the AWS **EKS Access
    Entries** API maps an AWS principal → a K8s access policy / group, and **EKS Pod
    Identity** maps a ServiceAccount → an AWS IAM role. Both are ``eks:*`` reads already
    covered by ``SecurityAudit`` — no new onboarding step.
  * **Layer B (optional, injected read-only K8s API seam):** ``GET``/``LIST`` on RBAC,
    ServiceAccounts, Pods, Pod-Security-Admission labels, and NetworkPolicies, behind an
    EKS bearer token. Fail-open when the endpoint is unreachable or read access is not
    granted.

This module holds the **boto3-free, socket-free** logic — the EKS bearer-token minter
(pure SigV4 presign, lazy botocore import), the access-policy tier classifier, the RBAC
effective-privilege evaluator, the IRSA / Pod-Security / PSA / NetworkPolicy classifiers —
so the whole KSPM/KIEM false-positive/false-negative catalogue runs offline. The thin,
reachability-gated collectors live in ``aws_live_scanner.py`` and call these functions.

READ-ONLY invariant: every K8s call is ``GET``/``LIST``; effective RBAC is computed HERE
from listed objects, so the scanner never issues a ``SelfSubjectAccessReview`` /
``SelfSubjectRulesReview`` / ``TokenReview`` (those are POST/create).
"""
from __future__ import annotations

import base64
from typing import Dict, List, Optional, Set, Tuple

# ── EKS access-policy tiers (KIEM) ────────────────────────────────────────────
# The managed EKS cluster-access policies, classified by their (account-less,
# partition-varying) ARN's last segment. Ranked so classify_access_entry can take a MAX.
_TIER_BY_POLICY = {
    "AmazonEKSClusterAdminPolicy": "CLUSTER_ADMIN",
    "AmazonEKSAdminPolicy": "NAMESPACE_ADMIN",
    "AmazonEKSEditPolicy": "EDIT",
    "AmazonEKSAdminViewPolicy": "SECRET",   # read-all incl. Secrets + RBAC
    "AmazonEKSViewPolicy": "VIEW",
}
_TIER_RANK = {"CLUSTER_ADMIN": 5, "NAMESPACE_ADMIN": 4, "EDIT": 3, "SECRET": 2,
              "VIEW": 1, "OTHER": 0}
# K8s built-in groups that must never carry real privilege via a binding.
ANON_GROUPS = frozenset({"system:anonymous", "system:unauthenticated", "system:authenticated"})
# RBAC verbs that grant privilege ESCALATION even without wildcard admin.
PRIVESC_VERBS = frozenset({"escalate", "bind", "impersonate"})
IRSA_ANNOTATION = "eks.amazonaws.com/role-arn"


def access_policy_tier(policy_arn: str) -> str:
    """Classify an EKS access-policy ARN by its last segment (partition-agnostic)."""
    name = (policy_arn or "").rstrip("/").split("/")[-1]
    return _TIER_BY_POLICY.get(name, "OTHER")


def classify_access_entry(entry: dict, associated_policies: List[dict]) -> Tuple[str, str, Set[str]]:
    """Return ``(max_tier, scope, kubernetesGroups)`` for an access entry + its associated
    policies. ``system:masters`` in the entry's groups is cluster-admin regardless of policy.
    ``describe_access_entry`` does NOT return the policies — the caller must pass the result
    of ``list_associated_access_policies``."""
    groups = set(entry.get("kubernetesGroups") or [])
    best_tier, best_scope = "OTHER", "cluster"
    if "system:masters" in groups:
        best_tier, best_scope = "CLUSTER_ADMIN", "cluster"
    for ap in associated_policies or []:
        tier = access_policy_tier(ap.get("policyArn", ""))
        scope = ((ap.get("accessScope") or {}).get("type")) or "cluster"
        if _TIER_RANK.get(tier, 0) > _TIER_RANK.get(best_tier, 0):
            best_tier, best_scope = tier, scope
    return best_tier, best_scope, groups


def tier_is_admin(tier: str) -> bool:
    return tier == "CLUSTER_ADMIN"


def tier_rank(tier: str) -> int:
    return _TIER_RANK.get(tier, 0)


# ── EKS Kubernetes-API bearer token (pure SigV4 presign; no socket) ──────────
def build_eks_bearer_token(credentials, region: str, cluster: str) -> str:
    """Mint an EKS API bearer token — ``"k8s-aws-v1." + base64url_nopad(presigned
    sts:GetCallerIdentity GET URL)`` — bound to ``cluster`` via the signed
    ``x-k8s-aws-id`` header (so a token cannot be replayed to another cluster). This is
    exactly what ``aws eks get-token`` / aws-iam-authenticator emit. Pure crypto, no
    socket; botocore is imported lazily so the rest of this module stays offline-import.

    ``credentials`` is a botocore ``Credentials`` (access_key/secret_key/token). The
    presign uses the REGIONAL STS endpoint. ``X-Amz-Expires=60`` is cosmetic — the STS
    presigned URL is valid ~15 min, so the caller regenerates per scan."""
    from botocore import session as _bcsession   # lazy: keeps import light + offline
    from botocore.signers import RequestSigner

    work = _bcsession.get_session()
    service_id = work.get_service_model("sts").service_id
    signer = RequestSigner(service_id, region, "sts", "v4", credentials,
                           work.get_component("event_emitter"))
    presigned = signer.generate_presigned_url(
        {"method": "GET",
         "url": f"https://sts.{region}.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15",
         "body": {}, "headers": {"x-k8s-aws-id": cluster}, "context": {}},
        region_name=region, expires_in=60, operation_name="")
    return "k8s-aws-v1." + base64.urlsafe_b64encode(presigned.encode("utf-8")).decode("utf-8").rstrip("=")


# ── RBAC effective-privilege evaluator (KIEM + KSPM-01/02/03) ─────────────────
def _rules_full_admin(rules: List[dict]) -> bool:
    """True if any rule grants ``*`` apiGroups AND ``*`` resources AND ``*`` verbs
    (the built-in ``cluster-admin`` shape)."""
    for r in rules or []:
        if ("*" in (r.get("apiGroups") or []) and "*" in (r.get("resources") or [])
                and "*" in (r.get("verbs") or [])):
            return True
    return False


def _rules_wildcard(rules: List[dict]) -> bool:
    """True if any rule uses ``*`` in ANY dimension (over-broad, CIS 4.1.3)."""
    for r in rules or []:
        if ("*" in (r.get("apiGroups") or []) or "*" in (r.get("resources") or [])
                or "*" in (r.get("verbs") or [])):
            return True
    return False


def _rules_privesc_verbs(rules: List[dict]) -> Set[str]:
    verbs: Set[str] = set()
    for r in rules or []:
        verbs |= set(r.get("verbs") or [])
    return verbs & PRIVESC_VERBS


def _rules_read_secrets(rules: List[dict]) -> bool:
    for r in rules or []:
        groups = set(r.get("apiGroups") or [])
        res = set(r.get("resources") or [])
        verbs = set(r.get("verbs") or [])
        if ("" in groups or "*" in groups) and ("secrets" in res or "*" in res) \
                and (verbs & {"get", "list", "watch", "*"}):
            return True
    return False


def _subject_key(s: dict) -> Tuple[str, Optional[str], str]:
    return (s.get("kind", ""), s.get("namespace"), s.get("name", ""))


def evaluate_rbac(clusterroles: List[dict], clusterrolebindings: List[dict],
                  roles: Optional[List[dict]] = None,
                  rolebindings: Optional[List[dict]] = None) -> dict:
    """Fold RBAC objects into effective privilege. Returns findings (anonymous /
    wildcard / cluster-admin bindings) for KSPM-01/02/03 AND subject-capability sets
    for the KIEM graph. RBAC is additive/allow-only, so a subject's effective power is
    the UNION over every binding. Only a ClusterRoleBinding to an admin ClusterRole is
    CLUSTER-scope admin; a RoleBinding is namespace-scoped."""
    cr_rules = {(cr.get("metadata") or {}).get("name"): (cr.get("rules") or [])
                for cr in clusterroles or []}
    role_rules = {((r.get("metadata") or {}).get("namespace"),
                   (r.get("metadata") or {}).get("name")): (r.get("rules") or [])
                  for r in roles or []}

    def _rules_for_ref(ref: dict, binding_ns: Optional[str]) -> Tuple[List[dict], str]:
        name = ref.get("name", "")
        if ref.get("kind") == "ClusterRole":
            return cr_rules.get(name, []), name
        return role_rules.get((binding_ns, name), []), name

    anonymous: List[dict] = []
    wildcard: List[dict] = []
    cluster_admin: List[dict] = []
    cluster_admin_subjects: Set[tuple] = set()
    namespace_admin_subjects: Set[tuple] = set()
    secret_subjects: Set[tuple] = set()
    privesc_subjects: Set[tuple] = set()

    def _scan(bindings, cluster_scope: bool):
        for b in bindings or []:
            meta = b.get("metadata") or {}
            ns = meta.get("namespace")
            rules, refname = _rules_for_ref(b.get("roleRef") or {}, ns)
            is_admin = refname == "cluster-admin" or _rules_full_admin(rules)
            is_wild = _rules_wildcard(rules)
            privesc = _rules_privesc_verbs(rules)
            secrets = _rules_read_secrets(rules)
            scope = "cluster" if cluster_scope else f"namespace:{ns}"
            for s in b.get("subjects") or []:
                key = _subject_key(s)
                # system:anonymous is a USER (not a Group) in K8s; system:unauthenticated/
                # authenticated are Groups. Match the name regardless of kind so the canonical
                # `--user=system:anonymous` cluster-admin anti-pattern is caught (it would
                # otherwise slip past both KSPM-01 and the KSPM-03 system:* controller skip).
                if s.get("name") in ANON_GROUPS:
                    anonymous.append({"binding": meta.get("name"), "scope": scope,
                                      "role": refname, "subject": s, "admin": is_admin})
                if is_admin:
                    (cluster_admin_subjects if cluster_scope
                     else namespace_admin_subjects).add(key)
                    if cluster_scope:
                        cluster_admin.append({"binding": meta.get("name"),
                                              "role": refname, "subject": s})
                elif is_wild:
                    wildcard.append({"binding": meta.get("name"), "scope": scope,
                                     "role": refname, "subject": s})
                if secrets:
                    secret_subjects.add(key)
                if privesc:
                    privesc_subjects.add(key)

    _scan(clusterrolebindings, cluster_scope=True)
    _scan(rolebindings, cluster_scope=False)
    return {
        "anonymous": anonymous, "wildcard": wildcard, "cluster_admin": cluster_admin,
        "cluster_admin_subjects": cluster_admin_subjects,
        "namespace_admin_subjects": namespace_admin_subjects,
        "secret_subjects": secret_subjects, "privesc_subjects": privesc_subjects,
    }


# ── ServiceAccount / Pod / PSA / NetworkPolicy classifiers (KSPM-04..07) ─────
def irsa_role_arn(sa_obj: dict) -> Optional[str]:
    """IRSA: a ServiceAccount annotated ``eks.amazonaws.com/role-arn`` assumes that AWS
    IAM role (the K8s→AWS cross-plane bridge)."""
    arn = ((sa_obj.get("metadata") or {}).get("annotations") or {}).get(IRSA_ANNOTATION)
    return arn if (arn and str(arn).startswith("arn:")) else None


def sa_automounts_token(sa_obj: dict) -> bool:
    """A ServiceAccount auto-mounts its token unless it explicitly opts out
    (``automountServiceAccountToken: false``). CIS 4.1.5/4.1.6."""
    return sa_obj.get("automountServiceAccountToken") is not False


def pod_service_account(pod: dict) -> str:
    spec = pod.get("spec") or {}
    return spec.get("serviceAccountName") or spec.get("serviceAccount") or "default"


def pod_security_findings(pod: dict, dangerous_caps: Set[str]) -> List[str]:
    """Pod-level escape primitives (CIS 4.2.x) — privileged / host-namespace / hostPath /
    dangerous caps / allowPrivilegeEscalation. ``dangerous_caps`` is reused from the
    scanner's ECS table so the two container surfaces stay consistent."""
    spec = pod.get("spec") or {}
    issues: List[str] = []
    for host in ("hostNetwork", "hostPID", "hostIPC"):
        if spec.get(host):
            issues.append(host)
    for v in spec.get("volumes") or []:
        hp = v.get("hostPath")
        if hp:
            issues.append(f"hostPath:{hp.get('path') or '?'}")
    # ALL container forms — an initContainer or ephemeralContainer running privileged / with a
    # dangerous cap can escape to the node just as a main container can (a common bootstrap trap).
    all_containers = ((spec.get("containers") or []) + (spec.get("initContainers") or [])
                      + (spec.get("ephemeralContainers") or []))
    for c in all_containers:
        cname = c.get("name", "?")
        sc = c.get("securityContext") or {}
        if sc.get("privileged"):
            issues.append(f"privileged:{cname}")
        if sc.get("allowPrivilegeEscalation") is True:
            issues.append(f"allowPrivEsc:{cname}")
        add = set(((sc.get("capabilities") or {}).get("add")) or [])
        risky = {cap.replace("CAP_", "") for cap in add} & dangerous_caps
        if risky:
            issues.append(f"caps:{cname}:{sorted(risky)}")
    return issues


def psa_enforce_level(ns_obj: dict) -> Optional[str]:
    """Pod Security Admission ENFORCE level from the namespace label (CIS 4.2/5.2).
    None = no namespace-level enforce label (the cluster-wide default is not readable
    here, so report INFO not FAIL)."""
    return ((ns_obj.get("metadata") or {}).get("labels") or {}).get(
        "pod-security.kubernetes.io/enforce")


def namespace_has_default_deny(netpols: List[dict], namespace: str) -> bool:
    """A namespace has default-deny iff its all-pods (``podSelector == {}``) no-allow-rule
    NetworkPolicies together cover BOTH directions. The single-policy form (policyTypes
    ⊇ {Ingress,Egress}) and the officially-documented TWO-policy form (a separate deny-ingress
    + deny-egress) are equivalent — so aggregate ``policyTypes`` across all such policies.
    CIS 4.3.2/5.3.x."""
    covered: Set[str] = set()
    for np in netpols or []:
        if ((np.get("metadata") or {}).get("namespace")) != namespace:
            continue
        spec = np.get("spec") or {}
        if spec.get("podSelector") == {} and not spec.get("ingress") and not spec.get("egress"):
            covered |= set(spec.get("policyTypes") or [])
    return {"Ingress", "Egress"} <= covered


def is_system_namespace(ns: Optional[str]) -> bool:
    """kube-system / kube-public / kube-node-lease and any kube-* — excluded from
    PSA / NetworkPolicy / pod FAILs (operator can't harden the managed control plane)."""
    return bool(ns) and (ns in ("kube-system", "kube-public", "kube-node-lease")
                         or str(ns).startswith("kube-"))


# ── reachability decision (from describe_cluster alone, before connecting) ────
def cluster_reachability(cluster: dict) -> Tuple[bool, str]:
    """Decide, from the ``describe_cluster`` dict alone, whether the K8s API layer can
    even be attempted. Returns ``(attemptable, reason)``. A private-only endpoint or a
    CONFIG_MAP-only auth mode is not attemptable agentlessly from outside the VPC."""
    vpc = cluster.get("resourcesVpcConfig") or {}
    public = vpc.get("endpointPublicAccess", True)
    private = vpc.get("endpointPrivateAccess", False)
    auth = ((cluster.get("accessConfig") or {}).get("authenticationMode")) or "API_AND_CONFIG_MAP"
    if not cluster.get("endpoint") or not (cluster.get("certificateAuthority") or {}).get("data"):
        return False, "cluster endpoint / CA not yet available (creating?)"
    if not public and private:
        return False, ("private-only API endpoint — run the K8s-API layer from inside the "
                       "VPC / via PrivateLink")
    if not public and not private:
        return False, "API endpoint access disabled"
    if auth == "CONFIG_MAP":
        return False, ("authenticationMode=CONFIG_MAP — identity mapping lives only in the "
                       "aws-auth ConfigMap; grant an EKS Access Entry (API mode) to read it")
    return True, "public endpoint reachable"


# ── the ONLY socket-touching function (injected seam default; mirrors default_http_post) ──
def default_k8s_get(ctx: dict, path: str) -> Optional[dict]:
    """GET a Kubernetes API path with an EKS bearer token, TLS-pinned to the cluster's own CA.
    ``ctx`` = ``{cluster, region, endpoint, ca_data(base64 PEM), credentials(botocore)}``.
    Returns the decoded JSON, or ``None`` on ANY failure (unreachable / TLS / 401 / 403 / timeout)
    so the caller fails open. READ-ONLY: only ever issues GET. Tests inject a fake for this."""
    import json as _json
    import ssl
    import urllib.request

    endpoint = (ctx.get("endpoint") or "").rstrip("/")
    if not endpoint or not ctx.get("credentials"):
        return None
    try:
        token = build_eks_bearer_token(ctx["credentials"], ctx["region"], ctx["cluster"])
        ca_pem = base64.b64decode(ctx["ca_data"]).decode("utf-8")
        ssl_ctx = ssl.create_default_context(cadata=ca_pem)   # verify against the cluster CA only
        req = urllib.request.Request(
            endpoint + path, method="GET",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=8, context=ssl_ctx) as resp:
            return _json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None
