"""B1 — pure aws_kube core: EKS access-policy tiers, the offline EKS bearer-token minter,
the RBAC effective-privilege evaluator, and the IRSA / Pod-Security / PSA / NetworkPolicy /
reachability classifiers. No boto3 client, no socket, no STS call."""
import base64
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_kube as K


# ── access-policy tiers (partition-agnostic, last ARN segment) ───────────────
def test_access_policy_tier():
    assert K.access_policy_tier("arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy") == "CLUSTER_ADMIN"
    assert K.access_policy_tier("arn:aws-us-gov:eks::aws:cluster-access-policy/AmazonEKSViewPolicy") == "VIEW"
    assert K.access_policy_tier("arn:aws-cn:eks::aws:cluster-access-policy/AmazonEKSAdminViewPolicy") == "SECRET"
    assert K.access_policy_tier("arn:aws:eks::aws:cluster-access-policy/SomethingElse") == "OTHER"


def test_classify_access_entry_masters_and_policy_max():
    tier, scope, groups = K.classify_access_entry(
        {"kubernetesGroups": ["system:masters"]}, [])
    assert tier == "CLUSTER_ADMIN" and "system:masters" in groups
    tier, scope, _ = K.classify_access_entry({"kubernetesGroups": []}, [
        {"policyArn": ".../AmazonEKSViewPolicy", "accessScope": {"type": "cluster"}},
        {"policyArn": ".../AmazonEKSClusterAdminPolicy", "accessScope": {"type": "cluster"}}])
    assert tier == "CLUSTER_ADMIN" and scope == "cluster"     # MAX over associated policies
    tier, scope, _ = K.classify_access_entry({"kubernetesGroups": []}, [
        {"policyArn": ".../AmazonEKSAdminPolicy", "accessScope": {"type": "namespace",
                                                                  "namespaces": ["prod"]}}])
    assert tier == "NAMESPACE_ADMIN" and scope == "namespace"


# ── EKS bearer token (offline SigV4 presign) ─────────────────────────────────
def test_build_eks_bearer_token_format():
    from botocore.credentials import Credentials
    tok = K.build_eks_bearer_token(Credentials("AKIAEXAMPLE", "secret123"),
                                   "us-west-2", "prod-cluster")
    assert tok.startswith("k8s-aws-v1.")
    body = tok[len("k8s-aws-v1."):]
    assert "=" not in body                                     # base64url, no padding
    url = base64.urlsafe_b64decode(body + "==").decode()
    assert "GetCallerIdentity" in url
    assert "x-k8s-aws-id" in url.lower()                       # cluster-bound (no replay)
    assert "sts.us-west-2.amazonaws.com" in url               # regional STS


# ── RBAC effective-privilege evaluator ───────────────────────────────────────
def _crb(name, role, subjects, kind="ClusterRole"):
    return {"metadata": {"name": name}, "roleRef": {"kind": kind, "name": role},
            "subjects": subjects}


def _cr(name, rules):
    return {"metadata": {"name": name}, "rules": rules}


def test_rbac_cluster_admin_and_anonymous_and_wildcard():
    clusterroles = [
        _cr("cluster-admin", [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]),
        _cr("wild-reader", [{"apiGroups": [""], "resources": ["*"], "verbs": ["get", "list"]}]),
    ]
    crbs = [
        _crb("admins", "cluster-admin",
             [{"kind": "ServiceAccount", "namespace": "prod", "name": "deployer"}]),
        _crb("anon", "wild-reader", [{"kind": "Group", "name": "system:anonymous"}]),
    ]
    ev = K.evaluate_rbac(clusterroles, crbs)
    assert ("ServiceAccount", "prod", "deployer") in ev["cluster_admin_subjects"]
    assert len(ev["cluster_admin"]) == 1
    assert any(a["subject"]["name"] == "system:anonymous" for a in ev["anonymous"])
    assert any(w["role"] == "wild-reader" for w in ev["wildcard"])


def test_rbac_privesc_verbs_and_secrets():
    crs = [
        _cr("binder", [{"apiGroups": ["rbac.authorization.k8s.io"], "resources": ["roles"],
                        "verbs": ["bind", "escalate"]}]),
        _cr("secret-reader", [{"apiGroups": [""], "resources": ["secrets"],
                               "verbs": ["get", "list"]}]),
    ]
    crbs = [
        _crb("b1", "binder", [{"kind": "ServiceAccount", "namespace": "ci", "name": "runner"}]),
        _crb("s1", "secret-reader", [{"kind": "User", "name": "alice"}]),
    ]
    ev = K.evaluate_rbac(crs, crbs)
    assert ("ServiceAccount", "ci", "runner") in ev["privesc_subjects"]
    assert ("User", None, "alice") in ev["secret_subjects"]
    assert ev["cluster_admin_subjects"] == set()               # neither is full admin


def test_rolebinding_is_namespace_scope_not_cluster_admin():
    roles = [{"metadata": {"namespace": "prod", "name": "ns-admin"},
              "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]}]
    rbs = [{"metadata": {"namespace": "prod", "name": "rb"},
            "roleRef": {"kind": "Role", "name": "ns-admin"},
            "subjects": [{"kind": "ServiceAccount", "namespace": "prod", "name": "sa"}]}]
    ev = K.evaluate_rbac([], [], roles=roles, rolebindings=rbs)
    assert ("ServiceAccount", "prod", "sa") in ev["namespace_admin_subjects"]
    assert ev["cluster_admin_subjects"] == set()               # a RoleBinding is NOT cluster-admin


# ── IRSA / SA / pod / PSA / netpol classifiers ───────────────────────────────
def test_irsa_role_arn():
    sa = {"metadata": {"annotations": {K.IRSA_ANNOTATION: "arn:aws:iam::111:role/app"}}}
    assert K.irsa_role_arn(sa) == "arn:aws:iam::111:role/app"
    assert K.irsa_role_arn({"metadata": {"annotations": {}}}) is None
    assert K.irsa_role_arn({"metadata": {"annotations": {K.IRSA_ANNOTATION: "notanarn"}}}) is None


def test_sa_automount_default_true():
    assert K.sa_automounts_token({}) is True
    assert K.sa_automounts_token({"automountServiceAccountToken": False}) is False
    assert K.sa_automounts_token({"automountServiceAccountToken": True}) is True


def test_pod_service_account_and_security_findings():
    pod = {"spec": {"serviceAccountName": "deployer", "hostNetwork": True, "hostPID": True,
                    "volumes": [{"hostPath": {"path": "/var/run/docker.sock"}}],
                    "containers": [{"name": "c", "securityContext": {
                        "privileged": True, "capabilities": {"add": ["SYS_ADMIN", "NET_BIND"]}}}]}}
    assert K.pod_service_account(pod) == "deployer"
    issues = K.pod_security_findings(pod, {"SYS_ADMIN"})
    assert "hostNetwork" in issues and "hostPID" in issues
    assert any(i.startswith("hostPath:") for i in issues)
    assert any(i.startswith("privileged:") for i in issues)
    assert any("SYS_ADMIN" in i for i in issues)


def test_pod_default_service_account():
    assert K.pod_service_account({"spec": {}}) == "default"


def test_psa_enforce_level():
    ns = {"metadata": {"labels": {"pod-security.kubernetes.io/enforce": "restricted"}}}
    assert K.psa_enforce_level(ns) == "restricted"
    assert K.psa_enforce_level({"metadata": {"labels": {}}}) is None


def test_networkpolicy_default_deny():
    deny = [{"metadata": {"namespace": "prod"},
             "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}}]
    assert K.namespace_has_default_deny(deny, "prod") is True
    assert K.namespace_has_default_deny(deny, "dev") is False   # wrong namespace
    # a policy with an allow rule is NOT default-deny
    allow = [{"metadata": {"namespace": "prod"},
              "spec": {"podSelector": {}, "policyTypes": ["Ingress"],
                       "ingress": [{"from": []}]}}]
    assert K.namespace_has_default_deny(allow, "prod") is False


def test_is_system_namespace():
    assert K.is_system_namespace("kube-system") and K.is_system_namespace("kube-node-lease")
    assert not K.is_system_namespace("prod") and not K.is_system_namespace(None)


# ── reachability decision (from describe_cluster alone) ──────────────────────
def test_cluster_reachability():
    base = {"endpoint": "https://x.eks.amazonaws.com",
            "certificateAuthority": {"data": "Zm9v"}}
    ok, _ = K.cluster_reachability({**base, "resourcesVpcConfig": {"endpointPublicAccess": True},
                                    "accessConfig": {"authenticationMode": "API"}})
    assert ok is True
    priv, reason = K.cluster_reachability({**base, "resourcesVpcConfig": {
        "endpointPublicAccess": False, "endpointPrivateAccess": True}})
    assert priv is False and "private-only" in reason
    cfg, reason = K.cluster_reachability({**base, "resourcesVpcConfig": {"endpointPublicAccess": True},
                                          "accessConfig": {"authenticationMode": "CONFIG_MAP"}})
    assert cfg is False and "CONFIG_MAP" in reason
    creating, reason = K.cluster_reachability({"resourcesVpcConfig": {"endpointPublicAccess": True}})
    assert creating is False                                    # no endpoint/CA yet
