"""Phase 3 — agentless KSPM (CIS-EKS K8s-side) + KIEM (identity/entitlement) via EKS
Access Entries + the read-only Kubernetes API, folded into the attack-path graph.

B2 (this file, part 1): the ALWAYS-ON AWS-side KIEM — EKS Access Entries -> AWS-principal
cluster-admin (KIEM-01/02/03), Pod Identity SA->role stash, EKS-08 auth-mode posture. No
cluster reachability, no K8s API. Offline: MagicMock eks via s._clients."""
import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import aws_live_scanner as A
import aws_graph
from test_live_scanner import make_scanner

OWN = "123456789012"
EXT = "999999999999"
CLUSTER = "prod"
CLUSTER_ARN = f"arn:aws:eks:us-east-1:{OWN}:cluster/{CLUSTER}"
CADMIN = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
VIEW = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy"
ADMINVIEW = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSAdminViewPolicy"


def _pager(key, items):
    p = MagicMock()
    p.paginate.return_value = [{key: items}]
    return p


def _eks(entries=None, entry_detail=None, assoc=None, pod_ids=None):
    """MagicMock eks that routes each paginator/describe by operation name."""
    eks = MagicMock()
    pagers = {
        "list_access_entries": _pager("accessEntries", entries or []),
        "list_associated_access_policies": _pager("associatedAccessPolicies", assoc or []),
        "list_pod_identity_associations": _pager("associations", pod_ids or []),
    }
    eks.get_paginator.side_effect = lambda op: pagers.get(op, _pager("x", []))
    eks.describe_access_entry.side_effect = lambda clusterName, principalArn: {
        "accessEntry": (entry_detail or {}).get(principalArn,
                                                {"principalArn": principalArn, "type": "STANDARD"})}
    return eks


def _scanner(c=None):
    s = make_scanner(["EKS"])
    s.account = OWN
    s.graph = aws_graph.SecurityGraph()
    return s


def _cluster(mode="API", arn=CLUSTER_ARN):
    return {"arn": arn, "accessConfig": {"authenticationMode": mode}}


def _status(s, cid):
    return {r.status for r in s.results if r.check_id == cid}


# ── EKS-08 auth mode ─────────────────────────────────────────────────────────
def test_eks08_config_map_warns():
    s = _scanner()
    s._check_eks_kiem(_eks(), CLUSTER, _cluster(mode="CONFIG_MAP"))
    assert "WARN" in _status(s, "EKS-08")


def test_eks08_api_mode_info():
    s = _scanner()
    s._check_eks_kiem(_eks(), CLUSTER, _cluster(mode="API"))
    assert _status(s, "EKS-08") == {"INFO"}


# ── KIEM-01: over-broad AWS principal with cluster-admin ─────────────────────
def test_kiem01_cluster_admin_via_policy():
    parn = f"arn:aws:iam::{OWN}:role/eks-admins"
    s = _scanner()
    s._check_eks_kiem(_eks(entries=[parn], assoc=[{"policyArn": CADMIN,
                       "accessScope": {"type": "cluster"}}]), CLUSTER, _cluster())
    assert "FAIL" in _status(s, "KIEM-01")
    # stashed cross-plane escalation edge principal -> KubeAdminCapability
    admin = [p for p in s._kube_payloads if p["kind"] == "principal_admin"]
    assert admin and admin[0]["principal"] == parn
    assert admin[0]["admin_cap"] == f"capability:k8s-admin:{CLUSTER_ARN}"
    assert admin[0]["conditioned"] is False


def test_kiem01_system_masters_group():
    parn = f"arn:aws:iam::{OWN}:role/masters"
    s = _scanner()
    detail = {parn: {"principalArn": parn, "type": "STANDARD",
                     "kubernetesGroups": ["system:masters"]}}
    s._check_eks_kiem(_eks(entries=[parn], entry_detail=detail), CLUSTER, _cluster())
    assert "FAIL" in _status(s, "KIEM-01")


def test_kiem01_cross_account_flagged_critical():
    parn = f"arn:aws:iam::{EXT}:role/partner"
    s = _scanner()
    s._check_eks_kiem(_eks(entries=[parn], assoc=[{"policyArn": CADMIN,
                       "accessScope": {"type": "cluster"}}]), CLUSTER, _cluster())
    msg = [r.message for r in s.results if r.check_id == "KIEM-01"][0]
    assert "CROSS-ACCOUNT" in msg


def test_node_bootstrap_entry_skipped():
    parn = f"arn:aws:iam::{OWN}:role/eks-nodegroup"
    s = _scanner()
    detail = {parn: {"principalArn": parn, "type": "EC2_LINUX",
                     "kubernetesGroups": ["system:nodes"]}}
    s._check_eks_kiem(_eks(entries=[parn], entry_detail=detail,
                           assoc=[{"policyArn": CADMIN}]), CLUSTER, _cluster())
    assert not _status(s, "KIEM-01")                 # node identity is not an over-priv finding


# ── KIEM-02/03: namespace-admin / secret-read ────────────────────────────────
def test_kiem03_secret_reader():
    parn = f"arn:aws:iam::{OWN}:role/auditor"
    s = _scanner()
    s._check_eks_kiem(_eks(entries=[parn], assoc=[{"policyArn": ADMINVIEW,
                       "accessScope": {"type": "cluster"}}]), CLUSTER, _cluster())
    assert "WARN" in _status(s, "KIEM-03")


# ── Pod Identity SA -> IAM role (cross-plane, no K8s API) ─────────────────────
def test_pod_identity_stashes_sa_role_edge():
    s = _scanner()
    s._check_eks_kiem(_eks(pod_ids=[{"namespace": "prod", "serviceAccount": "app",
                                     "roleArn": f"arn:aws:iam::{OWN}:role/app-irsa"}]),
                      CLUSTER, _cluster())
    sar = [p for p in s._kube_payloads if p["kind"] == "sa_role"]
    assert sar and sar[0]["role_arn"] == f"arn:aws:iam::{OWN}:role/app-irsa"
    assert sar[0]["sa_node"] == f"k8s:sa:{CLUSTER_ARN}:prod:app"
    assert sar[0]["basis"] == "pod-identity"


# ── fail-open: denied list_access_entries -> INFO, no crash ──────────────────
def test_access_entries_denied_info():
    s = _scanner()
    eks = MagicMock()
    eks.get_paginator.side_effect = RuntimeError("AccessDenied")
    s._check_eks_kiem(eks, CLUSTER, _cluster())
    assert "INFO" in _status(s, "KIEM-01")
    assert not [p for p in s._kube_payloads if p["kind"] == "principal_admin"]


# ═══════════════════════════════════════════════════════════════════════════════
# B3 — clobber-safe K8s graph lane (KubeAdminCapability, replay, idempotency)
# ═══════════════════════════════════════════════════════════════════════════════
import aws_correlate as C                                                     # noqa: E402

PRINCIPAL = f"arn:aws:iam::{OWN}:role/eks-admins"
K8S_ADMIN = f"capability:k8s-admin:{CLUSTER_ARN}"
SA_NODE = f"k8s:sa:{CLUSTER_ARN}:prod:app"
IRSA_ROLE = f"arn:aws:iam::{OWN}:role/app-irsa"


def test_kube_edges_replay_survives_clobber_idempotent():
    s = _scanner()
    s._kube_payloads = [
        {"kind": "principal_admin", "principal": PRINCIPAL, "admin_cap": K8S_ADMIN,
         "cluster_arn": CLUSTER_ARN, "conditioned": False},
        {"kind": "sa_role", "sa_node": SA_NODE, "cluster_arn": CLUSTER_ARN,
         "namespace": "prod", "sa_name": "app", "role_arn": IRSA_ROLE, "basis": "irsa"}]
    # simulate IAMPRIVESC#36 hard-replacing the graph, then replay twice
    s.graph = aws_graph.SecurityGraph()
    s._replay_kube_edges()
    s._replay_kube_edges()
    g = s.graph
    cap = g.node(K8S_ADMIN)
    assert cap["kind"] == "KubeAdminCapability" and cap["props"]["crown_jewel"] is True
    pe = g.out_edges(PRINCIPAL, ["CAN_PRIVESC_TO"])
    assert len(pe) == 1 and pe[0]["dst"] == K8S_ADMIN         # idempotent (not 2)
    ca = g.out_edges(SA_NODE, ["CAN_ASSUME"])
    assert len(ca) == 1 and ca[0]["dst"] == IRSA_ROLE and ca[0]["props"]["conditioned"] is False


def test_kube_admin_capability_is_crown_node():
    g = aws_graph.SecurityGraph()
    A.AWSLiveScanner._emit_one_kube(g, {"kind": "principal_admin", "principal": PRINCIPAL,
                                        "admin_cap": K8S_ADMIN, "cluster_arn": CLUSTER_ARN,
                                        "conditioned": False})
    # aws_correlate.crown_nodes is prop-based -> picks up KubeAdminCapability with ZERO kind edit
    assert K8S_ADMIN in C.crown_nodes(g)


def test_aws_correlate_unchanged_no_kube_kinds():
    # invariant: no _EXPLOIT_KINDS / E_PATH edit for the K8s slice (mirror the Fargate invariant)
    assert "KubePod" not in C._EXPLOIT_KINDS
    assert "KubeServiceAccount" not in C._EXPLOIT_KINDS
    assert "KubeAdminCapability" not in C._EXPLOIT_KINDS


def test_kube_admin_capability_distinct_from_aws_admin():
    # K8s cluster-admin != AWS account-admin: the two capability nodes are different ids
    s = _scanner()
    assert K8S_ADMIN != s._admin_cap_id()


# ═══════════════════════════════════════════════════════════════════════════════
# B4 — injected K8s-API layer (reachability gate + KSPM-00..07 from fixtures)
# ═══════════════════════════════════════════════════════════════════════════════
def _reachable_cluster():
    return {"arn": CLUSTER_ARN, "endpoint": "https://x.eks.amazonaws.com",
            "certificateAuthority": {"data": "Zm9v"},
            "resourcesVpcConfig": {"endpointPublicAccess": True},
            "accessConfig": {"authenticationMode": "API"}}


def _fake_k8s(namespaces=(), pods=(), sas=(), netpols=(), crs=(), crbs=(), roles=(), rbs=()):
    routes = {
        "/api/v1/namespaces": list(namespaces), "/api/v1/pods": list(pods),
        "/api/v1/serviceaccounts": list(sas),
        "/apis/networking.k8s.io/v1/networkpolicies": list(netpols),
        "/apis/rbac.authorization.k8s.io/v1/clusterroles": list(crs),
        "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings": list(crbs),
        "/apis/rbac.authorization.k8s.io/v1/roles": list(roles),
        "/apis/rbac.authorization.k8s.io/v1/rolebindings": list(rbs)}

    def get(ctx, path):
        return {"items": routes.get(path, [])}
    return get


def _ns(name, enforce=None):
    labels = {"pod-security.kubernetes.io/enforce": enforce} if enforce else {}
    return {"metadata": {"name": name, "labels": labels}}


def _run_kspm(s, c=None, **fixtures):
    c = c or _reachable_cluster()
    s._k8s_get = _fake_k8s(**fixtures)
    s._check_kspm(CLUSTER, c, CLUSTER_ARN, K8S_ADMIN)


# ── reachability fail-open ───────────────────────────────────────────────────
def test_kspm00_private_only_fail_open():
    s = _scanner()
    c = {"arn": CLUSTER_ARN, "endpoint": "https://x", "certificateAuthority": {"data": "Zm9v"},
         "resourcesVpcConfig": {"endpointPublicAccess": False, "endpointPrivateAccess": True}}
    s._check_kspm(CLUSTER, c, CLUSTER_ARN, K8S_ADMIN)
    assert "INFO" in _status(s, "KSPM-00")
    assert not [r for r in s.results if r.check_id.startswith("KSPM-0") and r.check_id != "KSPM-00"
                and r.status == "FAIL"]                        # no phantom FAIL/PASS


def test_kspm00_get_denied_fail_open():
    s = _scanner()
    s._k8s_get = lambda ctx, path: None                        # reachable but read denied
    s._check_kspm(CLUSTER, _reachable_cluster(), CLUSTER_ARN, K8S_ADMIN)
    assert "INFO" in _status(s, "KSPM-00")


# ── KSPM checks from fixtures ────────────────────────────────────────────────
def test_kspm01_anonymous_binding():
    s = _scanner()
    _run_kspm(s, crs=[{"metadata": {"name": "reader"},
                       "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}]}],
              crbs=[{"metadata": {"name": "anon"}, "roleRef": {"kind": "ClusterRole", "name": "reader"},
                     "subjects": [{"kind": "Group", "name": "system:anonymous"}]}])
    assert "FAIL" in _status(s, "KSPM-01")


def test_kspm03_cluster_admin_to_service_account_stashes_edge():
    s = _scanner()
    _run_kspm(s,
              crs=[{"metadata": {"name": "cluster-admin"},
                    "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]}],
              crbs=[{"metadata": {"name": "ca"}, "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
                     "subjects": [{"kind": "ServiceAccount", "namespace": "prod", "name": "deployer"}]}])
    assert "FAIL" in _status(s, "KSPM-03")
    # a cluster-admin ServiceAccount stashes an SA -> KubeAdminCapability escalation edge
    assert any(p["kind"] == "sa_admin" and p["sa_name"] == "deployer" for p in s._kube_payloads)


def test_kspm05_06_07_and_system_ns_excluded():
    s = _scanner()
    priv_pod = {"metadata": {"name": "bad", "namespace": "prod"},
                "spec": {"containers": [{"name": "c", "securityContext": {"privileged": True}}]}}
    sys_pod = {"metadata": {"name": "kube-proxy", "namespace": "kube-system"},
               "spec": {"hostNetwork": True, "containers": []}}
    _run_kspm(s, namespaces=[_ns("prod", enforce="privileged"), _ns("kube-system")],
              pods=[priv_pod, sys_pod])
    assert "FAIL" in _status(s, "KSPM-05")                     # prod PSA=privileged
    assert "FAIL" in _status(s, "KSPM-06")                     # prod no default-deny netpol
    assert "FAIL" in _status(s, "KSPM-07")                     # prod privileged pod
    # system namespace excluded from all three
    assert not any(r.resource.startswith(f"{CLUSTER}/kube-system") for r in s.results
                   if r.check_id in ("KSPM-05", "KSPM-06", "KSPM-07"))


def test_pod_and_irsa_graph_stashed():
    s = _scanner()
    irsa_role = f"arn:aws:iam::{OWN}:role/app-irsa"
    sa = {"metadata": {"name": "app", "namespace": "prod",
                       "annotations": {"eks.amazonaws.com/role-arn": irsa_role}}}
    img = f"{OWN}.dkr.ecr.us-east-1.amazonaws.com/api@sha256:beef"
    pod = {"metadata": {"name": "api-0", "namespace": "prod"},
           "spec": {"serviceAccountName": "app", "containers": [{"name": "api", "image": img}]},
           "status": {"podIP": "10.0.9.9",
                      "containerStatuses": [{"name": "api", "imageID": f"docker-pullable://{img}"}]}}
    _run_kspm(s, namespaces=[_ns("prod", enforce="restricted")], sas=[sa], pods=[pod])
    assert any(p["kind"] == "sa_role" and p["role_arn"] == irsa_role and p["basis"] == "irsa"
               for p in s._kube_payloads)
    pod_sa = [p for p in s._kube_payloads if p["kind"] == "pod_sa"]
    assert pod_sa and pod_sa[0]["sa_node"] == f"k8s:sa:{CLUSTER_ARN}:prod:app"
    assert pod_sa[0]["image_nodes"] and pod_sa[0]["private_ip"] == "10.0.9.9"


# ═══════════════════════════════════════════════════════════════════════════════
# B5 — IRSA cross-plane: KIEM-04 finding + enumerate_paths discovers the ranked path
# ═══════════════════════════════════════════════════════════════════════════════
import aws_deepplane as D                                                     # noqa: E402

POD = f"k8s:pod:{CLUSTER_ARN}:prod:api-0"
IMG = f"{OWN}.dkr.ecr.us-east-1.amazonaws.com/api@sha256:beef"
CROWN = "arn:aws:s3:::crown-data"


def _cross_plane_graph(kev=True):
    """internet -> exposed pod (image CVE) -> SA -> IRSA role -> AWS admin AND crown."""
    g = aws_graph.SecurityGraph()
    g.add_node("internet", "InternetSource")
    g.add_node(f"lb/{CLUSTER_ARN}", "LoadBalancer", name="ingress")
    g.add_node(POD, "KubePod", namespace="prod", name="api-0")
    g.add_node(SA_NODE, "KubeServiceAccount", namespace="prod", name="app")
    g.add_node(IRSA_ROLE, "IAMRole", name="app-irsa")
    aws_admin = f"capability:admin:{OWN}"
    g.add_node(aws_admin, "AdminCapability")
    g.add_node(CROWN, "S3Bucket", name="crown-data", crown_jewel=True)
    g.add_node(IMG, "ECRImage", repository="api")
    g.add_edge("internet", f"lb/{CLUSTER_ARN}", "EXPOSED_TO", basis="l7")
    g.add_edge(f"lb/{CLUSTER_ARN}", POD, "TARGETS", basis="l7-ip")
    g.add_edge(POD, SA_NODE, "HAS_ROLE", role_type="k8s-sa")
    g.add_edge(POD, IMG, "RUNS_IMAGE", container="api", scan_source="eks-pod")
    g.add_edge(SA_NODE, IRSA_ROLE, "CAN_ASSUME", basis="irsa", conditioned=False)
    g.add_edge(IRSA_ROLE, aws_admin, "CAN_PRIVESC_TO", conditioned=False)
    g.add_edge(IRSA_ROLE, CROWN, "CAN_READ_DATA", conditioned=False)
    if kev:
        g.add_node("CVE-2021-44228", "Vulnerability", kev=True)
        g.add_edge(IMG, "CVE-2021-44228", "HAS_VULN", cve="CVE-2021-44228", kev=True,
                   exploit_available="YES")
    return g, aws_admin


def test_enumerate_paths_discovers_cross_plane_irsa_path():
    g, aws_admin = _cross_plane_graph(kev=True)
    is_uncond = lambda e: not e["props"].get("conditioned") and not e["props"].get("has_condition")
    threatened = {e["dst"] for e in g.edges("THREAT_ON")}
    paths = C.enumerate_paths(g, {"internet"}, aws_admin, C.crown_nodes(g),
                              is_uncond, D.is_exploitable, lambda nid: nid in threatened)
    # internet -> pod (image CVE via RUNS_IMAGE) -> SA -> IRSA role -> AWS admin AND crown
    assert {p.terminal_kind for p in paths} == {"admin", "data"}
    assert all(p.severity == "CRITICAL" for p in paths)
    assert all(POD in p.nodes and SA_NODE in p.nodes and IRSA_ROLE in p.nodes for p in paths)


def test_kiem04_irsa_reaches_aws_admin():
    from unittest.mock import patch
    s = _scanner()
    g, _ = _cross_plane_graph(kev=True)
    s.graph = g
    s.account = OWN
    with patch("builtins.print"):
        s._check_kiem_irsa(g)
    k4 = [r for r in s.results if r.check_id == "KIEM-04"]
    assert k4 and k4[0].status == "FAIL"
    assert "assumes AWS role" in k4[0].message


# ═══════════════════════════════════════════════════════════════════════════════
# B6 — EXPOSURE join: an internet-facing ALB ip-target that is an EKS pod IP
# ═══════════════════════════════════════════════════════════════════════════════
from unittest.mock import patch                                              # noqa: E402

LB_ARN = f"arn:aws:elasticloadbalancing:us-east-1:{OWN}:loadbalancer/app/ingress/50dc"
PUB_SG = {"sg-1": [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}


def _ec2_client(enis, sgs=None):
    ec2 = MagicMock()
    pages = {"describe_network_interfaces": {"NetworkInterfaces": enis},
             "describe_security_groups": {"SecurityGroups": sgs or []},
             "describe_route_tables": {"RouteTables": []},
             "describe_network_acls": {"NetworkAcls": []},
             "describe_instances": {"Reservations": []}}
    ec2.get_paginator.side_effect = lambda op: type("P", (), {
        "paginate": lambda self, **k: [pages.get(op, {})]})()
    return ec2


def _elbv2_ip_target(ip):
    c = MagicMock()
    c.get_paginator.return_value = _pager("LoadBalancers", [{
        "LoadBalancerArn": LB_ARN, "LoadBalancerName": "ingress", "DNSName": "ingress.elb",
        "Scheme": "internet-facing", "Type": "application", "State": {"Code": "active"},
        "SecurityGroups": ["sg-1"]}])
    c.describe_listeners.return_value = {"Listeners": [{"Port": 443, "Protocol": "HTTPS"}]}
    c.describe_target_groups.return_value = {"TargetGroups": [
        {"TargetGroupArn": "arn:tg/1", "TargetType": "ip", "VpcId": "vpc-1"}]}
    c.describe_target_health.return_value = {"TargetHealthDescriptions": [
        {"Target": {"Id": ip}, "TargetHealth": {"State": "healthy"}}]}
    c.describe_rules.return_value = {"Rules": []}
    return c


def _empty_pager_client(key):
    c = MagicMock()
    c.get_paginator.return_value.paginate.return_value = [{key: []}]
    return c


def test_pod_behind_alb_ip_target_gets_internet_path():
    s = make_scanner(sections=["EXPOSURE"])
    s.account = OWN
    aws_admin = f"capability:admin:{OWN}"
    g = aws_graph.SecurityGraph()
    g.add_node(aws_admin, "AdminCapability")
    g.add_node(IRSA_ROLE, "IAMRole", name="app-irsa")
    g.add_edge(IRSA_ROLE, aws_admin, "CAN_PRIVESC_TO", conditioned=False)
    s.graph = g
    s._get_iam_principals = lambda: []
    s._cred_report = []
    s._cred_report_ok = False
    # stashed K8s workload graph (as EKS#18 would produce): pod -> SA (+ image), SA -> IRSA role
    s._kube_payloads = [
        {"kind": "pod_sa", "pod_node": POD, "sa_node": SA_NODE, "cluster_arn": CLUSTER_ARN,
         "cluster_vpc": "vpc-1", "namespace": "prod", "pod_name": "api-0", "sa_name": "app",
         "private_ip": "10.0.9.9",
         "image_nodes": [(IMG, {"repository": "api", "digest": "sha256:beef"}, "api")]},
        {"kind": "sa_role", "sa_node": SA_NODE, "cluster_arn": CLUSTER_ARN, "namespace": "prod",
         "sa_name": "app", "role_arn": IRSA_ROLE, "basis": "irsa"}]
    # a node ENI carrying the pod IP as a VPC-CNI secondary address
    s._clients["ec2:us-east-1"] = _ec2_client(
        [{"NetworkInterfaceId": "eni-node", "InterfaceType": "interface", "VpcId": "vpc-1",
          "PrivateIpAddresses": [{"PrivateIpAddress": "10.0.0.5"},
                                 {"PrivateIpAddress": "10.0.9.9"}], "Groups": []}],
        sgs=[{"GroupId": "sg-1", "IpPermissions": PUB_SG["sg-1"]}])
    s._clients["elbv2:us-east-1"] = _elbv2_ip_target("10.0.9.9")
    for svc, key in (("elb", "LoadBalancerDescriptions"), ("cloudfront", "DistributionList"),
                     ("apigateway", "items"), ("apigatewayv2", "Items")):
        s._clients[f"{svc}:us-east-1"] = _empty_pager_client(key)
    with patch("builtins.print"):
        s._check_exposure()
    node = f"lb/{LB_ARN}"
    # internet -> LB -> pod, and the pod's HAS_ROLE / SA CAN_ASSUME emitted inline (VULN-less-safe)
    assert any(e["dst"] == POD and e["kind"] == "TARGETS" for e in g.out_edges(node))
    assert POD in s._exposed_kube
    assert any(e["dst"] == SA_NODE for e in g.out_edges(POD, ["HAS_ROLE"]))
    assert any(e["dst"] == IRSA_ROLE for e in g.out_edges(SA_NODE, ["CAN_ASSUME"]))
    assert IMG in s._reachable_workloads
    # the full cross-plane path is now discoverable from internet
    is_uncond = lambda e: not e["props"].get("conditioned") and not e["props"].get("has_condition")
    paths = C.enumerate_paths(g, {"internet"}, aws_admin, C.crown_nodes(g), is_uncond,
                              D.is_exploitable, lambda nid: nid in set())
    assert any(p.terminal_kind == "admin" and POD in p.nodes for p in paths)


# ═══════════════════════════════════════════════════════════════════════════════
# Adversarial-verify regressions (10 confirmed findings)
# ═══════════════════════════════════════════════════════════════════════════════
import aws_kube as K                                                          # noqa: E402


# #1 [HIGH] — `User system:anonymous` cluster-admin must be caught (KSPM-01), not slip past
# both the Group-only anonymous check and the KSPM-03 system:* skip.
def test_user_system_anonymous_cluster_admin_flagged():
    crs = [{"metadata": {"name": "cluster-admin"},
            "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]}]
    crbs = [{"metadata": {"name": "anon-admin"}, "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
             "subjects": [{"kind": "User", "name": "system:anonymous"}]}]   # a USER, not a Group
    ev = K.evaluate_rbac(crs, crbs)
    assert any(a["subject"]["name"] == "system:anonymous" for a in ev["anonymous"])
    s = _scanner()
    _run_kspm(s, crs=crs, crbs=crbs)
    assert "FAIL" in _status(s, "KSPM-01")                    # not a silent pass


# #2 [MED] — a privileged initContainer / ephemeralContainer is an escape primitive too.
def test_pod_security_covers_init_and_ephemeral_containers():
    pod = {"spec": {"containers": [{"name": "app", "securityContext": {}}],
                    "initContainers": [{"name": "init", "securityContext": {
                        "privileged": True, "capabilities": {"add": ["SYS_ADMIN"]}}}]}}
    issues = K.pod_security_findings(pod, {"SYS_ADMIN"})
    assert any("privileged:init" in i for i in issues) and any("SYS_ADMIN" in i for i in issues)
    eph = {"spec": {"containers": [], "ephemeralContainers": [
        {"name": "dbg", "securityContext": {"privileged": True}}]}}
    assert any("privileged:dbg" in i for i in K.pod_security_findings(eph, set()))


# #3 [MED] — the two-policy (separate deny-ingress + deny-egress) default-deny form counts.
def test_two_policy_default_deny_recognized():
    netpols = [{"metadata": {"namespace": "prod"}, "spec": {"podSelector": {}, "policyTypes": ["Ingress"]}},
               {"metadata": {"namespace": "prod"}, "spec": {"podSelector": {}, "policyTypes": ["Egress"]}}]
    assert K.namespace_has_default_deny(netpols, "prod") is True
    # only one direction covered -> not default-deny
    assert K.namespace_has_default_deny(netpols[:1], "prod") is False


# #4 [MED] — a denied list_associated_access_policies fails open to INFO, not a silent miss.
def test_denied_associated_policies_infos_not_silent():
    parn = f"arn:aws:iam::{OWN}:role/eks-admins"
    s = _scanner()
    eks = _eks(entries=[parn])
    eks.get_paginator.side_effect = lambda op: (_ for _ in ()).throw(RuntimeError("denied")) \
        if op == "list_associated_access_policies" else _pager(
            {"list_access_entries": "accessEntries"}.get(op, "x"), [parn] if op == "list_access_entries" else [])
    s._check_eks_kiem(eks, CLUSTER, _cluster())
    info = [r for r in s.results if r.check_id == "KIEM-01" and r.status == "INFO"]
    assert info and "ListAssociatedAccessPolicies" in info[0].message


# #5/#9 [MED] — a denied NetworkPolicy read must NOT phantom-FAIL KSPM-06 for every namespace.
def test_kspm06_denied_netpol_read_fail_open():
    s = _scanner()
    # k8s_get: namespaces returns items, networkpolicies returns None (denied)
    def get(ctx, path):
        if path == "/api/v1/namespaces":
            return {"items": [_ns("prod")]}
        if path == "/apis/networking.k8s.io/v1/networkpolicies":
            return None
        return {"items": []}
    s._k8s_get = get
    s._check_kspm(CLUSTER, _reachable_cluster(), CLUSTER_ARN, K8S_ADMIN)
    assert not _status(s, "KSPM-06")                          # no phantom FAIL
    assert "INFO" in _status(s, "KSPM-00")


# #6 [MED] — KIEM-04 fires from the DATA section even when VULN is deselected (replay front-loaded).
def test_kiem04_fires_without_vuln_replay():
    from unittest.mock import patch
    s = _scanner()
    s.account = OWN
    g = aws_graph.SecurityGraph()
    g.add_node("internet", "InternetSource")
    aws_admin = f"capability:admin:{OWN}"
    g.add_node(aws_admin, "AdminCapability")
    g.add_node(IRSA_ROLE, "IAMRole", name="app-irsa")
    g.add_edge(IRSA_ROLE, aws_admin, "CAN_PRIVESC_TO", conditioned=False)
    s.graph = g
    # only the stash exists (as EKS#18 produced) — no VULN#40 replay ran
    s._kube_payloads = [{"kind": "sa_role", "sa_node": SA_NODE, "cluster_arn": CLUSTER_ARN,
                         "namespace": "prod", "sa_name": "app", "role_arn": IRSA_ROLE, "basis": "irsa"}]
    s._collect_macie = lambda g: set()
    s._collect_access_analyzer = lambda g: None
    s._build_can_read_data = lambda g, crown: None
    s._collect_dspm = lambda g: None
    with patch("builtins.print"):
        s._check_data()                                       # front-loads _replay_kube_edges
    assert "FAIL" in _status(s, "KIEM-04")                    # SA -> IRSA role -> AWS admin


# #7 [LOW] — a digest-pinned spec image is used even when the running imageID lacks a digest.
def test_pod_image_digest_from_spec_when_imageid_untagged():
    s = _scanner()
    dg = f"{OWN}.dkr.ecr.us-east-1.amazonaws.com/api@sha256:beef"
    pod = {"metadata": {"name": "api-0", "namespace": "prod"},
           "spec": {"serviceAccountName": "app", "containers": [{"name": "api", "image": dg}]},
           "status": {"podIP": "10.0.9.9",
                      "containerStatuses": [{"name": "api",   # imageID WITHOUT a digest
                                             "imageID": f"{OWN}.dkr.ecr.us-east-1.amazonaws.com/api"}]}}
    s._stash_kube_workload_graph(CLUSTER_ARN, "vpc-1", [pod], [])
    ps = [p for p in s._kube_payloads if p["kind"] == "pod_sa"][0]
    assert ps["image_nodes"] and any("@sha256:beef" in n for n, _, _ in ps["image_nodes"])


# #8/#10 [MED/LOW] — pod IP is keyed by (cluster_vpc, ip): a same-IP pod in another VPC never binds.
def test_pod_ip_keyed_by_cluster_vpc():
    s = _scanner()
    s._kube_payloads = [
        {"kind": "pod_sa", "pod_node": POD, "cluster_vpc": "vpc-A", "private_ip": "10.0.9.9",
         "sa_node": SA_NODE, "namespace": "prod", "pod_name": "api-0", "sa_name": "app",
         "image_nodes": [], "cluster_arn": CLUSTER_ARN}]
    # drive just the map-build via _check_exposure with an ENI in vpc-B carrying the same IP
    from unittest.mock import patch
    s.graph = aws_graph.SecurityGraph()
    s.graph.add_node(f"capability:admin:{OWN}", "AdminCapability")
    s._get_iam_principals = lambda: []
    s._cred_report = []
    s._cred_report_ok = False
    s._clients["ec2:us-east-1"] = _ec2_client(
        [{"NetworkInterfaceId": "eni-b", "InterfaceType": "interface", "VpcId": "vpc-B",
          "PrivateIpAddresses": [{"PrivateIpAddress": "10.0.9.9"}], "Groups": []}])
    for svc, key in (("elbv2", "LoadBalancers"), ("elb", "LoadBalancerDescriptions"),
                     ("cloudfront", "DistributionList"), ("apigateway", "items"),
                     ("apigatewayv2", "Items")):
        s._clients[f"{svc}:us-east-1"] = _empty_pager_client(key)
    with patch("builtins.print"):
        s._check_exposure()
    # the vpc-B ENI must NOT bind the vpc-A pod
    assert ("vpc-B", "10.0.9.9") not in s._ip_to_kube_pod
    assert s._ip_to_kube_pod == {}
