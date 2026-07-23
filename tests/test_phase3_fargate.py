"""Phase 3 — Fargate + EKS-Fargate image side-scan folded into the attack-path graph.

B1 (this file, part 1): enumerate RUNNING Fargate tasks -> stash -> replay (node +
RUNS_IMAGE + HAS_ROLE) survives the IAMPRIVESC graph clobber. Offline: MagicMock ECS
clients via s._clients, no boto3."""
import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import aws_live_scanner as A
import aws_correlate
import aws_graph
from test_live_scanner import MockPaginator, make_scanner

OWN = "123456789012"
CLUSTER = f"arn:aws:ecs:us-east-1:{OWN}:cluster/prod"
TASK = f"arn:aws:ecs:us-east-1:{OWN}:task/prod/abc123"
TASK_ROLE = f"arn:aws:iam::{OWN}:role/app-task-role"
TD_ARN = f"arn:aws:ecs:us-east-1:{OWN}:task-definition/api:7"


def _task(launch="FARGATE", cap=None, image=None, ip="10.0.1.50", eni="eni-aaa",
          role_in_task=None):
    t = {"taskArn": TASK, "taskDefinitionArn": TD_ARN, "group": "service:api",
         "attachments": [{"type": "ElasticNetworkInterface", "details": [
             {"name": "networkInterfaceId", "value": eni},
             {"name": "privateIPv4Address", "value": ip},
             {"name": "subnetId", "value": "subnet-1"}]}],
         "containers": [{"name": "api", "image": image}] if image else []}
    if launch:
        t["launchType"] = launch
    if cap:
        t["capacityProviderName"] = cap
    if role_in_task:
        t["overrides"] = {"taskRoleArn": role_in_task}
    return t


def _ecs_client(tasks, td=None):
    ecs = MagicMock()
    ecs.get_paginator.return_value = MockPaginator("taskArns", [t["taskArn"] for t in tasks])
    ecs.describe_tasks.return_value = {"tasks": tasks}
    ecs.describe_task_definition.return_value = {"taskDefinition": td or {
        "family": "api", "taskRoleArn": TASK_ROLE, "networkMode": "awsvpc",
        "containerDefinitions": [{"name": "api",
                                  "image": f"{OWN}.dkr.ecr.us-east-1.amazonaws.com/api@sha256:deadbeef"}]}}
    return ecs


def _scanner(tasks, td=None):
    s = make_scanner(["ECS"])
    s.graph = aws_graph.SecurityGraph()
    s._clients["ecs:us-east-1"] = _ecs_client(tasks, td)
    return s


# ── enumeration + launch-type re-guard ───────────────────────────────────────
def test_fargate_task_stashed():
    s = _scanner([_task(image=f"{OWN}.dkr.ecr.us-east-1.amazonaws.com/api@sha256:deadbeef")])
    s._check_fargate_tasks(s._clients["ecs:us-east-1"], [CLUSTER])
    assert len(s._fargate_payloads) == 1
    pl = s._fargate_payloads[0]
    assert pl["node_id"] == TASK and pl["task_role_arn"] == TASK_ROLE
    assert pl["eni_ids"] == ["eni-aaa"] and pl["private_ips"] == ["10.0.1.50"]
    assert pl["node_props"]["launch_type"] == "FARGATE"
    # FARGATE-01 inventory result emitted
    assert any(r.check_id == "FARGATE-01" for r in s.results)


def test_capacity_provider_task_accepted_ec2_rejected():
    s = _scanner([_task(launch=None, cap="FARGATE_SPOT",
                        image=f"{OWN}.dkr.ecr.us-east-1.amazonaws.com/api@sha256:d")])
    s._check_fargate_tasks(s._clients["ecs:us-east-1"], [CLUSTER])
    assert len(s._fargate_payloads) == 1                     # capacity-provider Fargate accepted

    s2 = _scanner([_task(launch="EC2",
                         image=f"{OWN}.dkr.ecr.us-east-1.amazonaws.com/api@sha256:d")])
    s2._check_fargate_tasks(s2._clients["ecs:us-east-1"], [CLUSTER])
    assert s2._fargate_payloads == []                        # EC2 launch type skipped


def test_runs_image_dual_emit_and_digest_from_tag():
    # a :tag image resolves to a digest via ecr.describe_images, then dual-emits both node ids
    s = make_scanner(["ECS"])
    s.graph = aws_graph.SecurityGraph()
    ecs = _ecs_client([_task(image=f"{OWN}.dkr.ecr.us-east-1.amazonaws.com/api:v9")],
                      td={"family": "api", "taskRoleArn": TASK_ROLE, "containerDefinitions": []})
    s._clients["ecs:us-east-1"] = ecs
    ecr = MagicMock()
    ecr.describe_images.return_value = {"imageDetails": [{"imageDigest": "sha256:cafe"}]}
    s._clients["ecr:us-east-1"] = ecr
    s._check_fargate_tasks(ecs, [CLUSTER])
    nodes = [n for n, _, _ in s._fargate_payloads[0]["image_nodes"]]
    assert f"{OWN}.dkr.ecr.us-east-1.amazonaws.com/api@sha256:cafe" in nodes
    assert f"arn:aws:ecr:us-east-1:{OWN}:repository/api/sha256:cafe" in nodes


def test_task_override_role_wins_over_taskdef():
    s = _scanner([_task(image=f"{OWN}.dkr.ecr.us-east-1.amazonaws.com/api@sha256:d",
                        role_in_task=f"arn:aws:iam::{OWN}:role/override-role")])
    s._check_fargate_tasks(s._clients["ecs:us-east-1"], [CLUSTER])
    assert s._fargate_payloads[0]["task_role_arn"] == f"arn:aws:iam::{OWN}:role/override-role"


def test_non_ecr_image_no_image_node():
    s = _scanner([_task(image="nginx:latest")],
                 td={"family": "api", "taskRoleArn": TASK_ROLE, "containerDefinitions": []})
    s._check_fargate_tasks(s._clients["ecs:us-east-1"], [CLUSTER])
    assert s._fargate_payloads[0]["image_nodes"] == []       # Docker Hub -> no ECRImage node


# ── replay survives the IAMPRIVESC graph clobber ─────────────────────────────
def test_replay_survives_clobber_and_is_idempotent():
    s = _scanner([_task(image=f"{OWN}.dkr.ecr.us-east-1.amazonaws.com/api@sha256:deadbeef")])
    s._check_fargate_tasks(s._clients["ecs:us-east-1"], [CLUSTER])
    # simulate IAMPRIVESC#36 hard-replacing the graph
    s.graph = aws_graph.SecurityGraph()
    s._replay_fargate_edges()
    s._replay_fargate_edges()                                # idempotent
    g = s.graph
    assert g.node(TASK)["kind"] == "ECSFargateTask"
    # dual-emit: RUNS_IMAGE to BOTH ecr_image_node_ids conventions (repoUri@digest + ARN),
    # idempotent across replays (still 2, not 4)
    dsts = {e["dst"] for e in g.out_edges(TASK, ["RUNS_IMAGE"])}
    assert dsts == {f"{OWN}.dkr.ecr.us-east-1.amazonaws.com/api@sha256:deadbeef",
                    f"arn:aws:ecr:us-east-1:{OWN}:repository/api/sha256:deadbeef"}
    hr = g.out_edges(TASK, ["HAS_ROLE"])
    assert len(hr) == 1 and hr[0]["dst"] == TASK_ROLE


def test_fargate_task_not_in_exploit_kinds():
    # invariant: no aws_correlate change — the RUNS_IMAGE ex-gate carries exploitability
    assert "ECSFargateTask" not in aws_correlate._EXPLOIT_KINDS


def test_denied_list_tasks_degrades_to_info():
    s = make_scanner(["ECS"])
    s.graph = aws_graph.SecurityGraph()
    ecs = MagicMock()
    ecs.get_paginator.side_effect = RuntimeError("AccessDenied")
    s._clients["ecs:us-east-1"] = ecs
    s._check_fargate_tasks(ecs, [CLUSTER])
    assert s._fargate_payloads == []
    assert any(r.check_id == "FARGATE-01" and r.status == "INFO" for r in s.results)


# ═══════════════════════════════════════════════════════════════════════════════
# B2 — EXPOSURE wiring: ip-target -> FargateTask, ATTACK-01/02, reachable boost
# ═══════════════════════════════════════════════════════════════════════════════
from unittest.mock import patch                                             # noqa: E402
import aws_deepplane as D                                                   # noqa: E402
import aws_correlate as C                                                   # noqa: E402

ADMIN = f"capability:admin:{OWN}"
CROWN = "arn:aws:s3:::crown-data"
LB_ARN = f"arn:aws:elasticloadbalancing:us-east-1:{OWN}:loadbalancer/app/app-lb/50dc"
PUB_SG = {"sg-1": [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}
IMG = f"{OWN}.dkr.ecr.us-east-1.amazonaws.com/api@sha256:deadbeef"


def _alb(scheme="internet-facing", typ="application", sgids=("sg-1",)):
    return {"LoadBalancerArn": LB_ARN, "LoadBalancerName": "app-lb",
            "DNSName": "app-lb.elb.amazonaws.com", "Scheme": scheme, "Type": typ,
            "State": {"Code": "active"}, "SecurityGroups": list(sgids)}


def _elbv2_client(lbs, tgs=None, health=None, listeners=None):
    c = MagicMock()
    c.get_paginator.return_value = MockPaginator("LoadBalancers", lbs)
    c.describe_listeners.return_value = {"Listeners": listeners or [{"Port": 443, "Protocol": "HTTPS"}]}
    c.describe_target_groups.return_value = {"TargetGroups": tgs or []}
    c.describe_target_health.return_value = {"TargetHealthDescriptions": health or []}
    c.describe_rules.return_value = {"Rules": []}
    return c


def _l7_scanner():
    s = make_scanner(sections=["EXPOSURE"])
    g = aws_graph.SecurityGraph()
    g.add_node("internet", "InternetSource")
    s.graph = g
    s._ip_to_fargate = {}
    s._exposed_fargate = set()
    return s, g


def test_ip_target_resolves_to_fargate_task():
    s, g = _l7_scanner()
    s._ip_to_fargate = {("vpc-1", "10.0.1.50"): TASK}
    tgs = [{"TargetGroupArn": "arn:tg/1", "TargetType": "ip", "VpcId": "vpc-1"}]
    health = [{"Target": {"Id": "10.0.1.50"}, "TargetHealth": {"State": "healthy"}}]
    s._clients["elbv2:us-east-1"] = _elbv2_client([_alb()], tgs=tgs, health=health)
    found = s._l7_elbv2(g, "internet", PUB_SG, {}, set(), {})   # ip_to_instance empty
    node = f"lb/{LB_ARN}"
    assert found
    assert any(e["dst"] == TASK and e["kind"] == "TARGETS" for e in g.out_edges(node))
    assert TASK in s._exposed_fargate


def test_ip_target_cross_vpc_binds_correct_task():
    s, g = _l7_scanner()
    other = TASK.replace("abc123", "other")
    s._ip_to_fargate = {("vpc-A", "10.0.1.50"): TASK, ("vpc-B", "10.0.1.50"): other}
    tgs = [{"TargetGroupArn": "arn:tg/1", "TargetType": "ip", "VpcId": "vpc-A"}]
    health = [{"Target": {"Id": "10.0.1.50"}, "TargetHealth": {"State": "healthy"}}]
    s._clients["elbv2:us-east-1"] = _elbv2_client([_alb()], tgs=tgs, health=health)
    s._l7_elbv2(g, "internet", PUB_SG, {}, set(), {})
    assert s._exposed_fargate == {TASK}                        # vpc-A task, never the collision


def test_ec2_wins_over_fargate_at_same_key():
    s, g = _l7_scanner()
    s._ip_to_fargate = {("vpc-1", "10.0.0.5"): TASK}
    tgs = [{"TargetGroupArn": "arn:tg/1", "TargetType": "ip", "VpcId": "vpc-1"}]
    health = [{"Target": {"Id": "10.0.0.5"}, "TargetHealth": {"State": "healthy"}}]
    s._clients["elbv2:us-east-1"] = _elbv2_client([_alb()], tgs=tgs, health=health)
    exposed = set()
    s._l7_elbv2(g, "internet", PUB_SG, {("vpc-1", "10.0.0.5"): "i-ec2"}, exposed, {})
    assert "i-ec2" in exposed and s._exposed_fargate == set()   # EC2 consulted first


def _full_fargate_graph(kev=True):
    g = aws_graph.SecurityGraph()
    g.add_node("internet", "InternetSource")
    g.add_node(f"lb/{LB_ARN}", "LoadBalancer", name="app-lb")
    g.add_node(TASK, "ECSFargateTask", cluster="prod")
    g.add_node(TASK_ROLE, "IAMRole", name="app-task-role")
    g.add_node(ADMIN, "AdminCapability")
    g.add_node(CROWN, "S3Bucket", name="crown-data", crown_jewel=True)
    g.add_node(IMG, "ECRImage", repository="api")
    g.add_edge("internet", f"lb/{LB_ARN}", "EXPOSED_TO", basis="l7-elbv2")
    g.add_edge(f"lb/{LB_ARN}", TASK, "TARGETS", basis="l7-elbv2-ip-fargate", target_type="ip")
    g.add_edge(TASK, TASK_ROLE, "HAS_ROLE", role_type="task")
    g.add_edge(TASK, IMG, "RUNS_IMAGE", container="api", scan_source="ecs-fargate")
    g.add_edge(TASK_ROLE, ADMIN, "CAN_PRIVESC_TO", conditioned=False)
    g.add_edge(TASK_ROLE, CROWN, "CAN_READ_DATA", conditioned=False)
    if kev:
        g.add_node("CVE-2021-44228", "Vulnerability", kev=True)
        g.add_edge(IMG, "CVE-2021-44228", "HAS_VULN", cve="CVE-2021-44228", kev=True,
                   exploit_available="YES")
    return g


def _enum(g):
    is_uncond = lambda e: not e["props"].get("conditioned") and not e["props"].get("has_condition")
    threatened = {e["dst"] for e in g.edges("THREAT_ON")}
    return C.enumerate_paths(g, {"internet"}, ADMIN, C.crown_nodes(g),
                             is_uncond, D.is_exploitable, lambda nid: nid in threatened)


def test_enumerate_paths_finds_fargate_admin_and_data():
    paths = _enum(_full_fargate_graph(kev=True))
    assert {p.terminal_kind for p in paths} == {"admin", "data"}
    assert all(p.severity == "CRITICAL" for p in paths)
    assert all(TASK in p.nodes for p in paths)                 # image CVE inherited via RUNS_IMAGE


def test_data_path_is_cve_gated():
    # drop the image CVE -> the data-terminal path disappears (admin needs no vuln)
    paths = _enum(_full_fargate_graph(kev=False))
    assert {p.terminal_kind for p in paths} == {"admin"}


def _ec2_client(enis, sgs=None):
    ec2 = MagicMock()
    pages = {"describe_network_interfaces": {"NetworkInterfaces": enis},
             "describe_security_groups": {"SecurityGroups": sgs or []},
             "describe_route_tables": {"RouteTables": []},
             "describe_network_acls": {"NetworkAcls": []},
             "describe_instances": {"Reservations": []}}

    def paginator(op):
        p = MagicMock()
        p.paginate.return_value = [pages.get(op, {})]
        return p
    ec2.get_paginator.side_effect = paginator
    return ec2


def _empty_pager(key):
    c = MagicMock()
    c.get_paginator.return_value.paginate.return_value = [{key: []}]
    return c


def test_fargate_behind_alb_fires_attack01_and_boost():
    s = make_scanner(sections=["EXPOSURE"])
    g = aws_graph.SecurityGraph()
    g.add_node(ADMIN, "AdminCapability")
    g.add_node(TASK_ROLE, "IAMRole", name="app-task-role")
    g.add_edge(TASK_ROLE, ADMIN, "CAN_PRIVESC_TO", conditioned=False)
    s.graph = g
    s._get_iam_principals = lambda: []
    s._cred_report = []
    s._cred_report_ok = False
    s._fargate_payloads = [{
        "node_id": TASK, "node_props": {"cluster": "prod"}, "task_role_arn": TASK_ROLE,
        "image_nodes": [(IMG, {"repository": "api", "digest": "sha256:deadbeef"}, "api")],
        "eni_ids": ["eni-f1"], "private_ips": ["10.0.1.50"], "subnet_id": "subnet-1",
        "cluster": "prod"}]
    s._clients["ec2:us-east-1"] = _ec2_client(
        [{"NetworkInterfaceId": "eni-f1", "InterfaceType": "interface", "VpcId": "vpc-1",
          "PrivateIpAddresses": [{"PrivateIpAddress": "10.0.1.50"}], "Groups": []}],
        sgs=[{"GroupId": "sg-1", "IpPermissions": PUB_SG["sg-1"]}])
    tgs = [{"TargetGroupArn": "arn:tg/1", "TargetType": "ip", "VpcId": "vpc-1"}]
    health = [{"Target": {"Id": "10.0.1.50"}, "TargetHealth": {"State": "healthy"}}]
    s._clients["elbv2:us-east-1"] = _elbv2_client([_alb()], tgs=tgs, health=health)
    for svc, key in (("elb", "LoadBalancerDescriptions"), ("cloudfront", "DistributionList"),
                     ("apigateway", "items"), ("apigatewayv2", "Items")):
        s._clients[f"{svc}:us-east-1"] = _empty_pager(key)
    with patch("builtins.print"):
        s._check_exposure()
    node = f"lb/{LB_ARN}"
    assert any(e["dst"] == TASK and e["kind"] == "TARGETS" for e in g.out_edges(node))
    assert TASK in s._exposed_fargate
    assert {r.status for r in s.results if r.check_id == "ATTACK-01"} == {"FAIL"}
    assert IMG in s._reachable_workloads                       # boost lands on the IMAGE node


def test_correlate_flagship_fargate_attack02():
    s = make_scanner(sections=["DATA"])
    g = _full_fargate_graph(kev=True)
    s.graph = g
    with patch("builtins.print"):
        s._correlate_flagship(g)
    fa = [r for r in s.results if r.check_id == "ATTACK-02"]
    assert fa and fa[0].status == "FAIL"
    assert "Fargate task" in fa[0].message


# ═══════════════════════════════════════════════════════════════════════════════
# B4 — EKS-Fargate profiles (documented agentless boundary, EKS-07)
# ═══════════════════════════════════════════════════════════════════════════════
def test_eks_fargate_profile_boundary():
    s = make_scanner(sections=["EKS"])
    eks = MagicMock()
    eks.list_clusters.return_value = {"clusters": ["prod"]}
    eks.describe_cluster.return_value = {"cluster": {
        "resourcesVpcConfig": {"endpointPublicAccess": False}, "logging": {},
        "encryptionConfig": [{"resources": ["secrets"]}], "version": "1.29"}}
    eks.list_nodegroups.return_value = {"nodegroups": []}
    eks.list_fargate_profiles.return_value = {"fargateProfileNames": ["fp-default"]}
    eks.describe_fargate_profile.return_value = {"fargateProfile": {
        "fargateProfileName": "fp-default",
        "podExecutionRoleArn": f"arn:aws:iam::{OWN}:role/eks-pod-exec",
        "selectors": [{"namespace": "prod"}]}}
    s._clients["eks:us-east-1"] = eks
    with patch("builtins.print"):
        s._check_eks()
    e7 = [r for r in s.results if r.check_id == "EKS-07"]
    assert len(e7) == 1 and e7[0].status == "INFO"
    assert "eks-pod-exec" in e7[0].message and "KSPM" in e7[0].message
    # no graph node is created for the inert profile
    assert s.graph is None or s.graph.node(f"arn:aws:eks:us-east-1:{OWN}:fargateprofile/prod/fp-default") is None


def test_eks_no_fargate_profiles_no_eks07():
    s = make_scanner(sections=["EKS"])
    eks = MagicMock()
    eks.list_clusters.return_value = {"clusters": ["prod"]}
    eks.describe_cluster.return_value = {"cluster": {
        "resourcesVpcConfig": {"endpointPublicAccess": False}, "logging": {},
        "encryptionConfig": [{"resources": ["secrets"]}], "version": "1.29"}}
    eks.list_nodegroups.return_value = {"nodegroups": []}
    eks.list_fargate_profiles.return_value = {"fargateProfileNames": []}
    s._clients["eks:us-east-1"] = eks
    with patch("builtins.print"):
        s._check_eks()
    assert not [r for r in s.results if r.check_id == "EKS-07"]


# ═══════════════════════════════════════════════════════════════════════════════
# Adversarial-verify regressions (5 confirmed findings)
# ═══════════════════════════════════════════════════════════════════════════════
class _RecordingPaginator:
    """Records the paginate() kwargs so a test can assert the server-side filter is gone."""
    def __init__(self, key, items, sink):
        self._key, self._items, self._sink = key, items, sink

    def paginate(self, **kwargs):
        self._sink.append(kwargs)
        return [{self._key: self._items}]


# #1 [HIGH] — capacity-provider (FARGATE_SPOT) tasks must NOT be dropped by a server-side
# launchType filter; list_tasks must be called WITHOUT launchType, classify client-side.
def test_list_tasks_omits_launchtype_and_keeps_capacity_provider_task():
    s = make_scanner(["ECS"])
    s.graph = aws_graph.SecurityGraph()
    calls = []
    ecs = MagicMock()
    ecs.get_paginator.return_value = _RecordingPaginator("taskArns", [TASK, TASK + "-ec2"], calls)
    # a FARGATE_SPOT task (launchType UNSET) + an EC2 task in the SAME describe_tasks batch
    spot = _task(launch=None, cap="FARGATE_SPOT",
                 image=f"{OWN}.dkr.ecr.us-east-1.amazonaws.com/api@sha256:d")
    ec2 = _task(launch="EC2", image=f"{OWN}.dkr.ecr.us-east-1.amazonaws.com/api@sha256:d")
    ec2["taskArn"] = TASK + "-ec2"
    ecs.describe_tasks.return_value = {"tasks": [spot, ec2]}
    ecs.describe_task_definition.return_value = {"taskDefinition": {
        "family": "api", "taskRoleArn": TASK_ROLE, "containerDefinitions": []}}
    s._clients["ecs:us-east-1"] = ecs
    s._check_fargate_tasks(ecs, [CLUSTER])
    # the enumeration query must NOT pin launchType (that would drop capacity-provider tasks)
    assert calls and all("launchType" not in c for c in calls)
    # only the FARGATE_SPOT task is stashed; the EC2 task is rejected client-side
    ids = [pl["node_id"] for pl in s._fargate_payloads]
    assert ids == [TASK]


# #2 [MED] — the running container's resolved imageDigest keys the digest node WITHOUT
# needing ecr:DescribeImages (which may be denied).
def test_running_image_digest_used_when_describe_images_denied():
    s = make_scanner(["ECS"])
    s.graph = aws_graph.SecurityGraph()
    t = _task(image=f"{OWN}.dkr.ecr.us-east-1.amazonaws.com/api:latest")
    t["containers"][0]["imageDigest"] = "sha256:beef"          # resolved running digest
    ecs = _ecs_client([t], td={"family": "api", "taskRoleArn": TASK_ROLE,
                               "containerDefinitions": []})
    s._clients["ecs:us-east-1"] = ecs
    ecr = MagicMock()
    ecr.describe_images.side_effect = RuntimeError("AccessDenied: ecr:DescribeImages")
    s._clients["ecr:us-east-1"] = ecr
    s._check_fargate_tasks(ecs, [CLUSTER])
    nodes = {n for n, _, _ in s._fargate_payloads[0]["image_nodes"]}
    # digest-keyed nodes (both conventions) — NOT a :latest tag-keyed orphan
    assert f"{OWN}.dkr.ecr.us-east-1.amazonaws.com/api@sha256:beef" in nodes
    assert not any(n.endswith(":latest") for n in nodes)


# #3 [LOW] — a denied DescribeTasks degrades to INFO, never a silent drop.
def test_describe_tasks_denied_emits_info():
    s = make_scanner(["ECS"])
    s.graph = aws_graph.SecurityGraph()
    ecs = MagicMock()
    ecs.get_paginator.return_value = MockPaginator("taskArns", [TASK])
    ecs.describe_tasks.side_effect = RuntimeError("AccessDenied: ecs:DescribeTasks")
    s._clients["ecs:us-east-1"] = ecs
    s._check_fargate_tasks(ecs, [CLUSTER])
    assert s._fargate_payloads == []
    infos = [r for r in s.results if r.check_id == "FARGATE-01" and r.status == "INFO"]
    assert infos and "DescribeTasks denied" in infos[0].message


# #4/#5 — the exposed Fargate task's RUNS_IMAGE + HAS_ROLE are emitted INLINE in EXPOSURE,
# so the attack path is graph-complete BEFORE the VULN replay (i.e. VULN can be deselected).
def test_exposure_emits_has_role_and_runs_image_without_vuln_replay():
    s = make_scanner(sections=["EXPOSURE"])
    g = aws_graph.SecurityGraph()
    g.add_node(ADMIN, "AdminCapability")
    g.add_node(TASK_ROLE, "IAMRole", name="app-task-role")
    g.add_edge(TASK_ROLE, ADMIN, "CAN_PRIVESC_TO", conditioned=False)
    s.graph = g
    s._get_iam_principals = lambda: []
    s._cred_report = []
    s._cred_report_ok = False
    s._fargate_payloads = [{
        "node_id": TASK, "node_props": {"cluster": "prod"}, "task_role_arn": TASK_ROLE,
        "image_nodes": [(IMG, {"repository": "api", "digest": "sha256:deadbeef"}, "api")],
        "eni_ids": ["eni-f1"], "private_ips": ["10.0.1.50"], "subnet_id": "subnet-1",
        "cluster": "prod"}]
    s._clients["ec2:us-east-1"] = _ec2_client(
        [{"NetworkInterfaceId": "eni-f1", "InterfaceType": "interface", "VpcId": "vpc-1",
          "PrivateIpAddresses": [{"PrivateIpAddress": "10.0.1.50"}], "Groups": []}],
        sgs=[{"GroupId": "sg-1", "IpPermissions": PUB_SG["sg-1"]}])
    tgs = [{"TargetGroupArn": "arn:tg/1", "TargetType": "ip", "VpcId": "vpc-1"}]
    health = [{"Target": {"Id": "10.0.1.50"}, "TargetHealth": {"State": "healthy"}}]
    s._clients["elbv2:us-east-1"] = _elbv2_client([_alb()], tgs=tgs, health=health)
    for svc, key in (("elb", "LoadBalancerDescriptions"), ("cloudfront", "DistributionList"),
                     ("apigateway", "items"), ("apigatewayv2", "Items")):
        s._clients[f"{svc}:us-east-1"] = _empty_pager(key)
    with patch("builtins.print"):
        s._check_exposure()                    # NOTE: no _replay_fargate_edges() called
    # edges present now -> _correlate_flagship / enumerate_paths (later sections) see the path
    assert any(e["dst"] == TASK_ROLE and e["kind"] == "HAS_ROLE" for e in g.out_edges(TASK))
    assert any(e["dst"] == IMG and e["kind"] == "RUNS_IMAGE" for e in g.out_edges(TASK))
    # and the path is now discoverable
    paths = _enum(g)
    assert any(p.terminal_kind == "admin" and TASK in p.nodes for p in paths)
