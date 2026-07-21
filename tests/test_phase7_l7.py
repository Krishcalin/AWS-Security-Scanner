"""Phase 7 Batch 3 — L7 reachability un-defer: internet-facing ALB/NLB/classic-ELB/
CloudFront/API-Gateway -> LoadBalancer/front node + TARGETS edges + EXPOSURE-03, plus
the reachable_service HAS_VULN tag and the RUNS_IMAGE clobber-safe replay. Offline:
MagicMock clients (no boto3, no AWS)."""
import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_live_scanner import make_scanner
from aws_graph import SecurityGraph

ACCT = "123456789012"
LB_ARN = f"arn:aws:elasticloadbalancing:us-east-1:{ACCT}:loadbalancer/app/app-lb/50dc"
PUB_SG = {"sg-1": [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                   "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}


def _l7_scanner():
    s = make_scanner(sections=["EXPOSURE"])
    s.account = ACCT
    g = SecurityGraph()
    g.add_node("internet", "InternetSource")
    s.graph = g
    return s, g


def _pager(key, items):
    p = MagicMock()
    p.paginate.return_value = [{key: items}]
    return p


def _status(s, cid):
    return {r.status for r in s.results if r.check_id == cid}


def _alb(scheme="internet-facing", typ="application", state="active", sgids=("sg-1",)):
    return {"LoadBalancerArn": LB_ARN, "LoadBalancerName": "app-lb",
            "DNSName": "app-lb-123.elb.amazonaws.com", "Scheme": scheme, "Type": typ,
            "State": {"Code": state}, "SecurityGroups": list(sgids)}


def _elbv2_client(lbs, listeners=None, tgs=None, health=None):
    c = MagicMock()
    c.get_paginator.return_value = _pager("LoadBalancers", lbs)
    c.describe_listeners.return_value = {
        "Listeners": listeners if listeners is not None else [{"Port": 443, "Protocol": "HTTPS"}]}
    c.describe_target_groups.return_value = {"TargetGroups": tgs or []}
    c.describe_target_health.return_value = {"TargetHealthDescriptions": health or []}
    return c


# ── ALB / NLB ─────────────────────────────────────────────────────────────────
def test_alb_internet_facing_instance_target():
    s, g = _l7_scanner()
    tgs = [{"TargetGroupArn": "arn:tg/1", "TargetType": "instance"}]
    health = [{"Target": {"Id": "i-aaa", "Port": 443}, "TargetHealth": {"State": "healthy"}}]
    s._clients["elbv2:us-east-1"] = _elbv2_client([_alb()], tgs=tgs, health=health)
    exposed = set()
    found = s._l7_elbv2(g, "internet", PUB_SG, {}, exposed, {})
    node = f"lb/{LB_ARN}"
    assert found
    assert g.node(node) and g.node(node)["kind"] == "LoadBalancer"
    assert any(e["kind"] == "EXPOSED_TO" and e["dst"] == node for e in g.out_edges("internet"))
    tarn = s._instance_arn("i-aaa")
    assert any(e["dst"] == tarn and e["kind"] == "TARGETS" for e in g.out_edges(node))
    assert "i-aaa" in exposed                       # feeds the LB-fronted ATTACK-01 loop
    assert "FAIL" in _status(s, "EXPOSURE-03")


def test_internal_alb_skipped():
    s, g = _l7_scanner()
    s._clients["elbv2:us-east-1"] = _elbv2_client([_alb(scheme="internal")])
    found = s._l7_elbv2(g, "internet", PUB_SG, {}, set(), {})
    assert not found
    assert not _status(s, "EXPOSURE-03")
    assert g.node(f"lb/{LB_ARN}") is None


def test_gateway_lb_skipped():
    s, g = _l7_scanner()
    s._clients["elbv2:us-east-1"] = _elbv2_client([_alb(typ="gateway")])
    assert not s._l7_elbv2(g, "internet", PUB_SG, {}, set(), {})


def test_alb_sg_does_not_open_listener_port_skipped():
    s, g = _l7_scanner()
    # SG opens 80, but the only listener is on 443 -> not internet-open at the LB
    sg = {"sg-1": [{"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}
    s._clients["elbv2:us-east-1"] = _elbv2_client([_alb()])
    found = s._l7_elbv2(g, "internet", sg, {}, set(), {})
    assert not found
    assert g.node(f"lb/{LB_ARN}") is None


def test_nlb_sg_less_internet_facing_counts():
    s, g = _l7_scanner()
    nlb = _alb(typ="network", sgids=())            # NLBs are frequently SG-less
    s._clients["elbv2:us-east-1"] = _elbv2_client(
        [nlb], listeners=[{"Port": 443, "Protocol": "TCP"}])
    found = s._l7_elbv2(g, "internet", {}, {}, set(), {})
    assert found                                    # scheme + active + listener suffices
    assert g.node(f"lb/{LB_ARN}")["kind"] == "LoadBalancer"


def test_draining_target_not_counted_info():
    s, g = _l7_scanner()
    tgs = [{"TargetGroupArn": "arn:tg/1", "TargetType": "instance"}]
    health = [{"Target": {"Id": "i-drain"}, "TargetHealth": {"State": "draining"}}]
    s._clients["elbv2:us-east-1"] = _elbv2_client([_alb()], tgs=tgs, health=health)
    exposed = set()
    found = s._l7_elbv2(g, "internet", PUB_SG, {}, exposed, {})
    assert found                                    # the LB itself is an internet entry
    assert "i-drain" not in exposed
    assert "INFO" in _status(s, "EXPOSURE-03")      # no resolvable in-rotation backend
    assert "FAIL" not in _status(s, "EXPOSURE-03")


def test_ip_target_resolves_via_eni():
    # F3: ip_to_instance is keyed by (vpc_id, addr) and resolved via the TG's VpcId.
    s, g = _l7_scanner()
    tgs = [{"TargetGroupArn": "arn:tg/1", "TargetType": "ip", "VpcId": "vpc-1"}]
    health = [{"Target": {"Id": "10.0.0.5"}, "TargetHealth": {"State": "healthy"}}]
    s._clients["elbv2:us-east-1"] = _elbv2_client([_alb()], tgs=tgs, health=health)
    exposed = set()
    found = s._l7_elbv2(g, "internet", PUB_SG, {("vpc-1", "10.0.0.5"): "i-ip1"}, exposed, {})
    assert found and "i-ip1" in exposed             # ip resolved to its ENI's instance in-VPC


def test_ip_target_unresolved_no_edge():
    s, g = _l7_scanner()
    tgs = [{"TargetGroupArn": "arn:tg/1", "TargetType": "ip", "VpcId": "vpc-1"}]
    health = [{"Target": {"Id": "203.0.113.9"}, "TargetHealth": {"State": "healthy"}}]
    s._clients["elbv2:us-east-1"] = _elbv2_client([_alb()], tgs=tgs, health=health)
    exposed = set()
    s._l7_elbv2(g, "internet", PUB_SG, {}, exposed, {})   # cross-VPC/on-prem ip -> unresolved
    assert not exposed
    assert "INFO" in _status(s, "EXPOSURE-03")


def test_ip_target_cross_vpc_collision_resolves_correct_instance():
    # F3 regression: two VPCs reuse private IP 10.0.1.50; the NLB in vpc-A must resolve to
    # i-A (its VPC), never i-B in vpc-B (last-write-wins bare-IP map would have picked i-B).
    s, g = _l7_scanner()
    tgs = [{"TargetGroupArn": "arn:tg/1", "TargetType": "ip", "VpcId": "vpc-A"}]
    health = [{"Target": {"Id": "10.0.1.50"}, "TargetHealth": {"State": "healthy"}}]
    s._clients["elbv2:us-east-1"] = _elbv2_client([_alb()], tgs=tgs, health=health)
    ip_map = {("vpc-A", "10.0.1.50"): "i-A", ("vpc-B", "10.0.1.50"): "i-B"}
    exposed = set()
    s._l7_elbv2(g, "internet", PUB_SG, ip_map, exposed, {})
    assert exposed == {"i-A"}                        # not i-B (the collision)


def test_elbv2_denied_is_info_not_phantom():
    s, g = _l7_scanner()
    c = MagicMock()
    c.get_paginator.side_effect = RuntimeError("AccessDenied")
    s._clients["elbv2:us-east-1"] = c
    found = s._l7_elbv2(g, "internet", PUB_SG, {}, set(), {})
    assert not found
    assert _status(s, "EXPOSURE-03") == {"INFO"}     # never a false all-clear PASS


# ── Classic ELB ───────────────────────────────────────────────────────────────
def test_f8_non_open_listener_tg_not_reachable():
    # F8: listener 443 (open) forwards to TG-web; listener 8080 (SG-blocked) forwards to
    # TG-admin. Only i-web is internet-reachable; i-admin (behind the blocked port) is not.
    s, g = _l7_scanner()
    listeners = [
        {"Port": 443, "Protocol": "HTTPS",
         "DefaultActions": [{"Type": "forward", "TargetGroupArn": "arn:tg/web"}]},
        {"Port": 8080, "Protocol": "HTTP",
         "DefaultActions": [{"Type": "forward", "TargetGroupArn": "arn:tg/admin"}]},
    ]
    tgs = [{"TargetGroupArn": "arn:tg/web", "TargetType": "instance"},
           {"TargetGroupArn": "arn:tg/admin", "TargetType": "instance"}]
    c = _elbv2_client([_alb()], listeners=listeners, tgs=tgs)
    c.describe_target_health.side_effect = lambda TargetGroupArn: {
        "TargetHealthDescriptions": [
            {"Target": {"Id": "i-web" if "web" in TargetGroupArn else "i-admin"},
             "TargetHealth": {"State": "healthy"}}]}
    s._clients["elbv2:us-east-1"] = c
    exposed = set()
    s._l7_elbv2(g, "internet", PUB_SG, {}, exposed, {})   # PUB_SG opens 443 only
    assert "i-web" in exposed                             # served by the open 443 listener
    assert "i-admin" not in exposed                       # served only by SG-blocked 8080


def test_f8_fail_open_when_no_forward_action():
    # a listener with no resolvable forward action -> fail open to all TGs (avoid FN)
    s, g = _l7_scanner()
    tgs = [{"TargetGroupArn": "arn:tg/web", "TargetType": "instance"}]
    health = [{"Target": {"Id": "i-web"}, "TargetHealth": {"State": "healthy"}}]
    c = _elbv2_client([_alb()], listeners=[{"Port": 443}], tgs=tgs, health=health)  # no DefaultActions
    s._clients["elbv2:us-east-1"] = c
    exposed = set()
    s._l7_elbv2(g, "internet", PUB_SG, {}, exposed, {})
    assert "i-web" in exposed                             # fail-open preserves coverage


def test_classic_elb_internet_facing():
    s, g = _l7_scanner()
    clb = {"LoadBalancerName": "clb1", "DNSName": "clb1.elb.amazonaws.com",
           "Scheme": "internet-facing", "SecurityGroups": ["sg-1"],
           "ListenerDescriptions": [{"Listener": {"LoadBalancerPort": 443, "Protocol": "HTTPS"}}],
           "Instances": [{"InstanceId": "i-bbb"}]}
    c = MagicMock()
    c.get_paginator.return_value = _pager("LoadBalancerDescriptions", [clb])
    s._clients["elb:us-east-1"] = c
    exposed = set()
    found = s._l7_classic_elb(g, "internet", PUB_SG, exposed, {})
    assert found and "i-bbb" in exposed
    assert g.node("clb/clb1")["kind"] == "LoadBalancer"
    assert "FAIL" in _status(s, "EXPOSURE-03")


# ── CloudFront ────────────────────────────────────────────────────────────────
def _cf_client(dist):
    c = MagicMock()
    p = MagicMock()
    p.paginate.return_value = [{"DistributionList": {"Items": [dist]}}]
    c.get_paginator.return_value = p
    return c


def test_cloudfront_custom_origin_to_lb_fail():
    s, g = _l7_scanner()
    g.add_node("lb/arn:x", "LoadBalancer")
    lb_dns = {"app-lb-123.elb.amazonaws.com": "lb/arn:x"}
    dist = {"Id": "E123", "DomainName": "d.cloudfront.net", "Enabled": True,
            "Aliases": {"Items": ["www.ex.com"]}, "WebACLId": "",
            "Origins": {"Items": [{"DomainName": "app-lb-123.elb.amazonaws.com",
                                   "CustomOriginConfig": {"OriginProtocolPolicy": "https-only"}}]}}
    s._clients["cloudfront:us-east-1"] = _cf_client(dist)
    found = s._l7_cloudfront(g, "internet", lb_dns)
    assert found
    assert any(e["dst"] == "lb/arn:x" and e["kind"] == "TARGETS"
               for e in g.out_edges("cf/E123"))
    assert "FAIL" in _status(s, "EXPOSURE-03")


def test_cloudfront_s3_origin_targets_bucket_no_finding():
    s, g = _l7_scanner()
    dist = {"Id": "E9", "DomainName": "d9.cloudfront.net", "Enabled": True,
            "Aliases": {"Items": []}, "WebACLId": "",
            "Origins": {"Items": [{"DomainName": "mybucket.s3.us-east-1.amazonaws.com",
                                   "S3OriginConfig": {"OriginAccessIdentity": ""}}]}}
    s._clients["cloudfront:us-east-1"] = _cf_client(dist)
    found = s._l7_cloudfront(g, "internet", {})
    assert found
    assert any(e["dst"] == "arn:aws:s3:::mybucket" and e["kind"] == "TARGETS"
               for e in g.out_edges("cf/E9"))
    # C8: S3-origin adds the graph edge but NO EXPOSURE-03 (S3/EXTACCESS/DATA own that)
    assert not _status(s, "EXPOSURE-03")


def test_cloudfront_global_dedup_guard():
    s, g = _l7_scanner()
    dist = {"Id": "E1", "DomainName": "d.cloudfront.net", "Enabled": True,
            "Aliases": {"Items": []}, "Origins": {"Items": []}}
    s._clients["cloudfront:us-east-1"] = _cf_client(dist)
    assert s._l7_cloudfront(g, "internet", {})       # first call enumerates
    assert not s._l7_cloudfront(g, "internet", {})   # guard: no re-enumerate per region


def test_cloudfront_disabled_distribution_skipped():
    s, g = _l7_scanner()
    dist = {"Id": "Eoff", "DomainName": "x", "Enabled": False, "Origins": {"Items": []}}
    s._clients["cloudfront:us-east-1"] = _cf_client(dist)
    s._l7_cloudfront(g, "internet", {})
    assert g.node("cf/Eoff") is None


# ── API Gateway v1 / v2 ───────────────────────────────────────────────────────
def test_apigw_v1_edge_info_private_skip():
    s, g = _l7_scanner()
    apis = [{"id": "a1", "name": "public-api", "endpointConfiguration": {"types": ["EDGE"]}},
            {"id": "a2", "name": "priv-api", "endpointConfiguration": {"types": ["PRIVATE"]}}]
    c = MagicMock()
    c.get_paginator.return_value = _pager("items", apis)
    s._clients["apigateway:us-east-1"] = c
    found = s._l7_apigateway(g, "internet")
    assert found
    assert g.node("apigw/a1") and g.node("apigw/a2") is None
    assert "INFO" in _status(s, "EXPOSURE-03")


def test_apigwv2_lambda_target():
    s, g = _l7_scanner()
    apis = [{"ApiId": "b1", "Name": "http-api", "ProtocolType": "HTTP",
             "ApiEndpoint": "https://b1.execute-api.us-east-1.amazonaws.com"}]
    larn = f"arn:aws:lambda:us-east-1:{ACCT}:function:fn"
    c = MagicMock()
    c.get_paginator.return_value = _pager("Items", apis)
    c.get_integrations.return_value = {"Items": [{"IntegrationUri":
        f"arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/{larn}/invocations"}]}
    s._clients["apigatewayv2:us-east-1"] = c
    found = s._l7_apigatewayv2(g, "internet")
    assert found and g.node("apigwv2/b1")
    assert g.node(larn) and g.node(larn)["kind"] == "LambdaFunction"
    assert any(e["dst"] == larn and e["kind"] == "TARGETS" for e in g.out_edges("apigwv2/b1"))


# ── reachable_service consumer (component-level exploitability) ────────────────
def _inspector(finding):
    insp = MagicMock()
    insp.batch_get_account_status.return_value = {
        "accounts": [{"resourceState": {"ec2": {"status": "ENABLED"},
                                        "ecr": {"status": "DISABLED"}}}]}
    insp.get_paginator.return_value = _pager("findings", [finding])
    insp.batch_get_finding_details.return_value = {"findingDetails": []}
    return insp


def _ec2_finding(iid):
    return {"findingArn": "arn:finding/1", "severity": "HIGH", "exploitAvailable": "YES",
            "fixAvailable": "YES", "epss": {"score": 0.5},
            "packageVulnerabilityDetails": {"vulnerabilityId": "CVE-2023-1"},
            "resources": [{"id": iid, "type": "AWS_EC2_INSTANCE"}]}


def test_reachable_service_tag_set_when_exposed():
    s, g = _l7_scanner()
    inst_arn = s._instance_arn("i-exp")
    s._clients["inspector2:us-east-1"] = _inspector(_ec2_finding("i-exp"))
    s._reachable_workloads = {inst_arn}
    with patch("builtins.print"):
        s._check_vuln()
    edges = g.out_edges(inst_arn, {"HAS_VULN"})
    assert edges and edges[0]["props"].get("reachable_service") is True


def test_reachable_service_absent_when_unexposed():
    s, g = _l7_scanner()
    inst_arn = s._instance_arn("i-priv")
    s._clients["inspector2:us-east-1"] = _inspector(_ec2_finding("i-priv"))
    s._reachable_workloads = set()
    with patch("builtins.print"):
        s._check_vuln()
    edges = g.out_edges(inst_arn, {"HAS_VULN"})
    # False is dropped by the graph (None props stripped) -> byte-identical graph.json
    assert edges and edges[0]["props"].get("reachable_service") is None


# ── RUNS_IMAGE clobber-safe replay ────────────────────────────────────────────
def test_runs_image_replay_survives_clobber():
    s, g = _l7_scanner()
    src = f"arn:aws:ecs:us-east-1:{ACCT}:task-definition/app:1"
    node = "111111111111.dkr.ecr.us-east-1.amazonaws.com/app@sha256:abc"
    s._runs_image_payloads = [(src, {"family": "app"}, node,
                               {"repository": "app", "digest": "sha256:abc"},
                               {"container": "c", "scan_source": "ecs"})]
    s._replay_runs_image_edges()
    assert g.node(node)["kind"] == "ECRImage"
    assert any(e["kind"] == "RUNS_IMAGE" and e["dst"] == node for e in g.out_edges(src))


def test_runs_image_replay_empty_noop():
    s, g = _l7_scanner()
    s._runs_image_payloads = []
    s._replay_runs_image_edges()                     # no crash, nothing added
    assert "RUNS_IMAGE" not in g.stats()["edge_kinds"]
