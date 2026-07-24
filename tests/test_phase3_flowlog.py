"""Layer B — pure aws_flowlog core: flow-log readability gate, LogFormat parsing,
Insights query builders, the world-open-port join, and the FLOW-01/02/03 deciders.
Plus default_flow_read's start_query→poll→results loop driven by a fake logs client.
No boto3, no socket, no AWS."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_flowlog as F


# ── flow-log readability gate ────────────────────────────────────────────────
def _fl(dest="cloud-watch-logs", status="SUCCESS", lg="fl-lg", tt="ALL"):
    return {"LogDestinationType": dest, "DeliverLogsStatus": status,
            "LogGroupName": lg, "TrafficType": tt}


def test_readability_cloudwatch_all():
    r = F.flow_readability(_fl())
    assert r["attemptable"] and r["has_accept"] and r["has_reject"]
    assert r["log_group"] == "fl-lg"


def test_readability_s3_and_firehose_fail_open():
    for dest in ("s3", "kinesis-data-firehose"):
        r = F.flow_readability(_fl(dest=dest))
        assert not r["attemptable"] and dest in r["reason"]


def test_readability_no_log_group_and_bad_status():
    assert not F.flow_readability(_fl(lg=None))["attemptable"]
    r = F.flow_readability(_fl(status="FAILED"))
    assert not r["attemptable"] and "FAILED" in r["reason"]


def test_readability_traffic_type_caps():
    acc = F.flow_readability(_fl(tt="ACCEPT"))
    assert acc["attemptable"] and acc["has_accept"] and not acc["has_reject"]
    rej = F.flow_readability(_fl(tt="REJECT"))
    assert rej["attemptable"] and rej["has_reject"] and not rej["has_accept"]


# ── LogFormat parsing + required-field gate ──────────────────────────────────
def test_parse_log_format_default_and_custom_and_malformed():
    assert F.parse_log_format("") == F.FLOW_FIELDS_DEFAULT
    assert F.parse_log_format(None) == F.FLOW_FIELDS_DEFAULT
    custom = "${srcaddr} ${dstaddr} ${dstport} ${action} ${interface-id} ${pkt-srcaddr}"
    assert F.parse_log_format(custom) == ["srcaddr", "dstaddr", "dstport", "action",
                                          "interface-id", "pkt-srcaddr"]
    assert F.parse_log_format("no tokens here") == []       # malformed ⇒ empty ⇒ fail-open


def test_required_fields_present():
    assert F.required_fields_present(F.FLOW_FIELDS_DEFAULT)
    # a custom format missing dstport can't drive the deciders
    assert not F.required_fields_present(["srcaddr", "dstaddr", "action", "interface-id"])


# ── query builders ───────────────────────────────────────────────────────────
def test_build_queries_default_uses_srcaddr():
    q = F.build_queries(F.FLOW_FIELDS_DEFAULT)
    assert q["srcfield"] == "srcaddr"
    assert 'filter action="ACCEPT"' in q["scopedown"]
    assert "by interface_id, dstport, o1, o2, o3" in q["scopedown"]
    assert 'filter action="REJECT"' in q["reject"]
    assert "parse @message" in q["accept_set"]


def test_build_queries_prefers_pkt_srcaddr_when_present():
    fields = ["interface-id", "srcaddr", "dstaddr", "dstport", "action", "pkt-srcaddr"]
    q = F.build_queries(fields)
    assert q["srcfield"] == "pkt_srcaddr"
    assert "isValidIpV4(pkt_srcaddr)" in q["scopedown"]


# ── world-open single-port join ──────────────────────────────────────────────
def _perm(proto="tcp", frm=23, to=23, cidr="0.0.0.0/0"):
    p = {"IpProtocol": proto, "IpRanges": [], "Ipv6Ranges": [],
         "UserIdGroupPairs": [], "PrefixListIds": [], "FromPort": frm, "ToPort": to}
    if cidr:
        p["IpRanges"] = [{"CidrIp": cidr}]
    return p


def test_world_open_single_ports_picks_single_ports_only():
    enis = [{"NetworkInterfaceId": "eni-1", "Groups": [{"GroupId": "sg-1"}]}]
    sg_perms = {"sg-1": [_perm(frm=23, to=23), _perm(frm=1000, to=2000)]}  # single + range
    wo = F.world_open_single_ports(enis, sg_perms)
    assert wo == {"eni-1": {23}}                            # range excluded (SEG-02's job)


# ── FLOW-01 scope-down decider ───────────────────────────────────────────────
def _row(**kw):
    return {k: str(v) for k, v in kw.items()}


def test_recommend_scopedown_small_cidr_set():
    rows = [_row(interface_id="eni-1", dstport=443, o1=203, o2=0, o3=113, flows=50),
            _row(interface_id="eni-1", dstport=443, o1=198, o2=51, o3=100, flows=30)]
    out = F.recommend_scopedown(rows, {"eni-1": {443}})
    assert len(out) == 1
    assert out[0]["cidrs"] == ["198.51.100.0/24", "203.0.113.0/24"]
    assert out[0]["flows"] == 80


def test_recommend_scopedown_skips_when_port_not_world_open():
    rows = [_row(interface_id="eni-1", dstport=443, o1=203, o2=0, o3=113, flows=50)]
    assert F.recommend_scopedown(rows, {"eni-1": {22}}) == []   # 443 not a world rule


def test_recommend_scopedown_skips_when_too_many_cidrs():
    rows = [_row(interface_id="eni-1", dstport=443, o1=10, o2=i, o3=0, flows=1)
            for i in range(F.MAX_SCOPE_CIDRS + 3)]
    assert F.recommend_scopedown(rows, {"eni-1": {443}}) == []   # too diffuse to scope


# ── FLOW-02 unused-allowed-port decider ──────────────────────────────────────
def test_unused_allowed_ports_flags_zero_accept_on_active_eni():
    accepts = [_row(interface_id="eni-1", dstport=443, accepts=120)]   # eni active on 443
    wo = {"eni-1": {443, 8080}}                                        # 8080 also world-open
    out = F.unused_allowed_ports(accepts, wo)
    assert out == [{"eni": "eni-1", "port": 8080}]                     # 8080 never accepted


def test_unused_allowed_ports_skips_idle_eni():
    wo = {"eni-1": {443}}
    assert F.unused_allowed_ports([], wo) == []                        # idle ⇒ no evidence


# ── FLOW-03 reject-talker decider ────────────────────────────────────────────
def test_top_reject_talkers_ranked():
    rows = [_row(srcaddr="1.2.3.4", attempts=500, portsProbed=40),
            _row(srcaddr="5.6.7.8", attempts=90, portsProbed=2)]
    out = F.top_reject_talkers(rows, srcfield="srcaddr", top=1)
    assert out == [{"src": "1.2.3.4", "attempts": 500, "ports_probed": 40}]


# ── window bounds (epoch SECONDS, lagged) ────────────────────────────────────
def test_window_bounds():
    start, end = F.window_bounds(1_000_000, hours=72, lag_min=10)
    assert end == 1_000_000 - 600
    assert start == end - 72 * 3600


# ── default_flow_read: start_query → poll → flatten (fake logs client) ────────
class _FakeLogs:
    def __init__(self, statuses, results=None, qid="q1", raise_on=None):
        self._statuses = list(statuses)      # returned in order by get_query_results
        self._results = results or []
        self._qid = qid
        self._raise_on = raise_on or set()
        self.stopped = False

    def start_query(self, **kw):
        if "start" in self._raise_on:
            raise RuntimeError("AccessDenied: logs:StartQuery")
        return {"queryId": self._qid} if self._qid else {}

    def get_query_results(self, queryId=None):
        st = self._statuses.pop(0) if self._statuses else "Complete"
        return {"status": st, "results": self._results if st == "Complete" else []}

    def stop_query(self, queryId=None):
        self.stopped = True
        return {"success": True}


def test_default_flow_read_happy_path():
    results = [[{"field": "interface_id", "value": "eni-1"},
                {"field": "dstport", "value": "443"},
                {"field": "@ptr", "value": "xyz"}]]
    c = _FakeLogs(["Running", "Complete"], results=results)
    rows = F.default_flow_read(c, ["fl-lg"], "stats count(*)", 1, 2,
                               _sleep=lambda s: None, _clock=lambda: 0.0)
    assert rows == [{"interface_id": "eni-1", "dstport": "443", "@ptr": "xyz"}]


def test_default_flow_read_denied_returns_none():
    c = _FakeLogs(["Complete"], raise_on={"start"})
    assert F.default_flow_read(c, ["lg"], "q", 1, 2, _sleep=lambda s: None) is None


def test_default_flow_read_no_query_id_returns_none():
    c = _FakeLogs(["Complete"], qid=None)
    assert F.default_flow_read(c, ["lg"], "q", 1, 2, _sleep=lambda s: None) is None


def test_default_flow_read_failed_status_returns_none():
    c = _FakeLogs(["Failed"])
    assert F.default_flow_read(c, ["lg"], "q", 1, 2, _sleep=lambda s: None) is None


def test_default_flow_read_timeout_stops_query():
    clock = {"t": 0.0}

    def _clock():
        clock["t"] += 100.0                  # each read jumps well past max_wait
        return clock["t"]

    c = _FakeLogs(["Running", "Running", "Running"])
    rows = F.default_flow_read(c, ["lg"], "q", 1, 2, max_wait_s=75,
                               _sleep=lambda s: None, _clock=_clock)
    assert rows is None and c.stopped is True


# ── scanner integration: _check_flowlog (FLOW-00..03 + graph overlay, fail-open) ──
from unittest.mock import MagicMock, patch     # noqa: E402
import aws_graph                                # noqa: E402
import aws_correlate                            # noqa: E402
from aws_live_scanner import AWSLiveScanner     # noqa: E402

_DEFAULT_FL = [{"LogDestinationType": "cloud-watch-logs", "DeliverLogsStatus": "SUCCESS",
                "LogGroupName": "fl-lg", "TrafficType": "ALL", "LogFormat": ""}]


def _scanner(fls=None, flow_read=None, flow_logs=True):
    with patch("aws_live_scanner.HAS_BOTO3", True):
        sc = AWSLiveScanner(sections=["EXPOSURE"])
    sc.flow_logs = flow_logs
    ec2 = MagicMock()
    ec2.describe_flow_logs.return_value = {"FlowLogs": _DEFAULT_FL if fls is None else fls}
    sc._client = lambda service, region=None: ec2
    if flow_read is not None:
        sc._flow_read = flow_read
    return sc


def _fake_reads(scope=None, accept=None, reject=None):
    def _r(logs, groups, query, s, e):
        if "o1, o2, o3" in query:
            return scope
        if 'action="REJECT"' in query:
            return reject
        return accept
    return _r


def _graph_exposed(eni="eni-1"):
    g = aws_graph.SecurityGraph()
    g.add_node("internet", "InternetSource")
    g.add_node(eni, "NetworkInterface")
    g.add_edge("internet", eni, "EXPOSED_TO", family="ipv4", ports="tcp/443")
    return g


_ENIS = [{"NetworkInterfaceId": "eni-1", "Groups": [{"GroupId": "sg-1"}]}]
_SGP = {"sg-1": [_perm(frm=443, to=443)]}


def _run_flow(sc, g):
    with patch("builtins.print"):
        return sc._check_flowlog(_ENIS, _SGP, g)


def _st(sc, cid):
    return [r for r in sc.results if r.check_id == cid]


def test_flow01_scopedown_emits_and_annotates_graph():
    scope = [_row(interface_id="eni-1", dstport=443, o1=203, o2=0, o3=113, flows=42)]
    sc = _scanner(flow_read=_fake_reads(scope=scope, accept=[], reject=[]))
    g = _graph_exposed()
    _run_flow(sc, g)
    f1 = _st(sc, "FLOW-01")
    assert f1 and f1[0].status == "WARN" and "203.0.113.0/24" in f1[0].message
    # EXPOSED_TO annotated with observed evidence
    edge = [e for e in g.out_edges("internet", {"EXPOSED_TO"}) if e["dst"] == "eni-1"][0]
    assert edge["props"].get("observed") is True
    assert edge["props"].get("observed_src_cidrs") == ["203.0.113.0/24"]
    # ObservedCidr overlay node + OBSERVED_FLOW edge, kept OFF the attack path
    assert g.node("cidr:203.0.113.0/24")["kind"] == "ObservedCidr"
    assert g.edges("OBSERVED_FLOW")
    for kind in ("OBSERVED_FLOW",):
        assert kind not in aws_correlate.E_PATH


def test_flow02_unused_port_warns():
    accept = [_row(interface_id="eni-1", dstport=22, accepts=99)]     # active, but never 443
    sc = _scanner(flow_read=_fake_reads(scope=[], accept=accept, reject=[]))
    g = _graph_exposed()
    _run_flow(sc, g)
    f2 = _st(sc, "FLOW-02")
    assert f2 and f2[0].status == "WARN" and "443" in f2[0].message
    edge = [e for e in g.out_edges("internet", {"EXPOSED_TO"}) if e["dst"] == "eni-1"][0]
    assert edge["props"].get("observed_zero_flow_ports") == [443]


def test_flow03_reject_talkers_info():
    reject = [_row(srcaddr="1.2.3.4", attempts=800, portsProbed=50)]
    sc = _scanner(flow_read=_fake_reads(scope=[], accept=[], reject=reject))
    _run_flow(sc, _graph_exposed())
    f3 = _st(sc, "FLOW-03")
    assert f3 and f3[0].status == "INFO" and "1.2.3.4" in f3[0].message


def test_flow00_disabled_is_silent():
    sc = _scanner(flow_logs=False)
    assert _run_flow(sc, _graph_exposed()) is False
    assert _st(sc, "FLOW-00") == [] and _st(sc, "FLOW-01") == []


def test_flow00_no_flow_logs_enabled():
    sc = _scanner(fls=[])
    _run_flow(sc, _graph_exposed())
    assert _st(sc, "FLOW-00") and "no flow logs enabled" in _st(sc, "FLOW-00")[0].message


def test_flow00_s3_destination_unreadable():
    sc = _scanner(fls=[{"LogDestinationType": "s3", "DeliverLogsStatus": "SUCCESS",
                        "LogDestination": "arn:aws:s3:::b", "TrafficType": "ALL"}])
    _run_flow(sc, _graph_exposed())
    assert _st(sc, "FLOW-00") and "s3" in _st(sc, "FLOW-00")[0].message


def test_flow00_read_denied_names_grant():
    sc = _scanner(flow_read=lambda *a, **k: None)     # StartQuery denied ⇒ seam returns None
    _run_flow(sc, _graph_exposed())
    f0 = _st(sc, "FLOW-00")
    assert f0 and "logs:StartQuery" in f0[0].message
    assert _st(sc, "FLOW-01") == [] and _st(sc, "FLOW-02") == []      # no phantom findings


def test_flow00_custom_format_missing_fields():
    sc = _scanner(fls=[{"LogDestinationType": "cloud-watch-logs", "DeliverLogsStatus": "SUCCESS",
                        "LogGroupName": "lg", "TrafficType": "ALL",
                        "LogFormat": "${srcaddr} ${dstaddr} ${action}"}])   # no dstport/interface-id
    _run_flow(sc, _graph_exposed())
    assert _st(sc, "FLOW-00") and "LogFormat" in _st(sc, "FLOW-00")[0].message


def test_flow00_reject_only_traffic_type_with_no_rows():
    sc = _scanner(fls=[{"LogDestinationType": "cloud-watch-logs", "DeliverLogsStatus": "SUCCESS",
                        "LogGroupName": "lg", "TrafficType": "REJECT", "LogFormat": ""}],
                  flow_read=lambda *a, **k: None)
    _run_flow(sc, _graph_exposed())
    assert _st(sc, "FLOW-00") and _st(sc, "FLOW-03") == []


def test_flow00_empty_window_no_evidence():
    sc = _scanner(flow_read=_fake_reads(scope=[], accept=[], reject=[]))
    _run_flow(sc, _graph_exposed())
    f0 = _st(sc, "FLOW-00")
    assert f0 and "no observed flows" in f0[0].message
