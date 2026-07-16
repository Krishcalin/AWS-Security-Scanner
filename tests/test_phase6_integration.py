"""Phase 6 integration — proves the pillar: agentless side-scan CVEs feed the
SAME attack-path correlation as Inspector (ATTACK-02 lights up with Inspector
DISABLED), MERGE-converge when both are present, and the real _check_side_scan
section emits CWPP findings + HAS_VULN edges through an injected pure extractor.
Also asserts save_json gating and the Neptune export wiring."""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_correlate as C
import aws_deepplane
import aws_sidescan as ss
from aws_graph import SecurityGraph
from aws_live_scanner import AWSLiveScanner

ACCT = "111122223333"
ADMIN = f"capability:admin:{ACCT}"
BUCKET = f"arn:aws:s3:::crown-{ACCT}"
UNCOND = AWSLiveScanner._edge_unconditioned


def _threat_fn(g):
    threatened = {e["dst"] for e in g.edges("THREAT_ON")}
    return lambda nid: nid in threatened


def _enum(g):
    return C.enumerate_paths(g, {"internet"}, ADMIN, {BUCKET}, UNCOND,
                             aws_deepplane.is_exploitable, _threat_fn(g))


def _flagship_no_vuln(iid="i-1"):
    """internet -> exposed EC2 -> instance-profile -> role -> {admin, crown S3},
    but WITHOUT any vulnerability edge (as if Inspector is disabled)."""
    g = SecurityGraph()
    inst = f"arn:aws:ec2:us-east-1:{ACCT}:instance/{iid}"
    eni, prof = f"eni-{iid}", f"arn:aws:iam::{ACCT}:instance-profile/p-{iid}"
    role = f"arn:aws:iam::{ACCT}:role/r-{iid}"
    g.add_node("internet", "InternetSource")
    g.add_node(eni, "NetworkInterface")
    g.add_node(inst, "EC2Instance", instance_id=iid)
    g.add_edge("internet", eni, "EXPOSED_TO", family="ipv4", ports="tcp/22")
    g.add_edge(eni, inst, "ATTACHED_TO")
    g.add_node(prof, "InstanceProfile")
    g.add_edge(inst, prof, "HAS_INSTANCE_PROFILE")
    g.add_node(role, "IAMRole", name=f"r-{iid}")
    g.add_edge(prof, role, "HAS_ROLE")
    g.add_node(ADMIN, "AdminCapability")
    g.add_edge(role, ADMIN, "CAN_PRIVESC_TO", conditioned=False)
    g.add_node(BUCKET, "S3Bucket", name="crown-data", crown_jewel=True)
    g.add_edge(role, BUCKET, "CAN_READ_DATA", conditioned=False)
    return g, inst


def _kev_match(cve="CVE-2021-44228"):
    return ss.EnrichedMatch(cve=cve, osv_id=cve, package="log4j", installed_version="2.14",
                            fixed_version="2.17", severity="CRITICAL", cvss_base=10.0,
                            epss=0.97, kev=True, exploit_available="YES",
                            ecosystem="Ubuntu:22.04")


class TestAgentlessLightsUpAttackPath(unittest.TestCase):

    def test_attack02_from_agentless_with_inspector_disabled(self):
        g, inst = _flagship_no_vuln()
        # baseline: with no vuln, the ATTACK-02 data path is NOT critical
        base = _enum(g)
        base_data_crit = [p for p in base if p.terminal_kind == "data"
                          and p.severity == "CRITICAL"]
        # now the agentless side-scan contributes the HAS_VULN edge Inspector would have
        n = ss.emit_vuln_edges(g, inst, "i-1", [_kev_match()], snapshot_id="snap-x")
        assert n == 1
        paths = _enum(g)
        data_crit = [p for p in paths if p.terminal_kind == "data" and p.severity == "CRITICAL"]
        assert data_crit, "agentless KEV CVE must light up the ATTACK-02 data path"
        assert data_crit[0].vuln_pivot is True
        assert len(data_crit) > len(base_data_crit)   # side-scan added the critical path

    def test_merge_converges_with_inspector(self):
        g, inst = _flagship_no_vuln()
        # simulate an Inspector edge for the same (instance, cve)
        g.add_node("CVE-2021-44228", "Vulnerability", kev=True)
        g.add_edge(inst, "CVE-2021-44228", "HAS_VULN", cve="CVE-2021-44228", kev=True,
                   exploit_available="YES", finding_arn="inspector-arn")
        before = len(list(g.edges("HAS_VULN")))
        ss.emit_vuln_edges(g, inst, "i-1", [_kev_match()], snapshot_id="snap-x")
        after = len(list(g.edges("HAS_VULN")))
        assert before == 1 and after == 1        # MERGE, not duplicate


class _CtxExtractor:
    def __init__(self, ext):
        self._ext = ext

    def __enter__(self):
        return self._ext

    def __exit__(self, *a):
        return False


DPKG = (b"Package: openssl\nStatus: install ok installed\nVersion: 3.0.2-0ubuntu1.1\n"
        b"Architecture: amd64\n")


def _osv(cve, eco, name, fixed, sev="CRITICAL"):
    return {"id": cve, "aliases": [cve],
            "affected": [{"package": {"ecosystem": eco, "name": name},
                          "ranges": [{"type": "ECOSYSTEM",
                                      "events": [{"introduced": "0"}, {"fixed": fixed}]}],
                          "database_specific": {"severity": sev}}],
            "severity": [{"type": "CVSS_V3", "score": "9.8"}]}


class TestCheckSideScanWiring(unittest.TestCase):

    def _scanner_with_exposed_instance(self):
        sc = AWSLiveScanner(region="us-east-1", sections=["SIDESCAN"])
        sc.account = ACCT
        sc.side_scan = True
        g = SecurityGraph()
        g.add_node("internet", "InternetSource")
        g.add_node("eni-1", "NetworkInterface")
        g.add_node(sc._instance_arn("i-1"), "EC2Instance", instance_id="i-1")
        g.add_edge("internet", "eni-1", "EXPOSED_TO")
        g.add_edge("eni-1", sc._instance_arn("i-1"), "ATTACHED_TO")
        sc.graph = g
        return sc

    def test_check_side_scan_emits_findings_and_edges(self):
        sc = self._scanner_with_exposed_instance()
        ext = ss.DictExtractor({"/etc/os-release": b"ID=ubuntu\nVERSION_ID=22.04\n",
                                "/var/lib/dpkg/status": DPKG,
                                "/root/.aws/credentials": b"[default]\naws_secret_access_key=x\n"})
        sc._sidescan_extractor_opener = lambda vol_ids, iid: _CtxExtractor(ext)
        feed = ss.OSVFeed.from_records([_osv("CVE-2024-9999", "Ubuntu:22.04", "openssl",
                                             "3.0.2-0ubuntu1.15")])
        sc._load_vuln_db = lambda: (feed, {"CVE-2024-9999": 0.9}, {"CVE-2024-9999"}, set())

        sc._check_side_scan()

        # a KEV CVE -> CWPP-02, a secret -> CWPP-03, plus a HAS_VULN edge on the instance
        ids = {r.check_id for r in sc.results}
        assert "CWPP-02" in ids           # kev
        assert "CWPP-03" in ids           # secret on disk
        assert len(list(sc.graph.edges("HAS_VULN"))) == 1
        assert sc._side_scan_report["targets_scanned"] == 1
        vnode = sc.graph.node("CVE-2024-9999")["props"]
        assert aws_deepplane.is_exploitable(vnode) is True

    def test_check_side_scan_disabled_is_noop(self):
        sc = self._scanner_with_exposed_instance()
        sc.side_scan = False
        sc._check_side_scan()
        assert sc._side_scan_report is None
        assert not any(r.check_id.startswith("CWPP") for r in sc.results)

    def test_check_side_scan_deferred_extractor_infos(self):
        # default opener (no boto3) -> SideScanUnavailable -> CWPP-04 INFO, no crash
        sc = self._scanner_with_exposed_instance()
        sc._check_side_scan()
        assert any(r.check_id == "CWPP-04" and r.status == "INFO" for r in sc.results)
        assert sc._side_scan_report["targets_scanned"] == 0


class TestSaveJsonGating(unittest.TestCase):

    def test_side_scan_block_only_when_run(self):
        sc = AWSLiveScanner(region="us-east-1", sections=["IAM"])
        sc.account = ACCT
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "base.json")
            sc.save_json(p)
            data = json.loads(open(p, encoding="utf-8").read())
        assert "side_scan" not in data and "backend" not in data and "graph_export" not in data

    def test_side_scan_block_present_when_run(self):
        sc = AWSLiveScanner(region="us-east-1", sections=["SIDESCAN"])
        sc.account = ACCT
        sc._side_scan_report = {"enabled": True, "targets_scanned": 1, "per_instance": []}
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "out.json")
            sc.save_json(p)
            data = json.loads(open(p, encoding="utf-8").read())
        assert data["side_scan"]["targets_scanned"] == 1


class TestBackendMetaGating(unittest.TestCase):
    """Regression (adversarial rank 2): the Phase-6 'backend' JSON key must NOT
    leak onto a plain --state / --list-waivers run (no --backend flag)."""

    def test_backend_meta_none_without_backend_flag(self):
        from aws_live_scanner import _backend_meta_for

        class Args:
            backend = None
        # a --state-only run resolves scheme 'sqlite' but must produce no backend meta
        assert _backend_meta_for(Args(), "sqlite", True) is None
        assert _backend_meta_for(Args(), "sqlite", False, "err") is None

    def test_backend_meta_present_with_backend_flag(self):
        from aws_live_scanner import _backend_meta_for

        class Args:
            backend = "postgresql://h/db"
        m = _backend_meta_for(Args(), "postgres", False, "no psycopg")
        assert m == {"scheme": "postgres", "available": False, "reason": "no psycopg"}
        ok = _backend_meta_for(Args(), "postgres", True)
        assert ok["available"] is True and ok["url"] == "postgresql://h/db"

    def test_state_only_scanner_omits_backend_key(self):
        # a scanner that ran --state (default sqlite, _backend_meta stays None)
        # must emit JSON without a 'backend' key — byte-for-byte with pre-Phase-6.
        sc = AWSLiveScanner(region="us-east-1", sections=["IAM"])
        sc.account = ACCT
        sc._state_report = {"drift": {"new": []}}     # as a --state run would set
        assert sc._backend_meta is None
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "out.json")
            sc.save_json(p)
            data = json.loads(open(p, encoding="utf-8").read())
        assert "backend" not in data
        assert "drift" in data                        # state ran; backend did not


class TestNeptuneExportWiring(unittest.TestCase):

    def test_export_graph_neptune_writes_files(self):
        from aws_live_scanner import _export_graph_neptune

        class Args:
            graph_neptune_csv = None
            graph_neptune_cypher = None
        sc = AWSLiveScanner(region="us-east-1", sections=["IAM"])
        sc.account = ACCT
        g = SecurityGraph()
        g.add_node("internet", "InternetSource")
        g.add_node("arn:i-1", "EC2Instance", instance_id="i-1")
        g.add_edge("internet", "arn:i-1", "EXPOSED_TO")
        sc.graph = g
        with tempfile.TemporaryDirectory() as d:
            a = Args()
            a.graph_neptune_csv = os.path.join(d, "csv")
            a.graph_neptune_cypher = os.path.join(d, "graph.cypher.json")
            _export_graph_neptune(sc, a)
            assert os.path.isdir(a.graph_neptune_csv)
            assert os.path.exists(a.graph_neptune_cypher)
            assert sc._graph_export_meta["gremlin_csv"]["files"] >= 1
            assert sc._graph_export_meta["opencypher"]["batches"] >= 1


if __name__ == "__main__":
    unittest.main()
