"""Phase 5 Batch B4 — OpenSearch TLS-policy depth (OSR-06) + engine EOL (OSR-07),
both reusing the already-fetched DomainStatus (zero new per-domain API calls)."""
import os
import sys
from datetime import date
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_live_scanner import make_scanner


def _osr_scanner(domain_status):
    s = make_scanner(sections=["OPENSEARCH"])
    s._today = date(2026, 7, 20)
    osr = MagicMock()
    osr.list_domain_names.return_value = {"DomainNames": [{"DomainName": "d1"}]}
    osr.describe_domain.return_value = {"DomainStatus": domain_status}
    s._clients["opensearch:us-east-1"] = osr
    return s


def _status(s, cid):
    return {r.status for r in s.results if r.check_id == cid}


def _base(engine_version="OpenSearch_2.11", tls="Policy-Min-TLS-1-2-2019-07", https=True):
    return {"DomainName": "d1", "ARN": "arn:aws:es:us-east-1:1:domain/d1",
            "EngineVersion": engine_version,
            "DomainEndpointOptions": {"EnforceHTTPS": https, "TLSSecurityPolicy": tls},
            "EncryptionAtRestOptions": {"Enabled": True},
            "NodeToNodeEncryptionOptions": {"Enabled": True},
            "VPCOptions": {"SubnetIds": ["subnet-1"]},
            "AdvancedSecurityOptions": {"Enabled": True}}


# ── OSR-06 TLS depth ──────────────────────────────────────────────────────────
def test_osr06_weak_tls_fails():
    s = _osr_scanner(_base(tls="Policy-Min-TLS-1-0-2019-07"))
    s._check_opensearch()
    assert "FAIL" in _status(s, "OSR-06")


def test_osr06_strong_tls_passes():
    s = _osr_scanner(_base(tls="Policy-Min-TLS-1-2-2019-07"))
    s._check_opensearch()
    assert _status(s, "OSR-06") == {"PASS"}


def test_osr06_https_off_is_info_not_double_fail():
    # OSR-01 owns the not-enforced FAIL; OSR-06 must not double-report -> INFO
    s = _osr_scanner(_base(https=False, tls="Policy-Min-TLS-1-0-2019-07"))
    s._check_opensearch()
    assert _status(s, "OSR-06") == {"INFO"}
    assert "FAIL" in _status(s, "OSR-01")


# ── OSR-07 engine EOL ─────────────────────────────────────────────────────────
def test_osr07_elasticsearch_always_eol():
    s = _osr_scanner(_base(engine_version="Elasticsearch_7.10"))
    s._check_opensearch()
    assert "FAIL" in _status(s, "OSR-07")
    edges = [p for p in s._eol_graph_payloads if p[1] == "OpenSearchDomain"]
    assert len(edges) == 1 and edges[0][2][0].cve == "EOL-elasticsearch-7.10"


def test_osr07_modern_opensearch_supported():
    s = _osr_scanner(_base(engine_version="OpenSearch_2.11"))
    s._check_opensearch()
    assert _status(s, "OSR-07") == {"PASS"}
    assert s._eol_graph_payloads == []


def test_osr07_pending_update_noted_in_message():
    ds = _base(engine_version="OpenSearch_2.11")
    ds["ServiceSoftwareOptions"] = {"UpdateAvailable": True}
    s = _osr_scanner(ds)
    s._check_opensearch()
    msg = [r.message for r in s.results if r.check_id == "OSR-07"][0]
    assert "service software update available" in msg


def test_osr07_missing_engine_version_info():
    ds = _base()
    ds.pop("EngineVersion")
    s = _osr_scanner(ds)
    s._check_opensearch()
    assert _status(s, "OSR-07") == {"INFO"}


def test_maps_lockstep():
    import aws_live_scanner as A
    for cid in ("OSR-06", "OSR-07"):
        assert cid in A.CHECK_SEVERITY and cid in A.COMPLIANCE_MAP and cid in A.REMEDIATION_MAP
        assert "aws " in A.REMEDIATION_MAP[cid].lower()
