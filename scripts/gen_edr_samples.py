#!/usr/bin/env python3
"""gen_edr_samples.py — generate the SAMPLE-mode runtime (EDR) fixtures from the REAL service.

SAMPLE mode has no backend, so the Runtime screen + the runtime_monitored WQL overlay run over
static fixtures. To guarantee SAMPLE == LIVE, those fixtures are produced by driving an actual
in-memory PlatformService: load each sample account's graph as its scan, ingest sample sensor
inventory + detections, then dump exactly what edr_coverage / list_incidents / get_finding_catalog
return. Regenerate with:  python scripts/gen_edr_samples.py

Writes, per account, under frontend/public/sample/:
  account_<id>_edr_coverage.json   coverage {overall, per_kind, gaps, monitored[]}
  account_<id>_incidents.json      runtime incident rows (ranked by reachability)
  account_<id>_edr_findings.json   the EDR-01 coverage finding overlay (Findings screen)
and edr_coverage_org.json (org roll-up).
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_edr
import aws_state
import cnapp_connectors as cc
from aws_graph import SecurityGraph
from cnapp_registry import AccountRegistry
from cnapp_service import InMemoryResultStore, PlatformService

SAMPLE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "frontend", "public", "sample")

# Sample runtime feeds per account. 123 = fully covered + a live detection on its app host;
# 234 = a sensor feed is wired (some hosts) but the exposed web-front is UNWATCHED -> a gap
# + the EDR-01 coverage finding; 345 = no workloads.
FEEDS = {
    "123456789012": {
        "vendor": "crowdstrike",
        "sensors": [{"instance_id": "i-0app01server", "status": "healthy"}],
        "detections": [{"composite_id": "cs-2041", "max_severity": 92, "status": "new",
                        "behaviors": [{"description": "Credential theft via LSASS access",
                                       "tactic": "CredentialAccess", "technique_id": "T1003"}],
                        "device": {"instance_id": "i-0app01server", "hostname": "app01"}}],
    },
    "234567890123": {
        "vendor": "crowdstrike",
        "sensors": [{"instance_id": "i-0legacybatch9", "status": "healthy"}],   # a covered host
        "detections": [],                                                       # (webfront is unwatched)
    },
}


def _load_graph(acct: str) -> dict:
    with open(os.path.join(SAMPLE_DIR, f"account_{acct}_graph.json"), encoding="utf-8") as f:
        return json.load(f)


def main() -> None:
    reg = AccountRegistry.open(":memory:")
    results = InMemoryResultStore()
    state = aws_state.StateStore(reg._be)
    svc = PlatformService(
        registry=reg, results=results, hub_role_arn="a", cfn_template_url="b",
        secret_writer=lambda a, v: "x", secret_reader=lambda r: "x",
        connectors=cc.ConnectorStore(reg._be), state=state, clock=lambda: 1_700_000_000)

    accounts = [f.split("account_")[1].split("_graph")[0]
                for f in sorted(os.listdir(SAMPLE_DIR)) if f.endswith("_graph.json")]
    for acct in accounts:
        gd = _load_graph(acct)
        results.put(acct, {"account": acct, "results": [], "attack_paths": [],
                           "finding_catalog": [], "graph_full": gd})
        reg.upsert_account(acct, now_epoch=1000, role_arn="r", external_id_ref="ssm://x")
        reg.set_onboarding_status(acct, "active", 1000)
        feed = FEEDS.get(acct)
        if feed:
            svc.ingest_edr(acct, vendor=feed["vendor"], sensors=feed["sensors"],
                           detections=feed["detections"])

    for acct in accounts:
        cov = svc.edr_coverage(acct) or {"overall": {"monitored": 0, "total": 0, "pct": None},
                                         "per_kind": {}, "gaps": []}
        # add the monitored node-id list so SAMPLE graphQuery can stamp runtime_monitored (the
        # join was done in Python — the client only sets a bool, so SAMPLE==LIVE holds).
        g = SecurityGraph.from_dict(_load_graph(acct))
        cov["monitored"] = sorted(aws_edr.monitored_node_ids(g, svc._edr_sensor_records(acct), acct))
        _write(f"account_{acct}_edr_coverage.json", cov)
        _write(f"account_{acct}_incidents.json", svc.list_incidents(acct))
        edr01 = [f for f in svc.get_finding_catalog(acct) if str(f.get("check_id", "")).startswith("EDR-")]
        _write(f"account_{acct}_edr_findings.json", edr01)

    _write("edr_coverage_org.json", svc.org_edr_coverage())
    print("wrote EDR sample fixtures for accounts:", accounts)


def _write(name: str, obj) -> None:
    with open(os.path.join(SAMPLE_DIR, name), "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)
        f.write("\n")


if __name__ == "__main__":
    main()
