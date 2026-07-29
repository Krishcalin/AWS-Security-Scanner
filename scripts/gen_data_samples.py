#!/usr/bin/env python3
"""gen_data_samples.py — generate the SAMPLE-mode DSPM + malware fixtures from the REAL service.

Like gen_edr_samples.py, this drives an in-memory PlatformService over the sample account graphs
so the SAMPLE Data screen + malware lane show exactly what the LIVE hub would (SAMPLE==LIVE by
construction). Writes, per account, under frontend/public/sample/:
  account_<id>_data_inventory.json     the DSPM crown-jewel data inventory
  account_<id>_malware_incidents.json  ranked malware incidents (guardduty-malware/clamav/yara)
and data_inventory_org.json (org roll-up). Regenerate with:  python scripts/gen_data_samples.py
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_malware
import aws_state
import cnapp_connectors as cc
from cnapp_registry import AccountRegistry
from cnapp_service import InMemoryResultStore, PlatformService

SAMPLE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "frontend", "public", "sample")

# a demo malware feed per account (only where a workload exists to land it on)
MALWARE = {
    "123456789012": ("clamav", [{"id": "cv-demo-901", "virus": "Unix.Trojan.Mirai",
                                  "file": "/usr/local/bin/.x", "instance_id": "i-0app01server"}]),
    "234567890123": ("yara", [{"id": "y-demo-902", "rule": "CobaltStrike_Beacon",
                               "meta": {"description": "Cobalt Strike beacon config"},
                               "target_file": "/tmp/beacon.bin", "instance_id": "i-0webfront01"}]),
}


def _load_graph(acct: str) -> dict:
    with open(os.path.join(SAMPLE_DIR, f"account_{acct}_graph.json"), encoding="utf-8") as f:
        return json.load(f)


def _write(name: str, obj) -> None:
    with open(os.path.join(SAMPLE_DIR, name), "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)
        f.write("\n")


def main() -> None:
    reg = AccountRegistry.open(":memory:")
    results = InMemoryResultStore()
    svc = PlatformService(
        registry=reg, results=results, hub_role_arn="a", cfn_template_url="b",
        secret_writer=lambda a, v: "x", secret_reader=lambda r: "x",
        connectors=cc.ConnectorStore(reg._be), state=aws_state.StateStore(reg._be),
        clock=lambda: 1_700_000_000)

    accounts = [f.split("account_")[1].split("_graph")[0]
                for f in sorted(os.listdir(SAMPLE_DIR)) if f.endswith("_graph.json")]
    for acct in accounts:
        results.put(acct, {"account": acct, "results": [], "attack_paths": [],
                           "finding_catalog": [], "graph_full": _load_graph(acct)})
        reg.upsert_account(acct, now_epoch=1000, role_arn="r", external_id_ref="ssm://x")
        reg.set_onboarding_status(acct, "active", 1000)
        if acct in MALWARE:
            src, events = MALWARE[acct]
            svc.ingest_malware(acct, source=src, events=events)

    for acct in accounts:
        _write(f"account_{acct}_data_inventory.json",
               svc.data_inventory(acct) or {"total": 0, "exposed": 0, "unencrypted": 0,
                                            "by_type": {}, "by_tier": {}, "stores": [], "classification_gaps": []})
        mal = [i for i in svc.list_incidents(acct) if i.get("source") in aws_malware.MALWARE_SOURCES]
        _write(f"account_{acct}_malware_incidents.json", mal)

    _write("data_inventory_org.json", svc.org_data_inventory())
    print("wrote DSPM + malware sample fixtures for accounts:", accounts)


if __name__ == "__main__":
    main()
