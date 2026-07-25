"""Phase-4 Slice-2 · B7 — the optional Marketplace usage emitter reads the Slice-1
accounts-under-management ledger and calls MeterUsage with the right quantity (boto3 client
injected; no AWS, no telemetry)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cnapp_marketplace_metering as mm
from cnapp_metering import MeteringStore
from cnapp_registry import AccountRegistry


class _FakeMP:
    def __init__(self):
        self.calls = []

    def meter_usage(self, **kw):
        self.calls.append(kw)
        return {"MeteringRecordId": f"rec-{len(self.calls)}"}


def _metering():
    reg = AccountRegistry.open(":memory:")
    m = MeteringStore(reg._be)
    # two workspaces, 3 active accounts this period (billable = accounts under management)
    for ws, acct in (("ws-a", "a1"), ("ws-a", "a2"), ("ws-b", "b1")):
        m.record(ws, "account.active", event_key=f"{acct}:2023-11", now_epoch=1_700_000_000,
                 account_id=acct)
    # a non-billable observability event must NOT count
    m.record("ws-a", "scan.completed", event_key="job-1", now_epoch=1_700_000_000)
    return m


def test_accounts_under_management_counts_active_only():
    assert mm.accounts_under_management(_metering(), period="2023-11") == 3
    assert mm.accounts_under_management(_metering(), period="2099-01") == 0


def test_meter_hourly_calls_meterusage_with_quantity():
    mp = _FakeMP()
    out = mm.meter_hourly(_metering(), product_code="prod-abc", now_epoch=1_700_000_000,
                          mp_client=mp, period="2023-11")
    assert out["quantity"] == 3 and out["metering_record_id"] == "rec-1"
    assert mp.calls[0]["ProductCode"] == "prod-abc"
    assert mp.calls[0]["UsageDimension"] == "accounts_under_mgmt"
    assert mp.calls[0]["UsageQuantity"] == 3


def test_meter_hourly_swallows_duplicate_as_noop():
    # a within-hour re-run raises DuplicateRequestException — the documented idempotent no-op
    class _DupMP:
        def meter_usage(self, **kw):
            raise type("DuplicateRequestException", (Exception,), {})("duplicate")
    out = mm.meter_hourly(_metering(), product_code="p", now_epoch=1_700_000_000,
                          mp_client=_DupMP(), period="2023-11")
    assert out["duplicate"] is True and out["metering_record_id"] is None


def test_meter_hourly_reraises_other_errors():
    import pytest
    class _BoomMP:
        def meter_usage(self, **kw):
            raise RuntimeError("throttled")
    with pytest.raises(RuntimeError):
        mm.meter_hourly(_metering(), product_code="p", now_epoch=1_700_000_000,
                        mp_client=_BoomMP(), period="2023-11")


# ── marketplace artifacts parse + carry the right security posture ────────────
def test_marketplace_artifacts_valid():
    import pytest
    yaml = pytest.importorskip("yaml")
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    mp = os.path.join(root, "deploy", "marketplace")
    listing = yaml.safe_load(open(os.path.join(mp, "listing.yaml"), encoding="utf-8"))
    assert listing["product"]["type"] == "container"          # self-hosted, air-gappable
    dims = {d["id"] for d in listing["pricing"]["dimensions"]}
    assert "accounts_under_mgmt" in dims                       # tied to the backend metering
    assert "annual_committed_accounts" in dims                 # the air-gap (no-egress) SKU

    class _L(yaml.SafeLoader):
        pass
    _L.add_multi_constructor("!", lambda l, s, n: None)        # ignore CFN !Sub/!Ref tags
    cfn = yaml.load(open(os.path.join(mp, "hub-deploy.yaml"), encoding="utf-8"), Loader=_L)
    inst = cfn["Resources"]["HubInstance"]["Properties"]
    assert inst["MetadataOptions"]["HttpTokens"] == "required"     # IMDSv2, no v1
    assert inst["BlockDeviceMappings"][0]["Ebs"]["Encrypted"] is True   # encrypted state
