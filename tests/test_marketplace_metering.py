"""Phase-4 Slice-2 · B7 — the optional Marketplace usage emitter reads the Slice-1
accounts-under-management ledger and calls MeterUsage with the right quantity (boto3 client
injected; no AWS, no telemetry)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hub import cnapp_marketplace_metering as mm
from hub.cnapp_metering import MeteringStore
from hub.cnapp_registry import AccountRegistry


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


# ══════════════════════════════════════════════════════════════════════════════
# The wiring — and, mostly, that it stays OFF
# ══════════════════════════════════════════════════════════════════════════════
# This emitter was complete, tested and documented in deploy/marketplace/ while no
# code path could reach it, so a metered listing would have billed nothing. The
# worker is the only hourly process in the product and is now its caller. Almost
# every test below asserts the emitter does NOT fire, because for the deployments
# this product targets — air-gapped, contract SKU, private offer — an unexpected
# call to an AWS billing endpoint is disqualifying, and "off by default" is a claim
# that has to be tested rather than commented.
class _Svc:
    """Only the attributes meter_marketplace_usage reads."""
    def __init__(self, *, code="", factory=None, metering=None, now=1_700_000_000):
        self.marketplace_product_code = code
        self.marketplace_client = factory
        self.metering = metering
        self.clock = lambda: now


def test_the_emitter_is_off_without_a_product_code():
    from hub import cnapp_worker
    mp = _FakeMP()
    out = cnapp_worker.meter_marketplace_usage(
        _Svc(code="", factory=lambda: mp, metering=_metering()))
    assert out is None
    assert mp.calls == [], "MeterUsage was called on an unmetered deployment"


def test_the_emitter_is_off_without_a_client_factory():
    from hub import cnapp_worker
    assert cnapp_worker.meter_marketplace_usage(
        _Svc(code="prod-abc", factory=None, metering=_metering())) is None


def test_the_emitter_is_off_without_a_metering_store():
    from hub import cnapp_worker
    mp = _FakeMP()
    assert cnapp_worker.meter_marketplace_usage(
        _Svc(code="prod-abc", factory=lambda: mp, metering=None)) is None
    assert mp.calls == []


def test_all_three_gates_open_emits_once():
    from hub import cnapp_worker
    mp = _FakeMP()
    out = cnapp_worker.meter_marketplace_usage(
        _Svc(code="prod-abc", factory=lambda: mp, metering=_metering()))
    assert out and out["quantity"] == 3
    assert len(mp.calls) == 1 and mp.calls[0]["ProductCode"] == "prod-abc"


def test_a_metering_failure_never_propagates():
    """FAIL-OPEN, matching the per-scan metering block in run_scan_job. An operator
    whose scans stop because a billing endpoint was unreachable has lost the product
    in order to protect the invoice. The error is returned and logged, not raised."""
    from hub import cnapp_worker

    class _BoomMP:
        def meter_usage(self, **kw):
            raise RuntimeError("throttled")

    logged = []
    out = cnapp_worker.meter_marketplace_usage(
        _Svc(code="p", factory=lambda: _BoomMP(), metering=_metering()),
        log=logged.append)
    assert out and "throttled" in out["error"]
    assert logged and "FAILED" in logged[0]


def test_the_client_factory_is_not_called_when_the_emitter_is_off():
    """The factory is a factory precisely so that 'off' constructs no boto3 client
    and resolves no hostname. A truthy product code is the only thing that may cause
    it to be invoked."""
    from hub import cnapp_worker
    called = []

    def factory():
        called.append(1)
        return _FakeMP()

    cnapp_worker.meter_marketplace_usage(
        _Svc(code="", factory=factory, metering=_metering()))
    assert called == [], "a client was constructed on an unmetered deployment"


def test_the_worker_loop_meters_once_per_hour_not_once_per_tick():
    """MeterUsage is hourly; the tick interval is typically five minutes. AWS
    de-duplicates within the hour so over-calling would not over-bill, but it would
    burn twelve API calls an hour for one record."""
    from hub import cnapp_worker
    mp = _FakeMP()
    clk = {"t": 1_700_000_000}

    class _LoopSvc(_Svc):
        def __init__(self):
            super().__init__(code="prod-abc", factory=lambda: mp,
                             metering=_metering())
            self.clock = lambda: clk["t"]

        def schedule_due_scans(self):
            return []

        def pending_jobs(self):
            return []

    svc = _LoopSvc()
    totals = cnapp_worker.run_forever(svc, ticks=4, sleep=lambda s: None,
                                      log=lambda m: None)
    assert len(mp.calls) == 1, "metered %d times in one hour" % len(mp.calls)
    assert totals["metered"] == 1

    clk["t"] += 3600                                  # next hour
    cnapp_worker.run_forever(svc, ticks=2, sleep=lambda s: None,
                             log=lambda m: None)
    assert len(mp.calls) == 2


def test_an_unmetered_worker_loop_reports_no_metering():
    from hub import cnapp_worker

    class _Plain(_Svc):
        def __init__(self):
            super().__init__()

        def schedule_due_scans(self):
            return []

        def pending_jobs(self):
            return []

    totals = cnapp_worker.run_forever(_Plain(), ticks=3, sleep=lambda s: None,
                                      log=lambda m: None)
    assert totals["metered"] == 0


def test_the_server_builds_no_client_factory_without_the_env_var(monkeypatch):
    """The decision to be a metered listing is made in one place. Unset means the
    factory itself is None, so boto3 is never imported for this purpose."""
    from hub import cnapp_server
    monkeypatch.delenv("CNAPP_MARKETPLACE_PRODUCT_CODE", raising=False)
    assert cnapp_server._marketplace_client_factory() is None
    monkeypatch.setenv("CNAPP_MARKETPLACE_PRODUCT_CODE", "prod-abc")
    assert callable(cnapp_server._marketplace_client_factory())


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
