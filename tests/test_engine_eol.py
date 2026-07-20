"""Phase 5 Batch B1 — pure managed-service engine-EOL signal (aws_engine_eol).
Deterministic: every verdict is a function of (service, engine, version, today, live_status).
No AWS, no clock — `today` is always injected."""
import os
import sys
from datetime import date

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_engine_eol as eol
from aws_sidescan import EnrichedMatch

FUTURE = date(2026, 7, 20)     # after every catalogued EOL date
PAST = date(2020, 1, 1)        # before every catalogued EOL date


# ── engine_series: the awkward real version strings ──────────────────────────────
def test_engine_series_shapes():
    assert eol.engine_series("rds", "mysql", "5.7.44") == (5, 7)
    assert eol.engine_series("rds", "aurora-mysql", "8.0.mysql_aurora.3.04.0") == (8, 0)
    assert eol.engine_series("rds", "aurora-mysql", "5.7.mysql_aurora.2.11.4") == (5, 7)
    assert eol.engine_series("rds", "postgres", "11.22") == (11,)
    assert eol.engine_series("rds", "oracle", "19.0.0.0.ru-2023-10") == (19,)
    assert eol.engine_series("rds", "sqlserver-ee", "15.00.4322.2.v1") == (15,)
    assert eol.engine_series("elasticache", "redis", "5.0.6") == (5, 0)
    assert eol.engine_series("opensearch", "elasticsearch", "7.10") == (7, 10)
    assert eol.engine_series("rds", "mysql", "not-a-version") is None


# ── managed_engine_cve: EOL vs supported, determinism ────────────────────────────
def test_mysql_57_eol_after_date():
    m = eol.managed_engine_cve("rds", "mysql", "5.7.44", today=FUTURE)
    assert len(m) == 1
    (mm,) = m
    assert isinstance(mm, EnrichedMatch)
    assert mm.cve == "EOL-mysql-5.7"
    assert mm.fixed_version == "8.0"
    assert mm.severity == "HIGH"
    assert mm.installed_version == "5.7.44"
    assert mm.package == "rds:mysql"
    assert mm.ecosystem == "aws-managed:rds"
    assert mm.kev is False and mm.exploit_available is None and mm.osv_id == ""


def test_mysql_57_supported_before_its_eol_date():
    # deterministic on `today`: same version, pre-EOL scan date -> supported
    assert eol.managed_engine_cve("rds", "mysql", "5.7.44", today=PAST) == []


def test_mysql_80_supported():
    assert eol.managed_engine_cve("rds", "mysql", "8.0.39", today=FUTURE) == []


def test_floor_safe_below_lowest_catalogued_series():
    # mysql 5.5 is below the lowest catalogued cutoff (5.6) -> still flagged, never false-clean
    m = eol.managed_engine_cve("rds", "mysql", "5.5.62", today=FUTURE)
    assert len(m) == 1 and m[0].cve == "EOL-mysql-5.6"


def test_tightest_train_wins_for_older_version():
    # 5.6 must report its OWN train/date, not the looser 5.7 train
    assert eol.managed_engine_cve("rds", "mysql", "5.6.51", today=FUTURE)[0].cve == "EOL-mysql-5.6"


def test_aurora_mysql_v2_eol_v3_ok():
    assert eol.managed_engine_cve("rds", "aurora-mysql",
                                  "5.7.mysql_aurora.2.11.4", today=FUTURE)[0].cve == "EOL-aurora-mysql-5.7"
    assert eol.managed_engine_cve("rds", "aurora-mysql",
                                  "8.0.mysql_aurora.3.04.0", today=FUTURE) == []
    # legacy 'aurora' engine == Aurora MySQL 5.6-compatible
    assert eol.managed_engine_cve("rds", "aurora", "5.6.10a", today=FUTURE)[0].cve == "EOL-aurora-mysql-5.6"


def test_elasticsearch_always_eol():
    m = eol.managed_engine_cve("opensearch", "elasticsearch", "7.10", today=PAST)  # date irrelevant
    assert len(m) == 1 and m[0].cve == "EOL-elasticsearch-7.10" and m[0].severity == "HIGH"


def test_opensearch_modern_supported():
    assert eol.managed_engine_cve("opensearch", "opensearch", "2.11", today=FUTURE) == []
    assert eol.managed_engine_cve("opensearch", "opensearch", "1.0", today=FUTURE)[0].severity == "MEDIUM"


def test_redis_5_eol_7_ok():
    assert eol.managed_engine_cve("elasticache", "redis", "5.0.6", today=FUTURE)[0].severity == "HIGH"
    assert eol.managed_engine_cve("elasticache", "redis", "7.1", today=FUTURE) == []


# ── live_status corroboration hook ───────────────────────────────────────────────
def test_live_deprecated_overrides_table():
    # a version the bundled table considers supported, but AWS reports deprecated -> EOL
    m = eol.managed_engine_cve("rds", "postgres", "17.1", today=PAST, live_status="deprecated")
    assert len(m) == 1 and m[0].cve.startswith("EOL-postgres-")


def test_live_available_stays_supported():
    assert eol.managed_engine_cve("rds", "mysql", "8.0.39", today=FUTURE, live_status="available") == []


def test_live_deprecated_unparseable_still_flags():
    m = eol.managed_engine_cve("rds", "custom", "weird-build", today=PAST, live_status="deprecated")
    assert len(m) == 1


# ── evaluable(): INFO-vs-PASS discriminator ──────────────────────────────────────
def test_evaluable_discriminates():
    assert eol.evaluable("rds", "mysql", "8.0.39") is True          # known + parseable -> PASS/FAIL
    assert eol.evaluable("opensearch", "elasticsearch", "7.10") is True
    assert eol.evaluable("rds", "mysql", "garbage") is False        # unparseable -> INFO
    assert eol.evaluable("rds", "totally-unknown-engine", "1.0") is False  # unknown -> INFO
    assert eol.managed_engine_cve("rds", "mysql", "garbage", today=FUTURE) == []  # no fail-open


# ── table sanity ─────────────────────────────────────────────────────────────────
def test_table_sanity():
    for (svc, eng), rows in eol.ENGINE_EOL.items():
        for r in rows:
            assert isinstance(r.eol, date)
            assert r.severity in eol._SEVERITIES
            assert r.recommend and r.note
            assert r.series == tuple(int(x) for x in r.series)
    for e in eol._ALL_EOL.values():
        assert e.severity in eol._SEVERITIES
