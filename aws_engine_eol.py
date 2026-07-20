"""Managed-service engine end-of-life (EOL) signal — Phase 5 "managed-service vuln axis".

A PURE, offline, deterministic module. It answers one question: *is this managed
DB/cache/search engine version past AWS standard-support EOL?* — and expresses a positive
answer as a synthetic `EnrichedMatch` so the caller can feed it straight into
`aws_sidescan.emit_node_vuln_edges`, producing a HAS_VULN edge byte-identical in shape to
the side-scan / Inspector edges.

WHY A SYNTHETIC "EOL" SIGNAL, NOT REAL CVE IDS
----------------------------------------------
Amazon RDS / ElastiCache / OpenSearch backport security fixes into EOL engine trains
*out of band*, hiding the true managed patch level behind the visible EngineVersion. So
asserting "CVE-XXXX affects this engine" keyed on the version string is a near-guaranteed
false positive. An EOL **date** is a public, deterministic fact (FP ~= 0), cheap to
maintain, and fully unit-testable offline. The finding is an honest lifecycle/governance
claim ("series past standard support — no free security patching"), NOT a CVE claim; the
synthetic id is namespaced `EOL-<engine>-<series>` so it never collides with a real CVE node.

DETERMINISM
-----------
`today` is a REQUIRED keyword — this module never calls `date.today()` itself, so a scan's
verdict is a pure function of (service, engine, version, today, live_status). Tests inject a
fixed date. `live_status` is an OPTIONAL live-API corroboration hook (RDS
DescribeDBEngineVersions[].Status): 'deprecated' forces EOL regardless of the bundled table
(catches table lag); 'available' with no matching rule stays supported. It defaults to None
(Phase 5 ships offline/deterministic; the guarded live call is deferred).

The EOL DATES below are DATA, refreshable without a code change as AWS lifecycle calendars
move. The correctness that tests lock is the ALGORITHM (floor-safe threshold + injectable
`today`), not the specific dates.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date
from typing import Dict, List, Optional, Tuple

from aws_sidescan import EnrichedMatch

_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


@dataclass(frozen=True)
class EolEntry:
    """One EOL cutoff for a (service, engine) train. A version whose parsed `series` is
    <= this cutoff's `series` AND is scanned on/after `eol` is end-of-life. Cutoffs are the
    *upper bound* of an EOL train, so the lowest cutoff also acts as the floor: any version
    at or below it is caught (never a false-clean on an un-catalogued sub-floor version)."""
    service: str
    engine: str
    series: Tuple[int, ...]
    eol: date
    severity: str
    recommend: str          # target supported version (-> EnrichedMatch.fixed_version)
    note: str


# How many leading numeric components form the comparison "series" for each engine family.
_SERIES_LEN: Dict[Tuple[str, str], int] = {
    ("rds", "mysql"): 2, ("rds", "mariadb"): 2, ("rds", "aurora-mysql"): 2,
    ("rds", "postgres"): 1, ("rds", "aurora-postgresql"): 1,
    ("rds", "oracle"): 1, ("rds", "sqlserver"): 1,
    ("elasticache", "redis"): 2, ("elasticache", "valkey"): 2,
    ("elasticache", "memcached"): 2,
    ("opensearch", "opensearch"): 2, ("opensearch", "elasticsearch"): 2,
}


def _e(service, engine, series, y, m, d, severity, recommend, note) -> EolEntry:
    return EolEntry(service, engine, tuple(series), date(y, m, d), severity, recommend, note)


# ── Bundled EOL table (DATA — refreshable). Keyed (service, engine) -> ordered cutoffs. ──
# Dates reconciled to AWS lifecycle calendars (RDS/Aurora version policy, ElastiCache
# supported versions, OpenSearch Service version history) at build time; see module docstring.
_ROWS: List[EolEntry] = [
    # ── RDS / Aurora ──────────────────────────────────────────────────────────────
    _e("rds", "mysql", (5, 6), 2021, 8, 3, "HIGH", "8.0",
       "RDS for MySQL 5.6 past end of standard support"),
    _e("rds", "mysql", (5, 7), 2024, 7, 31, "HIGH", "8.0",
       "RDS for MySQL 5.7 past end of standard support"),
    _e("rds", "mariadb", (10, 3), 2023, 10, 23, "HIGH", "10.11",
       "RDS for MariaDB 10.3 past end of standard support"),
    _e("rds", "mariadb", (10, 4), 2024, 6, 18, "HIGH", "10.11",
       "RDS for MariaDB 10.4 past end of standard support"),
    _e("rds", "postgres", (11,), 2024, 2, 29, "HIGH", "16",
       "RDS for PostgreSQL 11 past end of standard support"),
    _e("rds", "postgres", (12,), 2025, 2, 28, "HIGH", "16",
       "RDS for PostgreSQL 12 past end of standard support"),
    _e("rds", "aurora-mysql", (5, 6), 2023, 2, 28, "HIGH", "8.0",
       "Aurora MySQL v1 (5.6-compatible) end of life"),
    _e("rds", "aurora-mysql", (5, 7), 2024, 10, 31, "HIGH", "8.0",
       "Aurora MySQL v2 (5.7-compatible) end of standard support"),
    _e("rds", "aurora-postgresql", (11,), 2024, 2, 29, "HIGH", "16",
       "Aurora PostgreSQL 11 past end of standard support"),
    _e("rds", "aurora-postgresql", (12,), 2025, 2, 28, "HIGH", "16",
       "Aurora PostgreSQL 12 past end of standard support"),
    _e("rds", "oracle", (12,), 2024, 3, 1, "HIGH", "19",
       "RDS for Oracle 12.x past end of standard support"),
    _e("rds", "sqlserver", (11,), 2022, 7, 12, "HIGH", "15",
       "RDS for SQL Server 2012 (v11) end of life"),
    _e("rds", "sqlserver", (12,), 2024, 6, 1, "HIGH", "15",
       "RDS for SQL Server 2014 (v12) past end of standard support"),
    # ── ElastiCache ───────────────────────────────────────────────────────────────
    _e("elasticache", "redis", (5, 0), 2024, 3, 1, "HIGH", "7.1",
       "ElastiCache for Redis 5.x past end of support"),
    _e("elasticache", "memcached", (1, 5), 2023, 1, 1, "MEDIUM", "1.6",
       "ElastiCache for Memcached 1.5.x past end of support"),
    # ── OpenSearch (opensearch engine; Elasticsearch handled as _ALL_EOL) ─────────
    _e("opensearch", "opensearch", (1, 0), 2023, 12, 7, "MEDIUM", "2.x",
       "OpenSearch 1.0 deprecated on Amazon OpenSearch Service"),
    _e("opensearch", "opensearch", (1, 1), 2023, 12, 7, "MEDIUM", "2.x",
       "OpenSearch 1.1 deprecated on Amazon OpenSearch Service"),
    _e("opensearch", "opensearch", (1, 2), 2024, 6, 1, "MEDIUM", "2.x",
       "OpenSearch 1.2 deprecated on Amazon OpenSearch Service"),
]

ENGINE_EOL: Dict[Tuple[str, str], List[EolEntry]] = {}
for _row in _ROWS:
    ENGINE_EOL.setdefault((_row.service, _row.engine), []).append(_row)

# Engines that are wholesale legacy/EOL regardless of version (any version -> EOL).
_ALL_EOL: Dict[Tuple[str, str], EolEntry] = {
    ("opensearch", "elasticsearch"): EolEntry(
        "opensearch", "elasticsearch", (0,), date(2021, 1, 1), "HIGH", "OpenSearch_2.x",
        "Elasticsearch engines on Amazon OpenSearch Service are legacy "
        "(security-only, no new features)"),
}

# (service, engine) families this module can render a verdict for.
_KNOWN = set(ENGINE_EOL) | set(_ALL_EOL)


def _norm_engine(service: str, engine: str) -> str:
    """Normalize an AWS Engine value to a table family key."""
    e = (engine or "").lower().strip()
    if service == "rds":
        if e in ("aurora", "aurora-mysql"):
            return "aurora-mysql"          # legacy 'aurora' == Aurora MySQL (5.6-compatible)
        if e == "aurora-postgresql":
            return "aurora-postgresql"
        if e.startswith("sqlserver"):
            return "sqlserver"             # sqlserver-ee/se/ex/web
        if e.startswith("oracle"):
            return "oracle"                # oracle-ee/se2/...
    return e


def engine_series(service: str, engine: str, version: str) -> Optional[Tuple[int, ...]]:
    """Extract the numeric comparison series from an engine version string, at the
    granularity this family compares on. Returns None if no leading numeric run
    (caller must then emit INFO, never a fail-open PASS).

    Handles the awkward real shapes: '8.0.mysql_aurora.3.04.0' -> (8, 0);
    '5.7.mysql_aurora.2.11.4' -> (5, 7); '15.00.4322.2.v1' -> (15,);
    '19.0.0.0.ru-2023-10' -> (19,); 'OpenSearch_2.11' must be pre-split to '2.11' -> (2, 11).
    Deliberately NOT semver_vercmp/pep440_vercmp (those mis-order/reject these strings)."""
    m = re.match(r"\s*(\d+(?:\.\d+)*)", version or "")
    if not m:
        return None
    parts = [int(x) for x in m.group(1).split(".") if x != ""]
    if not parts:
        return None
    n = _SERIES_LEN.get((service, _norm_engine(service, engine)), 2)
    parts = (parts + [0] * n)[:n]
    return tuple(parts)


def evaluable(service: str, engine: str, version: str) -> bool:
    """True when this module can render an EOL/supported verdict for the version.
    False -> the caller emits INFO ('engine version not evaluable'), NOT a PASS."""
    eng = _norm_engine(service, engine)
    if (service, eng) in _ALL_EOL:
        return True                        # wholesale-legacy engine — always a verdict
    return (service, eng) in _KNOWN and engine_series(service, eng, version) is not None


def _series_label(series: Tuple[int, ...]) -> str:
    return ".".join(str(x) for x in series)


def _synth_match(service: str, engine: str, version: str, label_series: Tuple[int, ...],
                 severity: str, recommend: str) -> EnrichedMatch:
    """Build the single synthetic EnrichedMatch for an EOL verdict. ALL 11 frozen fields
    are populated (no defaults): a namespaced synthetic cve, no CVSS/EPSS/KEV (this is a
    lifecycle claim, not a scored CVE), and exploit_available=None (never a bool).

    `label_series` names the EOL TRAIN (the matched cutoff), NOT the exact running version,
    so every instance a cutoff catches — including sub-floor versions — dedups to one
    Vulnerability node; the exact version is preserved in `installed_version`."""
    return EnrichedMatch(
        cve=f"EOL-{engine}-{_series_label(label_series)}",
        osv_id="",
        package=f"{service}:{engine}",
        installed_version=version,
        fixed_version=recommend,
        severity=severity,
        cvss_base=None,
        epss=None,
        kev=False,
        exploit_available=None,
        ecosystem=f"aws-managed:{service}",
    )


def _match_entry(service: str, engine: str, series: Tuple[int, ...],
                 today: date) -> Optional[EolEntry]:
    """The tightest EOL train bounding `series` from above (the version's own train), if
    that train's EOL date has passed. Picking the smallest cutoff >= series avoids reporting
    a looser train's (later) date for an older version."""
    best: Optional[EolEntry] = None
    for entry in ENGINE_EOL.get((service, engine), ()):
        if series <= entry.series and (best is None or entry.series < best.series):
            best = entry
    if best is not None and today >= best.eol:
        return best
    return None


def managed_engine_cve(service: str, engine: str, version: str, *,
                       today: date, live_status: Optional[str] = None) -> List[EnrichedMatch]:
    """Return a 0-or-1-element list of synthetic EnrichedMatches for an EOL engine version.

    Empty list == supported OR not-evaluable (call `evaluable()` first to tell them apart:
    evaluable + [] -> PASS; not-evaluable -> INFO). `live_status='deprecated'` forces EOL
    regardless of the bundled table; 'available' with no matching rule stays supported."""
    eng = _norm_engine(service, engine)
    series = engine_series(service, eng, version)

    if live_status == "deprecated":
        s = series if series is not None else (0,)
        return [_synth_match(service, eng, version, s, "HIGH",
                             "a supported engine version")]

    if series is None:
        return []                          # unparseable -> not evaluable

    if (service, eng) in _ALL_EOL:
        e = _ALL_EOL[(service, eng)]
        return [_synth_match(service, eng, version, series, e.severity, e.recommend)]

    if live_status == "available":
        return []                          # AWS says supported; trust it over a stale table

    entry = _match_entry(service, eng, series, today)
    if entry is None:
        return []
    # label by the matched EOL TRAIN (entry.series), so sub-floor versions dedup to it
    return [_synth_match(service, eng, version, entry.series, entry.severity, entry.recommend)]
