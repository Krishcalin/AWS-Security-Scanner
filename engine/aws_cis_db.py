#!/usr/bin/env python3
"""aws_cis_db.py — the CIS AWS Database Services Benchmark v2.0.0 controls that
OverWatch did not already hold.

WHY A SEPARATE MODULE. The same reasoning as ``aws_cis_compute.py``: the checks carrying a
plain ``CIS`` key are all CIS AWS **Foundations** numbering, and each service benchmark
re-uses those section numbers for unrelated controls, so Database controls will carry
their own ``CIS-DB`` key rather than being folded into ``CIS``.

WHAT THIS MODULE IS FOR. The benchmark has 98 recommendations across ten services and
**every one of them is marked "(Manual)"** — none is Automated. The five things v2.0.0
added (public access, delete protection, IAM authentication, Aurora encryption at rest,
and enforcing encryption in transit at the database level) are the only recommendations
carrying a runnable audit command; much of the older material is console walkthroughs, and
a substantial number of rows have an empty Rationale and an empty Remediation. So the
honest yield is well below 98, and this module holds the part that is genuinely decidable
from a control-plane read.

Pure. No boto3, no network, no I/O. The scanner passes in what it already fetched, and
every rule here is unit-testable without a client or a fixture.

ON THE SOURCE DOCUMENT. CIS benchmarks may not be redistributed, so the PDF is not in this
repository and no rationale, audit or remediation prose is copied from it. What is cited is
the recommendation NUMBER, which is a reference, and every description is written from the
underlying AWS behaviour.
"""
from __future__ import annotations

from typing import Dict, Mapping, Optional, Sequence, Tuple

__all__ = [
    "TLS_PARAMETERS",
    "tls_parameter_for",
    "tls_enforcement",
    "NOT_DETERMINABLE",
    "DECLINED_AS_NOT_A_FINDING",
]


#: Recommendations that no agentless control-plane read can DECIDE, and why. Populated as
#: the mapping tranche verifies each section against the source document; kept as DATA
#: rather than prose so the coverage doc and the coverage test read the same list. A
#: claim about what is out of scope is worth exactly as much as its reason — the
#: precedent is the identically-named dict in ``aws_cis_compute.py``, which declined 5 of
#: 82 Compute recommendations rather than registering checks that could never fire.
NOT_DETERMINABLE: Dict[str, str] = {}

#: A DIFFERENT KIND OF DECLINE, and the distinction is worth keeping. These are readable
#: from the control plane and deliberately not reported, because a benchmark
#: recommendation is not automatically a security defect and a check that fires on a
#: legitimate design choice is noise that makes the real findings harder to see. Recorded
#: so the decision is visible and reversible rather than looking like an oversight
#: somebody should "fix".
DECLINED_AS_NOT_A_FINDING: Dict[str, str] = {
    "elasticache-cluster-mode": (
        "whether Redis cluster mode (sharding) is enabled is an architecture choice, not "
        "a posture setting -- a single-shard replication group is a legitimate and very "
        "common design, so reporting it would flag correct systems. The availability "
        "properties the recommendation is reaching for are covered by ELC-04 (automatic "
        "failover) and ELC-08 (Multi-AZ), which are settings rather than architecture"),
}


# ── encryption in transit ────────────────────────────────────────────────────
# Every RDS engine ACCEPTS TLS. Almost none REQUIRE it, and that difference is the entire
# control: a database that merely accepts TLS will happily serve any client that does not
# ask for it, so one mis-configured application or one psql invocation without sslmode is
# a cleartext session carrying credentials and rows across the VPC. Enforcement is a
# parameter-group setting, which is why it is invisible to every check that reads only
# `describe_db_instances` / `describe_db_clusters` — OverWatch had no coverage of it at
# all before this.
#
# The parameter name and its enforcing value differ per engine family, and getting the
# pair wrong in either direction is worse than not checking: a wrong name reads as
# "absent" and a wrong value reads as "not enforced", both of which are false FAILs on a
# correctly configured database.
_FORCE_SSL = ("rds.force_ssl", ("1",))
_SECURE_TRANSPORT = ("require_secure_transport", ("on", "1"))

#: engine -> (parameter name, values that mean ENFORCED). Values are compared casefolded.
TLS_PARAMETERS: Dict[str, Tuple[str, Tuple[str, ...]]] = {
    # PostgreSQL family — rds.force_ssl, an integer flag.
    "postgres": _FORCE_SSL,
    "aurora-postgresql": _FORCE_SSL,
    # MySQL family — require_secure_transport, which MySQL renders ON/OFF and Aurora
    # also accepts as 1/0.
    "mysql": _SECURE_TRANSPORT,
    "mariadb": _SECURE_TRANSPORT,
    "aurora": _SECURE_TRANSPORT,          # Aurora MySQL 5.6-compatible, legacy id
    "aurora-mysql": _SECURE_TRANSPORT,
    # DocumentDB — a cluster parameter with a word value, not a flag.
    "docdb": ("tls", ("enabled",)),
    # Neptune — its own parameter name.
    "neptune": ("neptune_enforce_ssl", ("1",)),
}

#: SQL Server uses rds.force_ssl like PostgreSQL, across four edition-specific engine
#: ids. Matched by prefix so a new edition does not silently fall through.
_SQLSERVER_PREFIX = "sqlserver-"

#: Oracle does NOT express this as a single parameter — TLS is configured through the
#: option group (SSL/NATIVE network encryption) and sqlnet settings, so a parameter read
#: cannot decide it. Reported as undecided with this reason rather than guessed at.
_ORACLE_PREFIX = "oracle-"
_ORACLE_REASON = (
    "Oracle configures transport security through the option group and sqlnet "
    "settings rather than a DB parameter, so a parameter-group read cannot decide it")


def tls_parameter_for(engine: Optional[str]) -> Optional[Tuple[str, Tuple[str, ...]]]:
    """(parameter name, enforcing values) for an engine, or None if there is no single
    parameter that decides it."""
    e = (engine or "").strip().lower()
    if not e:
        return None
    if e in TLS_PARAMETERS:
        return TLS_PARAMETERS[e]
    if e.startswith(_SQLSERVER_PREFIX):
        return _FORCE_SSL
    return None


def _find(parameters: Optional[Sequence[Mapping]], name: str) -> Optional[Mapping]:
    for p in parameters or ():
        if not isinstance(p, Mapping):
            continue
        if str(p.get("ParameterName") or "").strip().lower() == name.lower():
            return p
    return None


def tls_enforcement(engine: Optional[str],
                    parameters: Optional[Sequence[Mapping]],
                    group_name: str = "") -> dict:
    """Is client TLS ENFORCED on this database, or merely available?

    ``parameters`` is the full listing of a DB (cluster) parameter group as
    ``DescribeDBParameters`` / ``DescribeDBClusterParameters`` returns it, which includes
    engine defaults alongside anything the operator set. That matters: a parameter left
    at its default still appears, carrying the default value, so "absent from the
    listing" is genuinely unusual.

    THREE OUTCOMES, and the third is the one worth being careful about. Enforced and
    not-enforced are decidable. Everything else — an engine with no single deciding
    parameter, a parameter missing from the listing, a parameter present with no value —
    is UNDECIDED, and is reported as such rather than resolved to either side. Assuming
    a default here would produce a false FAIL on a correctly configured database, and
    assuming the other default would produce a false clean, which is worse.
    """
    e = (engine or "").strip().lower()
    pair = tls_parameter_for(e)
    out = {
        "engine": e,
        "group": group_name,
        "parameter": pair[0] if pair else "",
        "known": False,
        "enforced": False,
        "observed": None,
        "reason": "",
        "statement": "",
    }

    if pair is None:
        out["reason"] = (_ORACLE_REASON if e.startswith(_ORACLE_PREFIX) else
                         f"no TLS-enforcement parameter is known for engine {e!r}")
        out["statement"] = f"TLS enforcement NOT EVALUATED — {out['reason']}"
        return out

    name, enforcing = pair
    row = _find(parameters, name)
    if row is None:
        out["reason"] = (f"{name} was not present in parameter group "
                         f"{group_name or '(unnamed)'}")
        out["statement"] = f"TLS enforcement NOT EVALUATED — {out['reason']}"
        return out

    raw = row.get("ParameterValue")
    if raw is None or str(raw).strip() == "":
        out["reason"] = (f"{name} is present in {group_name or 'the parameter group'} "
                         f"but carries no value")
        out["statement"] = f"TLS enforcement NOT EVALUATED — {out['reason']}"
        return out

    value = str(raw).strip()
    out["observed"] = value
    out["known"] = True
    out["enforced"] = value.casefold() in enforcing
    if out["enforced"]:
        out["statement"] = (f"TLS enforced in transit ({name}={value}) "
                            f"| {group_name}")
    else:
        out["statement"] = (
            f"TLS NOT ENFORCED in transit — {name}={value} in parameter group "
            f"{group_name or '(unnamed)'}. The database accepts unencrypted client "
            f"connections, so one application configured without TLS sends credentials "
            f"and rows in cleartext")
    return out
