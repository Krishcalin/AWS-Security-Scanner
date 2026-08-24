#!/usr/bin/env python3
"""seed_demo_data.py — synthetic multi-tenant demo data for the OverWatch hub.

    python scripts/seed_demo_data.py                    # 5 orgs x 10 accounts
    python scripts/seed_demo_data.py --dry-run          # counts only, no writes
    python scripts/seed_demo_data.py --purge            # remove demo rows, keep real ones

Writes to the hub Postgres named by `CNAPP_DB_URL`. Populates workspaces,
accounts, scans, findings, finding events and ingested vulnerabilities so every
console screen has something to render without an AWS account anywhere near it.

DEMO DATA THAT CAN PASS FOR A REAL SCAN IS A HAZARD, SO THIS ONE CANNOT
-------------------------------------------------------------------------
A seeded database is one screenshot away from being presented as a customer's
posture, and a synthetic CRITICAL that nobody can tell from a real one is how
that happens. Three things make these rows self-identifying:

* **Account ids all begin `9999`.** AWS has never issued an account id in that
  range to anyone in this product's lifetime, and the prefix is checked, not
  merely conventional — `is_demo_account` is what `--purge` selects on.
* **Every workspace slug begins `demo-`** and every account alias ends
  `(DEMO)`, so the marking survives into any screenshot of any list.
* **Scans carry `scanner_version` = `DEMO-<version>`**, so a finding exported
  to JSON still says where it came from after it has left the console.

`--purge` deletes exactly the rows matching those markers and nothing else, so
running it against a hub holding real accounts is safe.

IT REFUSES TO SEED A HUB THAT HOLDS REAL ACCOUNTS
----------------------------------------------------
Not because the writes would collide — they would not — but because the
resulting hub would show real and synthetic posture side by side with nothing
but a suffix to tell them apart. `--force` is available and says what it is
doing; the refusal is the default because the failure is silent and the
recovery is "restore the database".

THE FIVE ORGANISATIONS ARE DELIBERATELY UNEQUAL
--------------------------------------------------
A demo where every tenant looks the same demonstrates nothing. Each profile
below exists to make a specific screen say something:

  northwind    strong posture, few criticals      — what "good" looks like
  atlas        weak posture, exposed crown jewels — attack paths, choke points
  vertex       heavy vulnerability debt (KEV)     — reachability re-ranking
  pinnacle     mid-migration, high churn          — drift, MTTR, reopened
  harbor       small and quiet, one bad account   — the needle in the haystack
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
from typing import Any, Dict, List, Sequence, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

DSN_ENV = "CNAPP_DB_URL"

#: The marker prefix. Checked rather than assumed — see `--purge`.
DEMO_ACCOUNT_PREFIX = "9999"
DEMO_SLUG_PREFIX = "demo-"
DEMO_ALIAS_SUFFIX = " (DEMO)"

#: Fixed so two runs of this script produce the same hub. A demo that changes
#: between rehearsal and delivery is worse than one that is obviously canned.
RANDOM_SEED = 20260824

REGIONS = ("us-east-1", "us-west-2", "eu-west-1", "eu-central-1",
           "ap-southeast-1", "ap-south-1")

#: Scans per account, and how far back the history runs. Enough for the posture
#: trend and MTTR tiles to have a shape rather than two points.
SCANS_PER_ACCOUNT = 8
HISTORY_DAYS = 90


class Profile:
    """One organisation's character, and what it exists to demonstrate."""

    def __init__(self, slug: str, name: str, plan: str, demonstrates: str,
                 crit: Tuple[int, int], high: Tuple[int, int],
                 med: Tuple[int, int], low: Tuple[int, int],
                 vulns: Tuple[int, int], kev_rate: float,
                 exposed_rate: float, resolved_rate: float,
                 unhealthy_accounts: int = 0) -> None:
        self.slug, self.name, self.plan = slug, name, plan
        self.demonstrates = demonstrates
        self.crit, self.high, self.med, self.low = crit, high, med, low
        self.vulns, self.kev_rate = vulns, kev_rate
        self.exposed_rate, self.resolved_rate = exposed_rate, resolved_rate
        self.unhealthy_accounts = unhealthy_accounts


PROFILES: Sequence[Profile] = (
    Profile("northwind", "Northwind Trading", "enterprise",
            "what a well-run estate looks like",
            crit=(0, 1), high=(1, 4), med=(4, 12), low=(6, 18),
            vulns=(4, 14), kev_rate=0.02, exposed_rate=0.05,
            resolved_rate=0.55),
    Profile("atlas", "Atlas Logistics", "enterprise",
            "attack paths and choke points on an exposed estate",
            crit=(4, 11), high=(10, 26), med=(18, 40), low=(12, 30),
            vulns=(20, 60), kev_rate=0.18, exposed_rate=0.42,
            resolved_rate=0.12, unhealthy_accounts=2),
    Profile("vertex", "Vertex Bioscience", "growth",
            "vulnerability debt and KEV reachability re-ranking",
            crit=(2, 6), high=(6, 16), med=(10, 26), low=(8, 20),
            vulns=(60, 140), kev_rate=0.30, exposed_rate=0.28,
            resolved_rate=0.20, unhealthy_accounts=1),
    Profile("pinnacle", "Pinnacle Media", "growth",
            "drift, MTTR and reopened findings during a migration",
            crit=(1, 5), high=(5, 18), med=(14, 34), low=(10, 26),
            vulns=(12, 40), kev_rate=0.10, exposed_rate=0.20,
            resolved_rate=0.45),
    Profile("harbor", "Harbor Federal Credit Union", "starter",
            "one bad account hiding in a quiet estate",
            crit=(0, 1), high=(1, 3), med=(3, 9), low=(4, 12),
            vulns=(2, 10), kev_rate=0.04, exposed_rate=0.06,
            resolved_rate=0.60),
)

ACCOUNT_ROLES = ("prod", "staging", "dev", "sandbox", "data", "shared-services",
                 "security", "logging", "network", "backup")


def is_demo_account(account_id: str) -> bool:
    return str(account_id or "").startswith(DEMO_ACCOUNT_PREFIX)


def _connect(dsn: str):
    try:
        import psycopg
    except ImportError:                                       # pragma: no cover
        try:
            import psycopg2 as psycopg                        # type: ignore
        except ImportError as exc:
            raise RuntimeError("no PostgreSQL driver: install psycopg") from exc
    return psycopg.connect(dsn)


def _catalogue() -> List[Tuple[str, str]]:
    """(check_id, severity) from the product's OWN catalogue.

    Imported rather than invented. A demo built on made-up check ids shows
    screens that no real scan can reproduce, and the first person to click
    through to a remediation write-up finds nothing there.
    """
    import aws_live_scanner as scanner

    import aws_finding_detail as detail
    out = []
    for check_id in sorted(detail.FINDING_DETAIL):
        severity = scanner.CHECK_SEVERITY.get(check_id)
        if severity:
            out.append((check_id, severity))
    return out


def _section_of(check_id: str) -> str:
    return check_id.split("-")[0]


def _pick(rng: random.Random, catalogue, severity: str, want: int):
    pool = [c for c in catalogue if c[1] == severity]
    if not pool:
        return []
    return [rng.choice(pool) for _ in range(want)]


def build(rng: random.Random) -> Dict[str, List[tuple]]:
    """Every row this seeder will write, as plain tuples. No database access.

    Built in full before anything is written so `--dry-run` reports exactly
    what a real run would do, rather than an estimate of it.
    """
    catalogue = _catalogue()
    now = int(time.time())
    rows: Dict[str, List[tuple]] = {
        "workspaces": [], "workspace_members": [], "workspace_accounts": [],
        "accounts": [], "scans": [], "findings": [], "finding_events": [],
        "ingested_vulns": [],
    }

    for org_index, profile in enumerate(PROFILES):
        workspace_id = f"ws-demo-{profile.slug}"
        rows["workspaces"].append((
            workspace_id, profile.name, DEMO_SLUG_PREFIX + profile.slug,
            "active", profile.plan, now, now))
        for role, principal in (("admin", f"admin@{profile.slug}.example"),
                                ("viewer", f"analyst@{profile.slug}.example")):
            rows["workspace_members"].append(
                (workspace_id, principal, role, "active", "demo-seed", now, now))

        for acct_index in range(10):
            # 9999 | org (2) | account (2) | 0000 — twelve digits, with the
            # org and account readable straight off the id in a screenshot.
            # The trailing zeros are deliberate: a real AWS account id looks
            # random, and this one visibly does not.
            account_id = (f"{DEMO_ACCOUNT_PREFIX}"
                          f"{org_index:02d}{acct_index:02d}0000")
            assert len(account_id) == 12, account_id
            purpose = ACCOUNT_ROLES[acct_index]
            alias = f"{profile.slug}-{purpose}{DEMO_ALIAS_SUFFIX}"
            health = "healthy"
            status = "active"
            if acct_index < profile.unhealthy_accounts:
                health, status = rng.choice(
                    [("degraded", "active"), ("unauthorized", "denied")])
            regions = rng.sample(REGIONS, rng.randint(2, 4))
            rows["accounts"].append((
                account_id, alias, f"o-demo{org_index}", "org", status,
                f"arn:aws:iam::{account_id}:role/OverWatchScannerRole",
                None, json.dumps(regions), "daily", health,
                "seeded demo account — not a real AWS account",
                now - rng.randint(3600, 86400), now - 86400 * 120, now))
            rows["workspace_accounts"].append((account_id, workspace_id, now))

            # Production carries the estate's worst posture; sandboxes the least.
            weight = 1.6 if purpose in ("prod", "data") else (
                0.4 if purpose in ("sandbox", "dev") else 1.0)
            _account_history(rng, rows, catalogue, profile, account_id,
                             regions, now, weight)
    return rows


def _account_history(rng, rows, catalogue, profile, account_id, regions,
                     now, weight) -> None:
    """Scans over time, and the findings whose lifecycle they explain."""
    import aws_live_scanner as scanner

    def count(span):
        low, high = span
        return max(0, int(round(rng.randint(low, high) * weight)))

    wanted = []
    for severity, span in (("CRITICAL", profile.crit), ("HIGH", profile.high),
                           ("MEDIUM", profile.med), ("LOW", profile.low)):
        wanted.extend(_pick(rng, catalogue, severity, count(span)))

    first_scan_epoch = now - HISTORY_DAYS * 86400
    step = (HISTORY_DAYS * 86400) // max(1, SCANS_PER_ACCOUNT - 1)
    scan_ids = [f"scan-demo-{account_id}-{i}" for i in range(SCANS_PER_ACCOUNT)]
    scan_epochs = [first_scan_epoch + i * step for i in range(SCANS_PER_ACCOUNT)]

    seen: set = set()
    open_by_sev: Dict[str, int] = {}
    for order, (check_id, severity) in enumerate(wanted):
        region = rng.choice(regions)
        resource = _resource_for(rng, check_id, account_id, region)
        finding_key = f"{region}|{check_id}|{resource}"
        if finding_key in seen:
            continue
        seen.add(finding_key)

        born = rng.randrange(0, SCANS_PER_ACCOUNT - 1)
        resolved = rng.random() < profile.resolved_rate
        died = rng.randrange(born + 1, SCANS_PER_ACCOUNT) if resolved else None
        reopens = 1 if (not resolved and rng.random() < 0.12) else 0
        last_index = (died if died is not None else SCANS_PER_ACCOUNT - 1)

        rows["findings"].append((
            account_id, finding_key, 1, region, check_id, _section_of(check_id),
            resource, _message_for(check_id, resource), severity, "FAIL",
            "resolved" if resolved else "open",
            scan_ids[born], scan_epochs[born], _iso(scan_epochs[born]),
            scan_ids[last_index], scan_epochs[last_index],
            _iso(scan_epochs[last_index]),
            scan_epochs[died] if died is not None else None,
            last_index - born + 1, reopens, scan_ids[last_index],
            f"demo-{abs(hash(finding_key)) % (10 ** 12):012d}"))

        rows["finding_events"].append((
            account_id, finding_key, scan_ids[born], scan_epochs[born],
            None, "open", severity, "seeded"))
        if died is not None:
            rows["finding_events"].append((
                account_id, finding_key, scan_ids[died], scan_epochs[died],
                "open", "resolved", severity, "seeded"))
        if not resolved:
            open_by_sev[severity] = open_by_sev.get(severity, 0) + 1

    for index, (scan_id, epoch) in enumerate(zip(scan_ids, scan_epochs)):
        # Posture improves slightly over the window for every profile except
        # the one whose whole point is that it does not.
        drift = 0 if profile.slug == "atlas" else index * 1.1
        crit = max(0, open_by_sev.get("CRITICAL", 0) - (index // 3))
        high = max(0, open_by_sev.get("HIGH", 0) - (index // 4))
        med = open_by_sev.get("MEDIUM", 0)
        low = open_by_sev.get("LOW", 0)
        total = crit + high + med + low
        score = max(5.0, min(99.0, 96.0 - crit * 6.5 - high * 1.4
                             - med * 0.35 - low * 0.08 + drift))
        rows["scans"].append((
            scan_id, account_id, None, epoch, _iso(epoch), round(score, 1),
            _grade(score), crit, high, med, low, 0, total,
            rng.randint(0, 4) if index else total,
            rng.randint(0, 3) if index else 0, 0, 0,
            f"DEMO-{getattr(scanner, 'VERSION', '2.35.0')}"))

    _account_vulns(rng, rows, profile, account_id, now, weight)


#: Real package/CVE pairs so the vulnerability screens show something a viewer
#: can recognise and look up. Versions are plausible rather than asserted — the
#: point is a demo, and `DEMO-` on the scan says so.
_VULN_POOL = (
    ("openssl", "3.0.11", "3.0.14", "CVE-2024-2511", "HIGH", 7.5),
    ("openssl", "1.1.1n", "1.1.1w", "CVE-2023-0286", "HIGH", 7.4),
    ("glibc", "2.35-0ubuntu3", "2.35-0ubuntu3.8", "CVE-2023-4911", "HIGH", 7.8),
    ("log4j-core", "2.14.1", "2.17.1", "CVE-2021-44228", "CRITICAL", 10.0),
    ("log4j-core", "2.15.0", "2.17.1", "CVE-2021-45046", "CRITICAL", 9.0),
    ("curl", "7.81.0", "7.88.1", "CVE-2023-38545", "CRITICAL", 9.8),
    ("libxml2", "2.9.13", "2.9.14", "CVE-2022-40304", "HIGH", 7.8),
    ("python3.9", "3.9.16", "3.9.18", "CVE-2023-24329", "MEDIUM", 5.3),
    ("nginx", "1.18.0", "1.24.0", "CVE-2022-41741", "MEDIUM", 6.5),
    ("spring-core", "5.3.18", "5.3.20", "CVE-2022-22965", "CRITICAL", 9.8),
    ("apache-struts2", "2.5.29", "2.5.30", "CVE-2023-50164", "CRITICAL", 9.8),
    ("golang.org/x/net", "0.7.0", "0.17.0", "CVE-2023-39325", "HIGH", 7.5),
    ("busybox", "1.35.0", "1.36.1", "CVE-2022-48174", "HIGH", 8.8),
    ("zlib", "1.2.11", "1.2.13", "CVE-2022-37434", "MEDIUM", 6.5),
    ("urllib3", "1.26.5", "1.26.18", "CVE-2023-45803", "MEDIUM", 4.2),
)

_NODE_KINDS = ("EC2Instance", "ECRImage", "LambdaFunction", "ECSTask")


def _account_vulns(rng, rows, profile, account_id, now, weight) -> None:
    low, high = profile.vulns
    wanted = max(0, int(round(rng.randint(low, high) * weight)))
    seen: set = set()
    for _ in range(wanted):
        package, installed, fixed, cve, severity, cvss = rng.choice(_VULN_POOL)
        kind = rng.choice(_NODE_KINDS)
        node_id = f"arn:aws:demo:{account_id}:{kind.lower()}/{rng.randint(1000, 9999)}"
        if (node_id, cve) in seen:
            continue
        seen.add((node_id, cve))

        kev = 1 if rng.random() < profile.kev_rate else 0
        exposed = 1 if rng.random() < profile.exposed_rate else 0
        on_path = 1 if (exposed and rng.random() < 0.7) else 0
        crown = 1 if (on_path and rng.random() < 0.4) else 0
        epss = round(min(0.97, rng.random() * (0.9 if kev else 0.25)), 4)

        # The demo's whole argument: severity alone does not rank. Reachability
        # and KEV move a MEDIUM above a CRITICAL nobody can reach.
        score = int(min(100, cvss * 4
                        + kev * 25 + exposed * 18 + on_path * 12 + crown * 15
                        + epss * 20))
        band = ("critical" if score >= 80 else "high" if score >= 60
                else "medium" if score >= 35 else "low")
        rows["ingested_vulns"].append((
            account_id, node_id, cve, kind, package, installed, fixed,
            severity, cvss, epss, kev,
            "poc" if kev else None,
            json.dumps(["demo-seed"]), 0, exposed, on_path, crown,
            json.dumps(["S3Bucket"] if crown else []),
            score, band,
            "internet → instance → role → data" if crown else None,
            "resolved", now - rng.randint(86400, 86400 * 60), now,
            f"doc-demo-{account_id}"))


def _resource_for(rng, check_id: str, account_id: str, region: str) -> str:
    family = _section_of(check_id).lower()
    tail = rng.randint(1000, 9999)
    shapes = {
        "s3": f"arn:aws:s3:::demo-{family}-bucket-{tail}",
        "iam": f"arn:aws:iam::{account_id}:role/demo-role-{tail}",
        "iampe": f"arn:aws:iam::{account_id}:role/demo-role-{tail}",
        "ec2": f"arn:aws:ec2:{region}:{account_id}:instance/i-demo{tail}",
        "rds": f"arn:aws:rds:{region}:{account_id}:db:demo-db-{tail}",
        "eks": f"arn:aws:eks:{region}:{account_id}:cluster/demo-cluster-{tail}",
    }
    return shapes.get(family,
                      f"arn:aws:{family}:{region}:{account_id}:resource/demo-{tail}")


def _message_for(check_id: str, resource: str) -> str:
    try:
        import aws_finding_detail as detail
        entry = detail.FINDING_DETAIL.get(check_id) or {}
        risk = str(entry.get("risk") or "").strip()
        if risk:
            return risk.split(". ")[0][:240]
    except Exception:                                         # noqa: BLE001
        pass
    return f"{check_id} failed for {resource}"


def _grade(score: float) -> str:
    for cutoff, grade in ((90, "A"), (80, "B"), (70, "C"), (60, "D")):
        if score >= cutoff:
            return grade
    return "F"


def _iso(epoch: int) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


_INSERTS = {
    "workspaces": ("INSERT INTO workspaces(workspace_id,name,slug,status,plan,"
                   "created_at,updated_at) VALUES(%s,%s,%s,%s,%s,%s,%s)"
                   " ON CONFLICT (workspace_id) DO NOTHING"),
    "workspace_members": ("INSERT INTO workspace_members(workspace_id,principal,"
                          "role,status,added_by,created_at,updated_at)"
                          " VALUES(%s,%s,%s,%s,%s,%s,%s)"
                          " ON CONFLICT (workspace_id,principal) DO NOTHING"),
    "accounts": ("INSERT INTO accounts(account_id,alias,org_id,onboarding_method,"
                 "onboarding_status,role_arn,external_id_ref,enabled_regions,"
                 "scan_schedule,health,health_detail,last_scan_at,first_seen_at,"
                 "updated_at) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
                 " ON CONFLICT (account_id) DO NOTHING"),
    "workspace_accounts": ("INSERT INTO workspace_accounts(account_id,workspace_id,"
                           "created_at) VALUES(%s,%s,%s)"
                           " ON CONFLICT (account_id) DO NOTHING"),
    "scans": ("INSERT INTO scans(scan_id,account,region,ts_epoch,ts_iso,"
              "posture_score,grade,crit,high,med,low,info,total_open,new_count,"
              "resolved_count,reopened_count,suppressed_count,scanner_version)"
              " VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
              " ON CONFLICT (scan_id) DO NOTHING"),
    "findings": ("INSERT INTO findings(account,finding_key,key_version,region,"
                 "check_id,section,resource,message,severity,result_status,status,"
                 "first_seen_scan,first_seen_epoch,first_seen_iso,last_seen_scan,"
                 "last_seen_epoch,last_seen_iso,resolved_epoch,times_seen,"
                 "reopen_count,last_scan_id,fingerprint)"
                 " VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,"
                 "%s,%s,%s,%s) ON CONFLICT (account,finding_key) DO NOTHING"),
    "finding_events": ("INSERT INTO finding_events(account,finding_key,scan_id,"
                       "ts_epoch,from_status,to_status,severity,note)"
                       " VALUES(%s,%s,%s,%s,%s,%s,%s,%s)"),
    "ingested_vulns": ("INSERT INTO ingested_vulns(account,node_id,cve,node_kind,"
                       "package,installed_version,fixed_version,severity,cvss_base,"
                       "epss,kev,exploit_available,sources_json,suppressed,"
                       "reachable_from_internet,on_attack_path,reaches_crown,"
                       "terminal_kinds_json,priority_score,priority_band,"
                       "driving_path,mapping_status,first_ingested_epoch,"
                       "last_seen_epoch,doc_id)"
                       " VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,"
                       "%s,%s,%s,%s,%s,%s,%s,%s,%s)"
                       " ON CONFLICT (account,node_id,cve) DO NOTHING"),
}

#: Insert order is FK order. workspace_accounts references both accounts and
#: workspaces, so it cannot lead.
_ORDER = ("workspaces", "workspace_members", "accounts", "workspace_accounts",
          "scans", "findings", "finding_events", "ingested_vulns")


def real_account_count(conn) -> int:
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM accounts WHERE account_id NOT LIKE %s",
                    (DEMO_ACCOUNT_PREFIX + "%",))
        return int(cur.fetchone()[0])


def purge(conn) -> Dict[str, int]:
    """Delete exactly the demo rows. Children first — these are real FKs."""
    like = DEMO_ACCOUNT_PREFIX + "%"
    removed: Dict[str, int] = {}
    with conn.cursor() as cur:
        for table, column in (("finding_events", "account"),
                              ("findings", "account"),
                              ("ingested_vulns", "account"),
                              ("scans", "account"),
                              ("workspace_accounts", "account_id"),
                              ("accounts", "account_id")):
            cur.execute(f"DELETE FROM {table} WHERE {column} LIKE %s", (like,))
            removed[table] = cur.rowcount
        cur.execute("DELETE FROM workspace_members WHERE workspace_id LIKE %s",
                    ("ws-demo-%",))
        removed["workspace_members"] = cur.rowcount
        cur.execute("DELETE FROM workspaces WHERE slug LIKE %s",
                    (DEMO_SLUG_PREFIX + "%",))
        removed["workspaces"] = cur.rowcount
    return removed


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dsn", default="",
                        help=f"hub DSN (default: ${DSN_ENV})")
    parser.add_argument("--dry-run", action="store_true",
                        help="build every row and report the counts without "
                             "writing anything")
    parser.add_argument("--purge", action="store_true",
                        help="delete the demo rows (matched on the 9999 account "
                             "prefix and demo- workspace slug) and stop")
    parser.add_argument("--force", action="store_true",
                        help="seed even though the hub holds real accounts")
    args = parser.parse_args(argv)

    rng = random.Random(RANDOM_SEED)
    rows = build(rng)

    if args.dry_run:
        print("DRY RUN — nothing was written.")
        for table in _ORDER:
            print(f"  {table:20s} {len(rows[table]):>7,}")
        print()
        print(f"  {len(PROFILES)} organisations x 10 accounts = "
              f"{len(rows['accounts'])} AWS accounts")
        for profile in PROFILES:
            print(f"    {profile.slug:10s} {profile.demonstrates}")
        return 0

    dsn = args.dsn or os.environ.get(DSN_ENV, "")
    if not dsn:
        print(f"Refused: {DSN_ENV} is not set and no --dsn was given.")
        return 2

    conn = _connect(dsn)
    try:
        conn.autocommit = False
        if args.purge:
            removed = purge(conn)
            conn.commit()
            print("Purged demo rows:")
            for table, count in removed.items():
                print(f"  {table:20s} {count:>7,}")
            return 0

        real = real_account_count(conn)
        if real and not args.force:
            print(f"Refused: this hub already holds {real} real account(s).")
            print("Seeding would put synthetic posture beside real posture with "
                  "nothing but a suffix to tell them apart, and a screenshot "
                  "does not carry the suffix. Re-run with --force if that is "
                  "genuinely what you want.")
            return 3

        written: Dict[str, int] = {}
        with conn.cursor() as cur:
            for table in _ORDER:
                data = rows[table]
                if data:
                    cur.executemany(_INSERTS[table], data)
                written[table] = len(data)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    print("Seeded the OverWatch hub with synthetic demo data:")
    for table in _ORDER:
        print(f"  {table:20s} {written[table]:>7,}")
    print()
    print(f"  {len(PROFILES)} organisations, {written['accounts']} AWS accounts.")
    print("  Every account id starts 9999 and every alias ends '(DEMO)'.")
    print("  Remove it all with: python scripts/seed_demo_data.py --purge")
    return 0


if __name__ == "__main__":
    sys.exit(main())
