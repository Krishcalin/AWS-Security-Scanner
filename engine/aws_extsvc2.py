#!/usr/bin/env python3
"""aws_extsvc2.py — extended AWS service coverage, batch 2.

Second batch off the 426-service gap analysis, and the first consumer of
``aws_checkdef``: every check here is declared **once**, and the severity, compliance
mapping, remediation, detail page and permission-ledger entry are all derived from that
declaration. Batch 1 needed the same fourteen facts spread across five dict literals in
three files; this needs one block per check, and a half-declared check will not import.

Every field was verified against the botocore service model before the classifier was
written — the operation exists, the field exists, the enum values are AWS's.

WHAT EACH SERVICE CONTRIBUTES
------------------------------
* **Network Firewall** — a firewall with no ``LogDestinationConfigs`` inspects traffic
  and records nothing, which is the expensive way to have no evidence. Stateless default
  actions of ``aws:pass`` mean unmatched packets are forwarded, so the firewall
  fails **open**.
* **Lightsail** — the shadow-IT corner of AWS: separate console, separate mental model,
  frequently outside whatever governs the main estate. Ports open to ``0.0.0.0/0`` and
  publicly-accessible managed databases are the two that matter.
* **ACM Private CA** — a private CA is a **trust root**. Anyone who can sign with it
  mints certificates your estate believes. A cross-account resource policy on one is a
  much larger grant than it looks.
* **QuickSight** — ``PublicSharingEnabled`` at account level is the switch that permits
  dashboards to be published to anyone with the link. QuickSight sits *on top of* your
  warehouses, so a shared dashboard is a data export path that bypasses the datastore's
  own controls entirely.
* **IAM Identity Center** — permission sets are how humans actually get access in a
  multi-account org. An inline policy granting ``*`` on ``*`` is org-wide administrator
  handed to everyone assigned that set, and it is invisible to any per-account IAM audit.
* **Glue** — ``ReturnConnectionPasswordEncrypted=false`` means the Data Catalog hands
  back connection passwords **in cleartext** to anyone who can call ``GetConnection``.
  Also catalog encryption mode and dev endpoints with a public address.

Pure functions over dicts. No boto3, no network, no I/O.
"""
from __future__ import annotations

import json
from typing import Dict, List, Optional, Sequence
from urllib.parse import unquote

from engine import aws_checkdef as _cd
from engine.aws_checkdef import CheckDef as _C, Perm as _P

__all__ = [
    "nfw_logging", "nfw_policy_default", "nfw_protection",
    "lightsail_ports", "lightsail_database",
    "pca_posture", "pca_policy_exposure",
    "quicksight_account", "quicksight_dashboard",
    "sso_permission_set", "glue_catalog_encryption", "glue_dev_endpoint",
    "PASS_ACTION", "PUBLIC_ACCESS", "DISABLED", "parse_doc",
]

# ── verified enum / sentinel values ─────────────────────────────────────────
PASS_ACTION = "aws:pass"          # network-firewall stateless default -> fail OPEN
PUBLIC_ACCESS = "Public"          # lightsail PortAccessType enum
DISABLED = "DISABLED"             # glue CatalogEncryptionMode enum
WORLD_V4 = "0.0.0.0/0"
WORLD_V6 = "::/0"


def _d(v) -> dict:
    return v if isinstance(v, dict) else {}


def _l(v) -> list:
    return list(v) if isinstance(v, (list, tuple)) else []


def parse_doc(doc) -> dict:
    if isinstance(doc, dict):
        return doc
    if not isinstance(doc, (str, bytes, bytearray)):
        return {}
    if isinstance(doc, (bytes, bytearray)):
        try:
            doc = doc.decode("utf-8")
        except Exception:
            return {}
    for cand in (doc, unquote(doc)):
        try:
            v = json.loads(cand)
            return v if isinstance(v, dict) else {}
        except Exception:
            continue
    return {}


def _stmts(doc) -> List[dict]:
    st = parse_doc(doc).get("Statement")
    if isinstance(st, dict):
        st = [st]
    return [s for s in (st or []) if isinstance(s, dict)]


def _is_wild(v) -> bool:
    if isinstance(v, str):
        return v.strip() == "*"
    return any(str(x).strip() == "*" for x in _l(v))


# ── AWS Network Firewall ────────────────────────────────────────────────────
def nfw_logging(name: str, config: Optional[dict]) -> dict:
    """A firewall with no log destination inspects traffic and records nothing."""
    dests = _l(_d(config).get("LogDestinationConfigs"))
    return {
        "firewall": name or "",
        "destinations": len(dests),
        "logging": bool(dests),
        "statement": (
            f"Network Firewall {name} has no logging destination configured — it is "
            f"inspecting traffic and recording none of it, so the one artefact an "
            f"investigation would want does not exist"
            if not dests else ""),
    }


def nfw_policy_default(name: str, policy: Optional[dict]) -> dict:
    """``aws:pass`` as a stateless default forwards everything unmatched."""
    p = _d(policy)
    defaults = [str(a) for a in _l(p.get("StatelessDefaultActions"))]
    frag = [str(a) for a in _l(p.get("StatelessFragmentDefaultActions"))]
    fails_open = PASS_ACTION in defaults
    return {
        "firewall": name or "",
        "known": bool(defaults),
        "defaults": tuple(defaults),
        "fragment_defaults": tuple(frag),
        "fails_open": fails_open,
        "statement": (
            f"Network Firewall policy for {name} has a stateless default action of "
            f"aws:pass — a packet matching no rule is FORWARDED, so the firewall fails "
            f"open rather than closed"
            if fails_open else ""),
    }


def nfw_protection(firewall: Optional[dict]) -> dict:
    """Delete and change protection: the difference between a firewall and a
    suggestion, once someone has console access."""
    f = _d(firewall)
    d, s, p = (f.get("DeleteProtection"), f.get("SubnetChangeProtection"),
               f.get("FirewallPolicyChangeProtection"))
    off = [n for n, v in (("DeleteProtection", d), ("SubnetChangeProtection", s),
                          ("FirewallPolicyChangeProtection", p)) if v is False]
    return {
        "firewall": f.get("FirewallName") or "",
        "known": any(isinstance(x, bool) for x in (d, s, p)),
        "unprotected": tuple(off),
        "statement": (
            f"Network Firewall {f.get('FirewallName')} has {', '.join(off)} disabled — "
            f"the firewall can be deleted or routed around in a single API call, which "
            f"is the first thing an intruder with console access does"
            if off else ""),
    }


# ── Amazon Lightsail ────────────────────────────────────────────────────────
def lightsail_ports(name: str, ports: Optional[Sequence]) -> dict:
    """Lightsail instance ports reachable from the whole internet."""
    open_ports = []
    for p in _l(ports):
        pd = _d(p)
        cidrs = [str(c) for c in _l(pd.get("cidrs")) + _l(pd.get("ipv6Cidrs"))]
        world = WORLD_V4 in cidrs or WORLD_V6 in cidrs
        if world or pd.get("accessType") == PUBLIC_ACCESS:
            frm, to = pd.get("fromPort"), pd.get("toPort")
            proto = pd.get("protocol") or "?"
            open_ports.append(f"{proto}/{frm}" if frm == to else f"{proto}/{frm}-{to}")
    return {
        "instance": name or "",
        "open_ports": tuple(open_ports),
        "world_open": bool(open_ports),
        "statement": (
            f"Lightsail instance {name} accepts traffic from the whole internet on "
            f"{', '.join(open_ports)} — Lightsail has its own console and its own "
            f"firewall, so these rules are invisible to an EC2 security-group audit"
            if open_ports else ""),
    }


def lightsail_database(db: Optional[dict]) -> dict:
    """A Lightsail managed database reachable from the internet."""
    d = _d(db)
    pub = d.get("publiclyAccessible")
    backup = d.get("backupRetentionEnabled")
    return {
        "name": d.get("name") or "",
        "public_known": isinstance(pub, bool),
        "public": pub is True,
        "backup_known": isinstance(backup, bool),
        "backups": backup is True,
        "statement": (
            f"Lightsail database {d.get('name')} is publicly accessible — its endpoint "
            f"resolves to a public address and the only thing between the internet and "
            f"the data is the database password"
            if pub is True else ""),
    }


# ── AWS Certificate Manager Private CA ──────────────────────────────────────
def pca_posture(ca: Optional[dict]) -> dict:
    """Status and key-storage standard of a private certificate authority."""
    c = _d(ca)
    std = c.get("KeyStorageSecurityStandard") or ""
    return {
        "arn": c.get("Arn") or "",
        "status": c.get("Status") or "",
        "active": c.get("Status") == "ACTIVE",
        "key_standard": std,
        "known": bool(std),
        "statement": "",
    }


def pca_policy_exposure(arn: str, policy) -> dict:
    """A resource policy on a CA shares the ability to issue certificates."""
    wide = []
    for s in _stmts(policy):
        if s.get("Effect") != "Allow":
            continue
        pr = s.get("Principal")
        if pr == "*" or _is_wild(_d(pr).get("AWS")) or _is_wild(pr):
            wide.append(s)
    return {
        "arn": arn or "",
        "has_policy": bool(_stmts(policy)),
        "public": bool(wide),
        "statement": (
            f"Private CA {arn} has a resource policy granting a wildcard principal. A "
            f"private CA is a TRUST ROOT: anyone who can issue from it mints "
            f"certificates every system trusting this CA will accept, which is a far "
            f"larger grant than sharing an ordinary resource"
            if wide else ""),
    }


# ── Amazon QuickSight ───────────────────────────────────────────────────────
def quicksight_account(settings: Optional[dict]) -> dict:
    """``PublicSharingEnabled`` permits dashboards to be published to anyone."""
    s = _d(settings)
    pub = s.get("PublicSharingEnabled")
    return {
        "account_name": s.get("AccountName") or "",
        "edition": s.get("Edition") or "",
        "known": isinstance(pub, bool),
        "public_sharing": pub is True,
        "statement": (
            f"QuickSight public sharing is ENABLED for this account, which permits any "
            f"dashboard to be published to anyone with the link. QuickSight sits on top "
            f"of your warehouses, so a shared dashboard is a data export path that "
            f"bypasses the datastore's own access controls entirely"
            if pub is True else ""),
    }


def quicksight_dashboard(dashboard_id: str, permissions: Optional[Sequence]) -> dict:
    """A dashboard granted to the public principal."""
    everyone = []
    for p in _l(permissions):
        pr = str(_d(p).get("Principal") or "")
        if pr.endswith(":user/public") or "PUBLIC" in pr.upper() or pr == "*":
            everyone.append(pr)
    return {
        "dashboard": dashboard_id or "",
        "public_principals": tuple(everyone),
        "public": bool(everyone),
        "statement": (
            f"QuickSight dashboard {dashboard_id} is granted to a public principal — "
            f"whatever the underlying datasets contain is readable by anyone with the "
            f"link, with no AWS credential required"
            if everyone else ""),
    }


# ── AWS IAM Identity Center ─────────────────────────────────────────────────
def sso_permission_set(name: str, inline_policy) -> dict:
    """A permission set granting everything is org-wide admin for its assignees.

    Permission sets are how humans actually get access in a multi-account org, and an
    over-broad one is invisible to a per-account IAM audit: the role it provisions looks
    ordinary in each account it lands in."""
    stmts = _stmts(inline_policy)
    wide = [s for s in stmts
            if s.get("Effect") == "Allow"
            and _is_wild(s.get("Action")) and _is_wild(s.get("Resource"))]
    return {
        "permission_set": name or "",
        "parsed": bool(stmts),
        "admin": bool(wide),
        "statement": (
            f"Permission set {name} has an inline policy allowing every action on every "
            f"resource — everyone assigned it holds administrator in every account the "
            f"set is provisioned into, and a per-account IAM review will not show where "
            f"that came from"
            if wide else ""),
    }


# ── AWS Glue ────────────────────────────────────────────────────────────────
def glue_catalog_encryption(settings: Optional[dict]) -> dict:
    """Catalog encryption mode and — the sharper one — connection-password handling."""
    s = _d(settings)
    at_rest = _d(s.get("EncryptionAtRest"))
    conn = _d(s.get("ConnectionPasswordEncryption"))
    mode = at_rest.get("CatalogEncryptionMode") or ""
    enc_pw = conn.get("ReturnConnectionPasswordEncrypted")
    return {
        "mode": mode,
        "mode_known": bool(mode),
        "encrypted": bool(mode) and mode != DISABLED,
        "password_known": isinstance(enc_pw, bool),
        "passwords_encrypted": enc_pw is True,
        "statement": (
            "The Glue Data Catalog is not encrypted at rest (CatalogEncryptionMode is "
            "DISABLED) — the catalog holds table schemas, column names and storage "
            "locations for the whole data estate, which is a map of where everything is"
            if mode == DISABLED else ""),
        "password_statement": (
            "Glue returns connection passwords in CLEARTEXT "
            "(ReturnConnectionPasswordEncrypted is false) — anyone able to call "
            "GetConnection reads the stored credential for every JDBC source the "
            "catalog knows about, which is usually the production databases"
            if enc_pw is False else ""),
    }


def glue_dev_endpoint(endpoint: Optional[dict]) -> dict:
    """A Glue development endpoint with a public address."""
    e = _d(endpoint)
    pub = e.get("PublicAddress") or ""
    return {
        "name": e.get("EndpointName") or "",
        "public_address": pub,
        "public": bool(pub),
        "role": e.get("RoleArn") or "",
        "statement": (
            f"Glue development endpoint {e.get('EndpointName')} has a public address "
            f"({pub}) — it is an interactive shell holding the endpoint's IAM role, "
            f"reachable from the internet"
            if pub else ""),
    }


# ══════════════════════════════════════════════════════════════════════════════
# Check declarations. Each one produces its severity, compliance mapping,
# remediation, detail page and ledger entry — see aws_checkdef.
# ══════════════════════════════════════════════════════════════════════════════
_ENC = {"PCI-DSS": "3.5.1", "HIPAA": "164.312(a)(2)(iv)", "SOC2": "CC6.1",
        "NIST": "SC-28"}
_NET = {"PCI-DSS": "1.3.1", "HIPAA": "164.312(e)(1)", "SOC2": "CC6.6", "NIST": "SC-7"}
_LOG = {"PCI-DSS": "10.2.1", "HIPAA": "164.312(b)", "SOC2": "CC7.2", "NIST": "AU-2"}
_ACC = {"PCI-DSS": "7.2.1", "HIPAA": "164.312(a)(1)", "SOC2": "CC6.3", "NIST": "AC-3"}
_PRIV = {"PCI-DSS": "7.2.1", "HIPAA": "164.312(a)(1)", "SOC2": "CC6.3", "NIST": "AC-6"}

CHECKS = _cd.register(
    _C(id="NFW-01", section="NETWORKFIREWALL", severity="MEDIUM", compliance=_LOG,
       permissions=(
           _P("network-firewall:ListFirewalls",
              "enumerate the firewalls deployed in this account and region"),
           _P("network-firewall:DescribeLoggingConfiguration",
              "read LogDestinationConfigs -- whether the firewall records any of what it inspects, which is the only artefact an investigation can use"),
       ),
       remediation=(
           "Give the firewall somewhere to log, or it is inspecting traffic and keeping "
           "none of it: aws network-firewall update-logging-configuration --firewall-name "
           "<NAME> --logging-configuration "
           "LogDestinationConfigs=[{LogType=FLOW,LogDestinationType=S3,"
           "LogDestination={bucketName=<BUCKET>}}] . Configure ALERT as well as FLOW — "
           "FLOW alone records that traffic passed, not that a rule matched it"),
       risk=(
           "This AWS Network Firewall has no logging destination configured, so it is "
           "inspecting traffic and recording none of what it sees. That is an expensive "
           "way to have no evidence: the firewall is doing the work of examining every "
           "packet and then discarding the one artefact an investigation would want. "
           "Network Firewall produces two log types and they answer different questions "
           "-- FLOW records the connections that traversed the firewall, and ALERT "
           "records the rule matches. Without ALERT you cannot tell whether a rule ever "
           "fired; without FLOW you cannot reconstruct what talked to what. In an "
           "incident this is usually the difference between scoping an intrusion to a "
           "handful of hosts and having to assume the whole VPC."),
       impact=("The firewall inspects traffic and retains no record of it, so neither "
               "connections nor rule matches can be reconstructed after an incident."),
       steps=(
           "Create or choose a destination -- S3 for retention, CloudWatch Logs for "
           "alerting, Kinesis Data Firehose for onward delivery.",
           "Attach it: aws network-firewall update-logging-configuration --firewall-name "
           "<NAME> --logging-configuration LogDestinationConfigs=[...]",
           "Configure BOTH FLOW and ALERT types -- they answer different questions and "
           "FLOW alone will not tell you whether a rule matched.",
           "Confirm records are arriving rather than assuming they are, then set a "
           "retention period matching your investigation window.")),

    _C(id="NFW-02", section="NETWORKFIREWALL", severity="HIGH", compliance=_NET,
       permissions=(
           _P("network-firewall:DescribeFirewall",
              "resolve each firewall to the policy ARN it enforces"),
           _P("network-firewall:DescribeFirewallPolicy",
              "read StatelessDefaultActions -- aws:pass forwards unmatched packets, so the firewall fails open and the stateful rules are never consulted"),
       ),
       remediation=(
           "Change the stateless default so unmatched packets are not simply forwarded. "
           "Inspect the policy first: aws network-firewall describe-firewall-policy "
           "--firewall-policy-name <NAME>. Then set the default to aws:drop or "
           "aws:forward_to_sfe so unmatched traffic reaches the stateful engine rather "
           "than passing unexamined: aws network-firewall update-firewall-policy "
           "--firewall-policy-name <NAME> --firewall-policy file://policy.json"),
       risk=(
           "The stateless default action on this firewall policy is aws:pass, which "
           "means a packet matching no stateless rule is FORWARDED without further "
           "examination. The firewall fails open rather than closed. This is worth "
           "checking rather than assuming because it inverts what most people believe "
           "they deployed: a firewall is generally understood to deny what it was not "
           "told to allow, and this configuration does the opposite. The usual correct "
           "value is aws:forward_to_sfe, which hands unmatched packets to the stateful "
           "engine where the real rule groups live -- with aws:pass they bypass that "
           "engine entirely, so every stateful rule you wrote is simply not consulted "
           "for traffic the stateless rules did not match. The result is a firewall that "
           "appears configured, passes review, and inspects far less than intended."),
       impact=("Packets matching no stateless rule are forwarded without reaching the "
               "stateful engine, so the stateful rule groups are never consulted for "
               "them."),
       steps=(
           "Read the current policy: aws network-firewall describe-firewall-policy "
           "--firewall-policy-name <NAME>",
           "Decide between aws:forward_to_sfe (usual: hand unmatched packets to the "
           "stateful engine) and aws:drop (strict).",
           "Apply it: aws network-firewall update-firewall-policy --firewall-policy-name "
           "<NAME> --firewall-policy file://policy.json",
           "Watch FLOW and ALERT logs after the change -- tightening a default action is "
           "exactly the change that surfaces traffic nobody knew about.")),

    _C(id="NFW-03", section="NETWORKFIREWALL", severity="MEDIUM", compliance=_NET,
       permissions=(
           _P("network-firewall:DescribeFirewall",
              "read DeleteProtection and the change-protection flags -- removing an inspection point is quieter than defeating it"),
       ),
       remediation=(
           "Turn the protections back on so the firewall cannot be removed or routed "
           "around in one call: aws network-firewall update-firewall-delete-protection "
           "--firewall-name <NAME> --delete-protection, then aws network-firewall "
           "update-subnet-change-protection --firewall-name <NAME> "
           "--subnet-change-protection, then aws network-firewall "
           "update-firewall-policy-change-protection --firewall-name <NAME> "
           "--firewall-policy-change-protection"),
       risk=(
           "This firewall has one or more of its protection flags disabled: delete "
           "protection, subnet change protection, or firewall policy change protection. "
           "These are not security controls in the sense of blocking traffic -- they are "
           "controls on the firewall itself, and they matter because removing an "
           "inspection point is quieter and quicker than defeating it. An intruder who "
           "reaches the console does not need to find a way through a firewall that can "
           "simply be deleted, or whose subnet associations can be edited so traffic no "
           "longer traverses it at all. Subnet change protection is the subtle one: "
           "detaching the firewall from a subnet leaves the firewall present and "
           "healthy-looking in every inventory while traffic quietly stops being "
           "inspected, which is considerably harder to notice than a deletion."),
       impact=("The firewall can be deleted, detached from its subnets, or have its "
               "policy swapped in a single API call, removing inspection without "
               "defeating it."),
       steps=(
           "Enable delete protection: aws network-firewall "
           "update-firewall-delete-protection --firewall-name <NAME> --delete-protection",
           "Enable subnet change protection -- detaching a firewall is quieter than "
           "deleting it: aws network-firewall update-subnet-change-protection "
           "--firewall-name <NAME> --subnet-change-protection",
           "Enable policy change protection: aws network-firewall "
           "update-firewall-policy-change-protection --firewall-name <NAME> "
           "--firewall-policy-change-protection",
           "Alarm on the corresponding CloudTrail events so a deliberate change by an "
           "administrator is still visible.")),

    _C(id="LSAIL-01", section="LIGHTSAIL", severity="HIGH", compliance=_NET,
       permissions=(
           _P("lightsail:GetInstances",
              "enumerate Lightsail instances, which are invisible to an EC2 inventory"),
           _P("lightsail:GetInstancePortStates",
              "read the Lightsail per-instance firewall, which is NOT a security group and so is invisible to an EC2 security-group audit"),
       ),
       remediation=(
           "Close the world-open ports on the Lightsail instance firewall, which is "
           "separate from EC2 security groups: aws lightsail "
           "get-instance-port-states --instance-name <NAME> to see them, then aws "
           "lightsail close-instance-public-ports --instance-name <NAME> "
           "--port-info fromPort=<PORT>,toPort=<PORT>,protocol=tcp . Re-open scoped to "
           "known CIDRs with open-instance-public-ports if the service is genuinely "
           "needed"),
       risk=(
           "This Lightsail instance accepts traffic from the entire internet on one or "
           "more ports. Lightsail deserves separate attention rather than being treated "
           "as small EC2, because it is the part of AWS most likely to sit outside "
           "whatever governs the rest of the estate: it has its own console, its own "
           "firewall model that is not security groups, and it is frequently created by "
           "people who would not otherwise provision infrastructure. The practical "
           "consequence is that an EC2 security-group audit -- including OverWatch's own "
           "SEG and EXPOSURE checks -- does not see these rules at all, so a Lightsail "
           "instance can be the one internet-facing host in an otherwise carefully "
           "segmented account and never appear in the review that was supposed to catch "
           "it. Lightsail instances also commonly run stacks installed from a blueprint "
           "and then left unpatched."),
       impact=("The instance is directly reachable from the internet on the listed "
               "ports, and the rules permitting it are invisible to any EC2 "
               "security-group audit."),
       steps=(
           "List the current rules: aws lightsail get-instance-port-states "
           "--instance-name <NAME>",
           "Close what is not needed: aws lightsail close-instance-public-ports "
           "--instance-name <NAME> --port-info fromPort=<PORT>,toPort=<PORT>,protocol=tcp",
           "Where a service must stay reachable, re-open it scoped to known CIDRs rather "
           "than 0.0.0.0/0: aws lightsail open-instance-public-ports --instance-name "
           "<NAME> --port-info fromPort=<PORT>,toPort=<PORT>,protocol=tcp,cidrs=<CIDR>",
           "Ask whether the workload belongs in Lightsail at all -- if it is production "
           "and internet-facing, it likely wants the controls the main estate has.")),

    _C(id="LSAIL-02", section="LIGHTSAIL", severity="HIGH", compliance=_NET,
       permissions=(
           _P("lightsail:GetRelationalDatabases",
              "read publiclyAccessible on Lightsail managed databases, where the master password is the only control in front of the data"),
       ),
       remediation=(
           "Make the Lightsail managed database private so its endpoint stops resolving "
           "to a public address: aws lightsail update-relational-database "
           "--relational-database-name <NAME> --no-publicly-accessible . Reach it from "
           "your instances over the private endpoint instead, and rotate the master "
           "password afterwards"),
       risk=(
           "This Lightsail managed database is publicly accessible: its endpoint "
           "resolves to a public address and the only thing standing between the "
           "internet and the data is the database password. There is no security group, "
           "no VPC boundary and no network ACL in front of it in the way there would be "
           "for RDS -- Lightsail databases are reached directly. That makes the exposure "
           "quite different in character from an RDS instance marked publicly "
           "accessible, where several other controls usually still apply. Internet-"
           "reachable database endpoints are continuously scanned and subjected to "
           "credential stuffing against default and weak master usernames, and because "
           "Lightsail is often used for smaller or older projects, those credentials are "
           "frequently the ones least likely to have been rotated."),
       impact=("The database endpoint is reachable from the internet, with the master "
               "password as the only control in front of the data."),
       steps=(
           "Make it private: aws lightsail update-relational-database "
           "--relational-database-name <NAME> --no-publicly-accessible",
           "Reach it from your Lightsail instances over the private endpoint instead.",
           "Rotate the master password, treating it as exposed to credential stuffing "
           "for as long as the endpoint was public.",
           "Confirm backups are on while you are here: aws lightsail "
           "get-relational-database --relational-database-name <NAME>")),

    _C(id="PCA-01", section="PRIVATECA", severity="HIGH", compliance=_ACC,
       permissions=(
           _P("acm-pca:ListCertificateAuthorities",
              "enumerate the private certificate authorities in this account"),
           _P("acm-pca:GetPolicy",
              "read the CA resource policy -- a private CA is a trust root, so sharing it shares the ability to mint certificates the estate believes"),
       ),
       remediation=(
           "Remove the wildcard principal from the private CA resource policy -- a CA is "
           "a trust root, not an ordinary shared resource: aws acm-pca get-policy "
           "--resource-arn <CA_ARN> to read it, then aws acm-pca put-policy "
           "--resource-arn <CA_ARN> --policy file://scoped-policy.json naming specific "
           "accounts or an aws:PrincipalOrgID condition. Then audit issued certificates "
           "with aws acm-pca list-certificates --certificate-authority-arn <CA_ARN>"),
       risk=(
           "This AWS Private CA has a resource policy granting a wildcard principal. A "
           "private CA is not an ordinary resource being shared -- it is a TRUST ROOT. "
           "Anyone able to issue certificates from it can mint credentials that every "
           "system configured to trust this CA will accept as legitimate, which in most "
           "estates means internal service-to-service TLS, mutual TLS between "
           "microservices, VPN client authentication, and sometimes device identity. The "
           "attacker does not need to break any of those systems: they ask your CA for a "
           "certificate with whatever subject they like and are then trusted by "
           "construction. This is also very hard to detect after the fact, because the "
           "resulting certificates are genuine -- they validate correctly, chain to a CA "
           "you deliberately deployed, and appear in no list of compromised material."),
       impact=("Anyone matching the wildcard can issue certificates your estate trusts "
               "by construction, enabling impersonation of internal services with "
               "genuine, correctly-chaining credentials."),
       steps=(
           "Read the policy: aws acm-pca get-policy --resource-arn <CA_ARN>",
           "Replace it with one naming specific accounts, or gated on aws:PrincipalOrgID: "
           "aws acm-pca put-policy --resource-arn <CA_ARN> --policy "
           "file://scoped-policy.json",
           "Audit what has already been issued -- the certificates are genuine and will "
           "not look anomalous: aws acm-pca list-certificates "
           "--certificate-authority-arn <CA_ARN>",
           "Revoke anything unexpected and consider whether the CA itself should be "
           "rotated, since you cannot distinguish attacker-requested certificates from "
           "legitimate ones by inspection.")),

    _C(id="QS-01", section="QUICKSIGHT", severity="HIGH", compliance=_ACC,
       permissions=(
           _P("quicksight:DescribeAccountSettings",
              "read PublicSharingEnabled -- whether dashboards over the warehouses may be published to anonymous readers"),
       ),
       remediation=(
           "Turn off account-level public sharing unless you deliberately publish "
           "dashboards to the world: aws quicksight update-public-sharing-settings "
           "--aws-account-id <ACCOUNT_ID> --no-public-sharing-enabled . Then audit which "
           "dashboards were shared while it was on: aws quicksight list-dashboards "
           "--aws-account-id <ACCOUNT_ID>"),
       risk=(
           "QuickSight public sharing is enabled at the account level, which permits any "
           "dashboard in the account to be published so that anyone with the link can "
           "read it, with no AWS credential required. The reason this matters more than "
           "a comparable setting elsewhere is where QuickSight sits: it is layered ON TOP "
           "of your warehouses and lakes -- Redshift, Athena, S3, RDS -- and it reads "
           "them using its own service credentials. A dashboard published to the "
           "internet is therefore a data export path that bypasses the underlying "
           "datastore's access controls entirely. Every control you placed on the "
           "warehouse is still in force and still irrelevant, because the data has "
           "already been read on QuickSight's behalf and rendered. Enabling the account "
           "switch does not publish anything by itself, which is precisely why it drifts "
           "on and stays on."),
       impact=("Any dashboard in the account can be published to anonymous readers, "
               "exposing warehouse data through a path that bypasses the datastore's own "
               "access controls."),
       steps=(
           "Disable it unless public dashboards are a deliberate product decision: aws "
           "quicksight update-public-sharing-settings --aws-account-id <ACCOUNT_ID> "
           "--no-public-sharing-enabled",
           "Audit what was shared while it was on: aws quicksight list-dashboards "
           "--aws-account-id <ACCOUNT_ID>",
           "For each, read the permissions: aws quicksight describe-dashboard-permissions "
           "--aws-account-id <ACCOUNT_ID> --dashboard-id <ID>",
           "Treat data behind any dashboard that was publicly shared as disclosed for "
           "that window -- anonymous reads leave no per-viewer trail.")),

    # CIS AWS Foundations v7.0.0 2.14 asks that no policy granting Action:* on Resource:*
    # be attached to anything. An Identity Center permission set with that inline is the
    # same defect on a surface an audit that only reads iam: APIs never sees, so it is
    # part of 2.14's covering set. Merged rather than added to _PRIV: that constant is
    # shared, and editing it would silently cite 2.14 on every check that uses it.
    _C(id="SSO-01", section="IDENTITYCENTER", severity="HIGH",
       compliance={**_PRIV, "CIS": "2.14"},
       permissions=(
           _P("sso:ListInstances",
              "locate the IAM Identity Center instance for this organization"),
           _P("sso:ListPermissionSets",
              "enumerate permission sets, which are how humans actually obtain access across a multi-account organization"),
           _P("sso:GetInlinePolicyForPermissionSet",
              "read the inline policy -- a wildcard grant here is administrator in every account the set is provisioned into"),
       ),
       remediation=(
           "Scope the permission set rather than granting everything: aws sso-admin "
           "get-inline-policy-for-permission-set --instance-arn <INSTANCE_ARN> "
           "--permission-set-arn <PS_ARN> to read it, then aws sso-admin "
           "put-inline-policy-to-permission-set --instance-arn <INSTANCE_ARN> "
           "--permission-set-arn <PS_ARN> --inline-policy file://scoped.json . "
           "Provision the change with aws sso-admin provision-permission-set, or the "
           "accounts keep the old policy"),
       risk=(
           "This IAM Identity Center permission set has an inline policy allowing every "
           "action on every resource. Permission sets are how humans actually obtain "
           "access in a multi-account organisation, so this is not one over-privileged "
           "role -- it is administrator in every account the set is provisioned into, "
           "for everyone assigned it, including whatever groups are synced from your "
           "identity provider. The part that makes it genuinely hard to catch is that it "
           "is close to invisible from below: Identity Center provisions an ordinary IAM "
           "role into each target account, so a per-account IAM review sees a role with "
           "broad permissions and no indication of who can assume it or that the grant "
           "originates centrally. Assignment also happens in the identity provider, so "
           "the population holding this can grow without any change in AWS at all."),
       impact=("Everyone assigned this permission set holds administrator in every "
               "account it is provisioned into, and a per-account IAM review does not "
               "reveal where the grant came from or who holds it."),
       steps=(
           "Read the policy: aws sso-admin get-inline-policy-for-permission-set "
           "--instance-arn <INSTANCE_ARN> --permission-set-arn <PS_ARN>",
           "Find out who actually holds it before changing anything: aws sso-admin "
           "list-account-assignments --instance-arn <INSTANCE_ARN> --account-id "
           "<ACCOUNT_ID> --permission-set-arn <PS_ARN>",
           "Replace it with a scoped policy: aws sso-admin "
           "put-inline-policy-to-permission-set --instance-arn <INSTANCE_ARN> "
           "--permission-set-arn <PS_ARN> --inline-policy file://scoped.json",
           "Re-provision, or target accounts keep the old policy: aws sso-admin "
           "provision-permission-set --instance-arn <INSTANCE_ARN> --permission-set-arn "
           "<PS_ARN> --target-type ALL_PROVISIONED_ACCOUNTS",
           "Keep a genuine break-glass administrator set, assigned to very few people "
           "and alarmed on use, rather than removing administrative access entirely.")),

    _C(id="GLUE-01", section="GLUE", severity="HIGH", compliance=_ENC,
       permissions=(
           _P("glue:GetDataCatalogEncryptionSettings",
              "read ReturnConnectionPasswordEncrypted -- when false the catalog hands back stored database passwords in cleartext to any GetConnection caller"),
       ),
       remediation=(
           "Stop the Data Catalog handing back connection passwords in cleartext: aws "
           "glue put-data-catalog-encryption-settings --data-catalog-encryption-settings "
           "'{\"ConnectionPasswordEncryption\":{\"ReturnConnectionPasswordEncrypted\":true,"
           "\"AwsKmsKeyId\":\"<KEY_ARN>\"},\"EncryptionAtRest\":"
           "{\"CatalogEncryptionMode\":\"SSE-KMS\",\"SseAwsKmsKeyId\":\"<KEY_ARN>\"}}' . "
           "Then rotate every credential stored in a Glue connection"),
       risk=(
           "The Glue Data Catalog is configured to return connection passwords in "
           "cleartext, and separately may hold the catalog itself unencrypted. The "
           "password half is the sharper problem and is easy to miss because it is not a "
           "storage setting -- it governs what the API HANDS BACK. With "
           "ReturnConnectionPasswordEncrypted set to false, any principal able to call "
           "glue:GetConnection receives the stored credential in the clear, for every "
           "JDBC connection the catalog knows about. In a typical data platform those "
           "connections point at the production databases: the warehouse, the "
           "operational replicas, the reporting stores. So a permission that reads like "
           "metadata access -- looking up how to connect to something -- is in practice "
           "a credential dispenser for the estate's most valuable datastores. The "
           "catalog encryption half matters for a different reason: the catalog is a map "
           "of where all the data lives, which is exactly what reconnaissance wants."),
       impact=("Any principal able to call glue:GetConnection reads stored database "
               "credentials in cleartext, typically for the production data stores."),
       steps=(
           "Read the current settings: aws glue get-data-catalog-encryption-settings",
           "Enable both password encryption and catalog encryption with a CMK: aws glue "
           "put-data-catalog-encryption-settings --data-catalog-encryption-settings "
           "'{\"ConnectionPasswordEncryption\":{\"ReturnConnectionPasswordEncrypted\":"
           "true,\"AwsKmsKeyId\":\"<KEY_ARN>\"},\"EncryptionAtRest\":"
           "{\"CatalogEncryptionMode\":\"SSE-KMS\",\"SseAwsKmsKeyId\":\"<KEY_ARN>\"}}'",
           "Rotate every credential stored in a Glue connection -- they were retrievable "
           "in cleartext by anyone holding glue:GetConnection.",
           "Audit who holds glue:GetConnection and narrow it; it reads like a metadata "
           "permission and is not one.")),

    _C(id="GLUE-02", section="GLUE", severity="MEDIUM", compliance=_NET,
       permissions=(
           _P("glue:GetDevEndpoints",
              "read PublicAddress on Glue development endpoints, which are interactive shells holding the endpoint IAM role"),
       ),
       remediation=(
           "Glue development endpoints cannot be made private in place -- delete the "
           "endpoint and use an interactive session or a VPC-attached endpoint instead: "
           "aws glue delete-dev-endpoint --endpoint-name <NAME>. If interactive "
           "development is genuinely needed, recreate it inside a VPC subnet with a "
           "security group: aws glue create-dev-endpoint --endpoint-name <NAME> "
           "--role-arn <ROLE_ARN> --subnet-id <SUBNET> --security-group-ids <SG>"),
       risk=(
           "This Glue development endpoint has a public address. A development endpoint "
           "is an interactive environment -- typically reached over SSH or through a "
           "notebook -- that runs holding the endpoint's IAM role, and that role is "
           "usually generous, because the whole purpose of the endpoint is exploratory "
           "work against the data estate. A publicly addressed one is therefore an "
           "internet-reachable interactive shell attached to a role with broad data "
           "access. Development endpoints are also unusually likely to be forgotten: "
           "they are created for a specific piece of work, they are billed hourly, and "
           "they persist quietly long after the person who created them has moved on. "
           "They are worth checking specifically because they are neither a workload nor "
           "a datastore, so they tend not to appear in either inventory."),
       impact=("An internet-reachable interactive endpoint runs with the Glue role's "
               "data access, and such endpoints commonly outlive the work that created "
               "them."),
       steps=(
           "Establish whether it is still in use: aws glue get-dev-endpoint "
           "--endpoint-name <NAME>",
           "Prefer deleting it -- interactive sessions have largely replaced development "
           "endpoints: aws glue delete-dev-endpoint --endpoint-name <NAME>",
           "If interactive development is genuinely required, recreate it inside a VPC "
           "subnet with a security group: aws glue create-dev-endpoint --endpoint-name "
           "<NAME> --role-arn <ROLE_ARN> --subnet-id <SUBNET> --security-group-ids <SG>",
           "Review what the endpoint's role can reach, since anyone who got to the "
           "endpoint held it.")),
)
