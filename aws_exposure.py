#!/usr/bin/env python3
"""aws_exposure.py — effective internet-reachability oracle for the AWS CNAPP (Phase 2).

The hard, correctness-critical core of the exposure engine, kept **boto3-free and
pure** so the whole false-positive/false-negative catalog runs without AWS. An
EC2 ENI is judged internet-reachable only when ALL FOUR gates pass — never on
"a security group allows 0.0.0.0/0" alone, which is the industry's #1 false positive:

  1. Public entry point   — the ENI has a public IPv4 (auto-assigned or EIP) or a
                            global IPv6 address, evaluated per address family.
  2. IGW default route    — the subnet's effective route table has an ACTIVE default
                            route (0.0.0.0/0 or ::/0) to a real internet gateway
                            (igw-…), not a NAT/egress-only-IGW/blackhole target.
  3. SG public ports      — union of ingress rules opens ports to 0.0.0.0/0 / ::/0
                            (sg-references and prefix-lists are NOT public).
  4. Stateless NACL       — the subnet NACL allows the inbound service port AND the
                            OUTBOUND ephemeral return (1024-65535). NACLs are
                            stateless and evaluated in ascending rule-number order,
                            first match wins.

Everything takes raw boto3 response shapes (exact field names) so tests mirror
reality. This module stays the boto3-free L3/L4 oracle for DIRECT ENIs; the
Phase-7 L7 axis (internet-facing ALB/NLB/CloudFront/API-Gateway front resolution
-> LoadBalancer/front graph nodes + TARGETS edges) lives in
``aws_live_scanner._build_l7_exposure``, which reuses ``sg_public_ports`` here so
this file remains boto3-free and purely testable. Grounded in a verified
AWS-semantics research pass; see the FP/FN catalog in tests/test_exposure.py.
"""
from __future__ import annotations

from typing import Dict, List, Optional, Tuple, Set

Port = Tuple[str, int, int]   # (proto, from_port, to_port)

# Well-known sensitive service ports (raise finding severity when internet-exposed)
SENSITIVE_PORTS: Dict[int, str] = {
    22: "SSH", 23: "Telnet", 21: "FTP", 3389: "RDP", 445: "SMB", 135: "RPC",
    139: "NetBIOS", 3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL",
    1521: "Oracle", 27017: "MongoDB", 6379: "Redis", 11211: "Memcached",
    9200: "Elasticsearch", 9300: "Elasticsearch", 5984: "CouchDB",
    2379: "etcd", 2375: "Docker", 2376: "Docker-TLS", 5900: "VNC",
    6443: "Kubernetes-API", 10250: "Kubelet", 8020: "HDFS", 7199: "Cassandra",
}


# ─── helpers ─────────────────────────────────────────────────────────────────
def _int(v, default: int) -> int:
    return default if v is None else int(v)


def _merge(intervals: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    """Merge overlapping/adjacent (lo, hi) intervals into a minimal sorted list."""
    if not intervals:
        return []
    s = sorted(intervals)
    out = [list(s[0])]
    for lo, hi in s[1:]:
        if lo <= out[-1][1] + 1:
            out[-1][1] = max(out[-1][1], hi)
        else:
            out.append([lo, hi])
    return [(a, b) for a, b in out]


def is_public_cidr(cidr: str, family: str) -> bool:
    """True only for the whole internet (0.0.0.0/0 or ::/0). Narrower public
    ranges (split-CIDR) are deliberately deferred and fail closed."""
    if family == "ipv4":
        return cidr == "0.0.0.0/0"
    return cidr == "::/0"


# ─── Gate 1: public entry point ──────────────────────────────────────────────
def classify_public_ip(association: Optional[dict], ipv6_addrs: Optional[list]) -> Dict:
    """Classify an ENI's internet entry point per family.

    Returns ``{'ipv4': None|'auto'|'eip', 'ipv6': bool}``. An EIP is identified by
    ``Association.AllocationId`` (eipalloc-…) or an ``IpOwnerId`` that is a real
    account id; an auto-assigned public IPv4 has ``IpOwnerId=='amazon'`` and no
    AllocationId (ephemeral — changes on stop/start). Any global IPv6 counts as a
    public entry (no NAT for IPv6).
    """
    out = {"ipv4": None, "ipv6": bool(ipv6_addrs)}
    if association and association.get("PublicIp"):
        owner = association.get("IpOwnerId")
        if association.get("AllocationId") or (owner and owner != "amazon"):
            out["ipv4"] = "eip"
        else:
            out["ipv4"] = "auto"
    return out


# ─── Gate 2: IGW default route ───────────────────────────────────────────────
def find_effective_route_table(subnet_id: str, vpc_id: str,
                               route_tables: List[dict]) -> Optional[dict]:
    """Explicit subnet association wins; otherwise the subnet inherits the VPC
    main route table (forgetting this fallback is a classic false negative)."""
    main = None
    for rt in route_tables:
        for a in rt.get("Associations", []):
            state = (a.get("AssociationState") or {}).get("State", "associated")
            if a.get("SubnetId") == subnet_id and state == "associated":
                return rt
            if a.get("Main") and rt.get("VpcId") == vpc_id:
                main = rt
    return main


def has_igw_default_route(route_table: Optional[dict], family: str) -> bool:
    """Active default route to a real internet gateway (igw-…). Rejects NAT,
    egress-only IGW, instance/ENI, peering, TGW, VPC-endpoint targets and
    blackhole routes — only a true IGW gives inbound reachability."""
    if not route_table:
        return False
    for r in route_table.get("Routes", []):
        if r.get("State") == "blackhole":
            continue
        gw = r.get("GatewayId") or ""
        if not gw.startswith("igw-"):
            continue
        if family == "ipv4" and r.get("DestinationCidrBlock") == "0.0.0.0/0":
            return True
        if family == "ipv6" and r.get("DestinationIpv6CidrBlock") == "::/0":
            return True
    return False


# ─── Gate 3: security-group public ports ─────────────────────────────────────
def sg_public_ports(ip_permissions: Optional[List[dict]], family: str) -> Set[Port]:
    """Publicly-open ``(proto, from, to)`` from the union of ingress rules, for the
    given family. Excludes ``UserIdGroupPairs`` (sg-references — intra-VPC, the #1
    false positive) and ``PrefixListIds`` (unresolved → not public). Expands
    ``IpProtocol='-1'`` (all protocols/ports, with FromPort/ToPort absent) into
    full tcp+udp — skipping it is the #1 false negative."""
    out: Set[Port] = set()
    for perm in ip_permissions or []:
        proto = str(perm.get("IpProtocol"))
        if family == "ipv4":
            public = any(r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", []))
        else:
            public = any(r.get("CidrIpv6") == "::/0" for r in perm.get("Ipv6Ranges", []))
        if not public:
            continue
        pl = proto.lower()
        if proto == "-1":
            out.add(("tcp", 0, 65535))
            out.add(("udp", 0, 65535))
        elif pl in ("tcp", "6"):
            out.add(("tcp", _int(perm.get("FromPort"), 0), _int(perm.get("ToPort"), 65535)))
        elif pl in ("udp", "17"):
            out.add(("udp", _int(perm.get("FromPort"), 0), _int(perm.get("ToPort"), 65535)))
        elif pl in ("icmp", "1", "icmpv6", "58"):
            out.add(("icmp", _int(perm.get("FromPort"), -1), _int(perm.get("ToPort"), -1)))
        # any other numeric protocol (e.g. GRE 47) opens no tcp/udp service port → skip
    return out


# ─── Gate 4: stateless NACL ──────────────────────────────────────────────────
def find_governing_nacl(subnet_id: str, vpc_id: str,
                        nacls: List[dict]) -> Optional[dict]:
    """Explicit subnet association wins; else the VPC default NACL (allow-all)."""
    default = None
    for n in nacls:
        for a in n.get("Associations", []):
            if a.get("SubnetId") == subnet_id:
                return n
        if n.get("IsDefault") and n.get("VpcId") == vpc_id:
            default = n
    return default


def _entry_port_span(entry: dict, flow_proto: str) -> Optional[Tuple[int, int]]:
    """Port span an NACL entry covers for a tcp/udp flow, or None if the entry's
    protocol doesn't apply. Protocol is an IANA number STRING ('-1'=all/6/17)."""
    p = str(entry.get("Protocol", "-1"))
    if p == "-1":
        return (0, 65535)
    want = {"tcp": "6", "udp": "17"}.get(flow_proto)
    if p != want:
        return None
    pr = entry.get("PortRange") or {}
    return (_int(pr.get("From"), 0), _int(pr.get("To"), 65535))


def nacl_allowed_subranges(nacl: Optional[dict], egress: bool, proto: str,
                           family: str, lo: int, hi: int) -> List[Tuple[int, int]]:
    """Sub-ranges of [lo, hi] that first-match an ALLOW for a tcp/udp flow, under
    ordered (ascending RuleNumber) first-match-wins evaluation, considering only
    whole-internet entries (0.0.0.0/0 / ::/0). A None NACL, or an entry-less
    default NACL, allows all."""
    if nacl is None:
        return [(lo, hi)]
    entries = nacl.get("Entries") or []
    if not entries:
        # No rules to evaluate: an unmodified default NACL allows all; a custom
        # NACL with no allow rule denies all. (The AWS default NACL always ships
        # allow-all rules — but if an admin EDITS it, those edits are enforced
        # below, so we must NOT blanket-allow on IsDefault alone.)
        return [(lo, hi)] if nacl.get("IsDefault") else []

    rules = []
    for e in entries:
        if bool(e.get("Egress")) != egress:
            continue
        if family == "ipv4":
            if e.get("CidrBlock") != "0.0.0.0/0":
                continue
        else:
            if e.get("Ipv6CidrBlock") != "::/0":
                continue
        span = _entry_port_span(e, proto)
        if span is None:
            continue
        rules.append({"num": _int(e.get("RuleNumber"), 32767),
                      "action": str(e.get("RuleAction", "deny")).lower(),
                      "span": span})
    rules.sort(key=lambda r: r["num"])

    undecided = [(lo, hi)]
    allowed: List[Tuple[int, int]] = []
    for r in rules:
        if not undecided:
            break
        s_lo, s_hi = r["span"]
        nxt = []
        for (u_lo, u_hi) in undecided:
            i_lo, i_hi = max(u_lo, s_lo), min(u_hi, s_hi)
            if i_lo > i_hi:                      # no overlap — still undecided
                nxt.append((u_lo, u_hi))
                continue
            if r["action"] == "allow":
                allowed.append((i_lo, i_hi))
            # deny: the intersected part is denied (dropped); either way the
            # remainder outside the intersection stays undecided for later rules
            if u_lo < i_lo:
                nxt.append((u_lo, i_lo - 1))
            if i_hi < u_hi:
                nxt.append((i_hi + 1, u_hi))
        undecided = nxt
    return _merge(allowed)


def nacl_range_fully_allowed(nacl: Optional[dict], egress: bool, proto: str,
                             family: str, lo: int, hi: int) -> bool:
    subs = nacl_allowed_subranges(nacl, egress, proto, family, lo, hi)
    return sum(b - a + 1 for a, b in subs) == (hi - lo + 1)


def nacl_permits_service(nacl: Optional[dict], proto: str, family: str,
                         port_lo: int, port_hi: int,
                         ephemeral: Tuple[int, int] = (1024, 65535)
                         ) -> List[Tuple[int, int]]:
    """Sub-ranges of the inbound [port_lo, port_hi] that are actually reachable:
    inbound must allow the service port AND the outbound direction must allow the
    ENTIRE ephemeral return window (stateless return path). If the return window
    isn't fully allowed, nothing is reachable."""
    if not nacl_range_fully_allowed(nacl, True, proto, family, *ephemeral):
        return []
    return nacl_allowed_subranges(nacl, False, proto, family, port_lo, port_hi)


# ─── the 4-gate AND ──────────────────────────────────────────────────────────
def compute_exposure(eni: dict, route_table: Optional[dict], nacl: Optional[dict],
                     sg_ip_permissions: List[dict]) -> Dict[str, Set[Port]]:
    """Return ``{family: {(proto, from, to), …}}`` of internet-reachable ports for
    an ENI, per address family, as the AND of all four gates. Empty dict == not
    exposed. ``eni`` carries ``ipv4_public`` (None|'auto'|'eip') and ``ipv6_public``
    (bool); managed ENIs (nat/lb/endpoint) should be filtered by the caller."""
    result: Dict[str, Set[Port]] = {}
    for family in ("ipv4", "ipv6"):
        # Gate 1 — public entry point
        if family == "ipv4" and eni.get("ipv4_public") not in ("auto", "eip"):
            continue
        if family == "ipv6" and not eni.get("ipv6_public"):
            continue
        # Gate 2 — active IGW default route
        if not has_igw_default_route(route_table, family):
            continue
        # Gate 3 — SG opens ports to the internet
        pub = sg_public_ports(sg_ip_permissions, family)
        if not pub:
            continue
        # Gate 4 — stateless NACL allows inbound service + outbound ephemeral return
        exposed: Set[Port] = set()
        for (proto, lo, hi) in pub:
            if proto not in ("tcp", "udp"):
                continue                         # ICMP/other opens no service port
            for (a, b) in nacl_permits_service(nacl, proto, family, lo, hi):
                exposed.add((proto, a, b))
        if exposed:
            result[family] = exposed
    return result


def iter_exposed_ports(port_set: Set[Port]):
    """Yield individual sensitive/notable ports and whether each is sensitive,
    plus a compact human summary of the exposed ranges."""
    ranges = sorted(port_set)
    summary = ", ".join(
        f"{proto}/{lo}" if lo == hi else f"{proto}/{lo}-{hi}"
        for proto, lo, hi in ranges
    )
    hits = []
    for proto, lo, hi in ranges:
        for port, name in SENSITIVE_PORTS.items():
            if lo <= port <= hi:
                hits.append((proto, port, name))
    return summary, hits


# ─── Layer A: static SG micro-segmentation (config-only, ZERO new grant) ──────
# Pure detection over the exact SG/ENI dicts the exposure engine already fetched.
# Distinct lens from compute_exposure's 4-gate oracle: SEG-* flag an OVER-PERMISSIVE
# SG regardless of whether the host is currently internet-REACHABLE (defence-in-depth
# / lateral concern), whereas EXPOSURE-01 confirms reachability. The two are
# complementary, never a double-FAIL on the same port: SEG-01 covers only the
# sensitive ports VPC-01 does NOT already handle.
#
# Ports the scanner's VPC-01 check (aws_live_scanner._check_vpc RISKY_PORTS) already
# FAILs on. Duplicated here (rather than imported) so this module stays boto3-free
# and self-contained; tests/test_exposure.py asserts SEG01_SENSITIVE_PORTS excludes
# every one of them so the two checks can never double-FAIL the same rule.
_VPC01_RISKY_PORTS = frozenset({22, 3389, 1433, 3306, 5432, 27017, 6379,
                                9200, 9300, 8080, 445})
# Expected-public web / ALB ports — 0.0.0.0/0 on these ALONE is normal, never a finding.
WEB_PORTS = frozenset({80, 443, 8443})
# A single world-open ingress rule spanning at least this many ports is "overly wide".
WIDE_SPAN = 100
# The sensitive ports SEG-01 flags = the sensitive set minus what VPC-01 already covers.
SEG01_SENSITIVE_PORTS: Dict[int, str] = {p: n for p, n in SENSITIVE_PORTS.items()
                                         if p not in _VPC01_RISKY_PORTS}


def _sg_world_ports(sg: dict) -> Set[Port]:
    """Union of (proto, lo, hi) an SG opens to the whole internet (v4+v6 ingress)."""
    ing = sg.get("IpPermissions", [])
    return sg_public_ports(ing, "ipv4") | sg_public_ports(ing, "ipv6")


def _span_hits(port_set: Set[Port], port_map: Dict[int, str]) -> List[Tuple[int, str]]:
    """Ports from ``port_map`` that fall inside any tcp/udp span in ``port_set``,
    sorted and de-duplicated as ``(port, name)``."""
    hits = set()
    for proto, lo, hi in port_set:
        if proto not in ("tcp", "udp"):
            continue
        for port, name in port_map.items():
            if lo <= port <= hi:
                hits.add((port, name))
    return sorted(hits)


def _egress_allows_all(sg: dict) -> bool:
    """True if the SG has an egress rule allowing ALL protocols to 0.0.0.0/0 — the
    AWS default on every security group (the seam Layer-B flow evidence tightens)."""
    for perm in sg.get("IpPermissionsEgress", []):
        if str(perm.get("IpProtocol")) == "-1" and any(
                r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", [])):
            return True
    return False


def _perm_grants(perm: dict) -> List[Tuple[str, str, str, int, int]]:
    """Atomic ``(family, cidr, proto, lo, hi)`` grants for one ingress permission,
    expanding ``-1`` to an all-protocol/all-port span. Only comparable IpRanges /
    Ipv6Ranges are returned; sg-references and prefix-lists are excluded (their
    coverage can't be compared by CIDR)."""
    proto = str(perm.get("IpProtocol"))
    if proto == "-1":
        pk, lo, hi = "all", 0, 65535
    elif proto in ("tcp", "6"):
        pk, lo, hi = "tcp", _int(perm.get("FromPort"), 0), _int(perm.get("ToPort"), 65535)
    elif proto in ("udp", "17"):
        pk, lo, hi = "udp", _int(perm.get("FromPort"), 0), _int(perm.get("ToPort"), 65535)
    elif proto in ("icmp", "1", "icmpv6", "58"):
        pk, lo, hi = "icmp", _int(perm.get("FromPort"), -1), _int(perm.get("ToPort"), -1)
    else:
        return []
    grants = []
    for r in perm.get("IpRanges", []):
        if r.get("CidrIp"):
            grants.append(("ipv4", r["CidrIp"], pk, lo, hi))
    for r in perm.get("Ipv6Ranges", []):
        if r.get("CidrIpv6"):
            grants.append(("ipv6", r["CidrIpv6"], pk, lo, hi))
    return grants


def _grant_covers(b, a) -> bool:
    """Does atomic grant ``b`` fully cover ``a``? Same family+CIDR, ``b`` protocol
    covers ``a`` (``all`` covers any), and ``b``'s port span contains ``a``'s."""
    fb, cb, pb, lob, hib = b
    fa, ca, pa, loa, hia = a
    if fb != fa or cb != ca:
        return False
    if pb != "all" and pb != pa:
        return False
    return lob <= loa and hia <= hib


def _covers_all(b_grants, a_grants) -> bool:
    """Every atomic grant in ``a_grants`` is covered by some grant in ``b_grants``
    (and ``a_grants`` is non-empty)."""
    return bool(a_grants) and all(any(_grant_covers(b, a) for b in b_grants)
                                  for a in a_grants)


def microseg_findings(sgs: Optional[List[dict]],
                      enis: Optional[List[dict]]) -> List[dict]:
    """Static SG micro-segmentation findings from raw boto3 ``describe_security_groups``
    + ``describe_network_interfaces`` shapes. Pure: no AWS, no graph, no side effects.
    Returns a list of ``{id,status,gid,gname,resource,message,attached,...}`` dicts the
    scanner maps onto ``_add`` + the graph overlay. All reachability is confirmed
    separately by the 4-gate ``compute_exposure`` (EXPOSURE-01)."""
    findings: List[dict] = []
    sgs = sgs or []
    enis = enis or []

    eni_attached: Set[str] = set()
    for e in enis:
        for grp in e.get("Groups", []):
            if grp.get("GroupId"):
                eni_attached.add(grp["GroupId"])
    # An SG referenced by another SG's rule (UserIdGroupPair, incl. cross-VPC
    # ReferencedGroupId) is NOT "unused" even if it touches no ENI — deleting it would
    # break the referencing rule. Include both keys so SEG-04 never mis-flags them.
    ref_by_rule: Set[str] = set()
    for sg in sgs:
        for perm in sg.get("IpPermissions", []) + sg.get("IpPermissionsEgress", []):
            for pair in perm.get("UserIdGroupPairs", []):
                for k in ("GroupId", "ReferencedGroupId"):
                    if pair.get(k):
                        ref_by_rule.add(pair[k])
    referenced = eni_attached | ref_by_rule

    world = {sg.get("GroupId"): _sg_world_ports(sg) for sg in sgs}

    for sg in sgs:
        gid = sg.get("GroupId")
        gname = sg.get("GroupName", "")
        res = f"{gid} ({gname})"
        node = f"sg/{gid}"
        w = world.get(gid) or set()
        attached = gid in eni_attached

        # SEG-02 — overly-wide world-open range (attached SGs only). sg_public_ports
        # has already expanded '-1' into full tcp+udp spans, so all-traffic is caught.
        wide = sorted((p, lo, hi) for (p, lo, hi) in w
                      if p in ("tcp", "udp") and (hi - lo + 1) >= WIDE_SPAN)
        seg02 = attached and bool(wide)
        if seg02:
            span_txt = ", ".join(f"{p}/{lo}-{hi}" for p, lo, hi in wide)
            total = sum(hi - lo + 1 for _, lo, hi in wide)
            sens = _span_hits(set(wide), SENSITIVE_PORTS)
            sens_txt = ("; includes sensitive " +
                        ", ".join(f"{n}({p})" for p, n in sens)) if sens else ""
            findings.append({
                "id": "SEG-02", "status": "FAIL", "gid": gid, "gname": gname,
                "resource": res, "attached": attached,
                "message": (f"Security group {res} opens an overly-wide port range to "
                            f"0.0.0.0/0 [{span_txt}] ({total} ports){sens_txt} — narrow to "
                            f"the specific service ports the workload needs | {node}")})

        # SEG-01 — world-open sensitive (non-web) port. Only the ports VPC-01 does NOT
        # cover, so the two checks never double-FAIL. Suppressed when SEG-02 already
        # fired for this SG (the wide-range finding subsumes it). Attached SGs only.
        if attached and not seg02:
            hits = _span_hits(w, SEG01_SENSITIVE_PORTS)
            if hits:
                svc = ", ".join(f"{n}({p})" for p, n in hits)
                findings.append({
                    "id": "SEG-01", "status": "FAIL", "gid": gid, "gname": gname,
                    "resource": res, "attached": attached,
                    "message": (f"Security group {res} opens sensitive port(s) {svc} to "
                                f"0.0.0.0/0 — restrict to trusted CIDRs or front the service "
                                f"with a load balancer (any live internet reachability is "
                                f"confirmed separately by EXPOSURE-01) | {node}")})

        # SEG-05 — chains to a world-open SG: an ingress sg-reference to a group that is
        # itself 0.0.0.0/0-open ⇒ internet → that group's host → here (attached target).
        if attached:
            chained = set()
            for perm in sg.get("IpPermissions", []):
                for pair in perm.get("UserIdGroupPairs", []):
                    ref = pair.get("ReferencedGroupId") or pair.get("GroupId")
                    if ref and ref != gid and world.get(ref):
                        chained.add(ref)
            if chained:
                refs = ", ".join(sorted(chained))
                findings.append({
                    "id": "SEG-05", "status": "FAIL", "gid": gid, "gname": gname,
                    "resource": res, "attached": attached, "chain_refs": sorted(chained),
                    "message": (f"Security group {res} allows ingress from group(s) {refs} that "
                                f"are themselves open to 0.0.0.0/0 — an internet-reachable host in "
                                f"the referenced group can pivot here (transitive exposure) | {node}")})

        # SEG-06 — internet-exposed SG that ALSO allows unrestricted egress ⇒ exfil path.
        # Tightly gated (attached + sensitive world-open inbound + egress-all) to stay
        # low-noise; the default all-egress on an isolated SG is not flagged here.
        if attached and _egress_allows_all(sg) and _span_hits(w, SENSITIVE_PORTS):
            findings.append({
                "id": "SEG-06", "status": "WARN", "gid": gid, "gname": gname,
                "resource": res, "attached": attached,
                "message": (f"Security group {res} is internet-exposed on a sensitive port AND "
                            f"allows unrestricted egress (all protocols to 0.0.0.0/0) — a "
                            f"compromised host can exfiltrate freely; restrict egress to the "
                            f"required destinations | {node}")})

        # SEG-03 — redundant / shadowed ingress rule (hygiene, INFO). Conservative:
        # flags a rule only when a SINGLE other rule fully covers it (never a union),
        # keeping the smallest-index rule on an exact duplicate. No false positives on
        # partial overlaps.
        perms_in = sg.get("IpPermissions", [])
        grants = [_perm_grants(p) for p in perms_in]
        for i, gi in enumerate(grants):
            if not gi:
                continue
            # A rule that ALSO grants access via sg-references or prefix-lists carries
            # grants _perm_grants does not model (an sg-ref matches by GROUP MEMBERSHIP,
            # not CIDR — its members' IPs can sit outside any covering CIDR, e.g. a peered
            # VPC), so a CIDR-only rule can never be proven to "fully cover" it. Skip the
            # covered-rule to avoid a false 'redundant, remove it' verdict.
            if perms_in[i].get("UserIdGroupPairs") or perms_in[i].get("PrefixListIds"):
                continue
            for j, gj in enumerate(grants):
                if j == i or not gj:
                    continue
                if _covers_all(gj, gi) and (not _covers_all(gi, gj) or j < i):
                    findings.append({
                        "id": "SEG-03", "status": "INFO", "gid": gid, "gname": gname,
                        "resource": res, "attached": attached,
                        "message": (f"Security group {res} has a redundant/shadowed ingress rule "
                                    f"(rule #{i + 1} is fully covered by a broader rule) — remove "
                                    f"it to simplify the policy | {node}")})
                    break

    # SEG-04 — unused SG (touches no ENI, referenced by no group, not the default SG).
    # FAIL-OPEN: if ENIs couldn't be enumerated at all we cannot tell unused from
    # can't-tell, so skip the check entirely rather than flag every SG.
    if enis:
        for sg in sgs:
            gid = sg.get("GroupId")
            gname = sg.get("GroupName", "")
            if gname == "default" or gid in referenced:
                continue
            findings.append({
                "id": "SEG-04", "status": "INFO", "gid": gid, "gname": gname,
                "resource": f"{gid} ({gname})", "attached": False,
                "message": (f"Security group {gid} ({gname}) is attached to no ENI and referenced "
                            f"by no other group — safe-to-delete candidate (verify no launch "
                            f"template / ASG / cross-region use first) | sg/{gid}")})
    return findings
