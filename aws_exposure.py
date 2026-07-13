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
reality. L7 load-balancer / CloudFront exposure is intentionally deferred and
fails closed (never emits an EXPOSED_TO) — deferring cannot manufacture a false
positive. Grounded in a verified AWS-semantics research pass; see the FP/FN
catalog in tests/test_exposure.py.
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
