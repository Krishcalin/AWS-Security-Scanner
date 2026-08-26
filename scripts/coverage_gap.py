#!/usr/bin/env python3
"""Which AWS services does OverWatch not yet read, ranked by what they would buy?

This drives the service-coverage programme. It had lived in a scratch directory across
six batches, which meant a fix to it lived nowhere — so it is a repo artefact now.

HOW IT RANKS
------------
botocore ships a service model for every AWS API, and a service only has detectable
CONFIG if it has a ``Describe``/``Get``/``List`` operation. So rather than guessing which
of the 426 services matter, each uncovered one is scored by the security-relevant read
operations it actually exposes, weighted by what they answer: resource-policy and
public-access reads highest, then encryption and network, then logging, auth, backup, TLS.

TWO THINGS IT LEARNED THE HARD WAY
-----------------------------------
**Deduplicate by signing name, not by client directory.** ``es`` and ``opensearch`` are
the same service at different API versions and both sign as ``es``; keying on directory
names counted it twice and ranked an already-covered service at 16. Same for any service
whose client name differs from its IAM prefix — which is six and counting
(``bedrock-agentcore``, ``sso``, ``aps``, ``ses``, ``codeguru-profiler``, ``cloudhsm``).

**A high score is not a reason to build.** Three of the four highest-ranked gaps in the
batch-6 ranking were discontinued services: MediaStore (support ended 2025-11-13) and
AWS WAF Classic's two clients (2025-09-30). A check against a service no account can
have is worse than no check, because it reads as coverage. Confirm the service is live
before writing anything — the score says only that the API surface would be worth
reading if it were.
"""
from __future__ import annotations

import glob
import gzip
import io
import json
import os
import re
import sys

import botocore

BASE = os.path.join(os.path.dirname(botocore.__file__), "data")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: Read operations whose NAME answers a security question, weighted by how directly.
SIGNALS = {
    "resource_policy": (re.compile(r"(GetResourcePolicy|GetPolicy$|Get.*Policy$|"
                                   r"Describe.*Policy|ListResourcePolic)", re.I), 5),
    "public_access": (re.compile(r"(PublicAccess|Public|Anonymous|Shareable|"
                                 r"ShareSettings|Sharing)", re.I), 5),
    "encryption": (re.compile(r"(Encryption|Kms|CustomerManagedKey|Cmk|ServerSideEnc)",
                              re.I), 4),
    "network": (re.compile(r"(VpcConfig|VpcEndpoint|NetworkConfig|SecurityGroup|"
                           r"PubliclyAccessible|EndpointAccess|EndpointConfig)", re.I), 4),
    "logging": (re.compile(r"(Logging|LogConfig|Trail|Audit|LogDelivery|LogGroup)",
                           re.I), 3),
    "auth": (re.compile(r"(Authorizer|Authentication|Credential|Token|Mfa|"
                        r"IdentityProvider|Oauth|ApiKey)", re.I), 3),
    "backup": (re.compile(r"(Backup|Snapshot|Retention|Recovery|Versioning)", re.I), 2),
    "tls": (re.compile(r"(Certificate|Tls|Ssl|MinimumProtocol)", re.I), 2),
}
READ = re.compile(r"^(Describe|Get|List|BatchGet|Lookup|Retrieve|Query|Check|Search)")

#: Services AWS has discontinued. Scored highly and deliberately NOT built; recorded so
#: the omission carries a date rather than looking like an oversight.
DISCONTINUED = {
    "mediastore": "2025-11-13",
    "waf": "2025-09-30",           # AWS WAF Classic; wafv2 is the successor and covered
    "waf-regional": "2025-09-30",
}


def _model(svc):
    d = os.path.join(BASE, svc)
    versions = sorted(v for v in os.listdir(d) if os.path.isdir(os.path.join(d, v)))
    if not versions:
        return None
    hits = glob.glob(os.path.join(d, versions[-1], "service-2.json*"))
    if not hits:
        return None
    op = gzip.open if hits[0].endswith(".gz") else open
    try:
        with op(hits[0], "rt", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def signing_name(meta) -> str:
    """The IAM prefix. signingName wins; endpointPrefix is the fallback for services
    that omit it (EMR's client dir is `emr`, its IAM prefix is `elasticmapreduce`)."""
    return meta.get("signingName") or meta.get("endpointPrefix") or ""


def covered_signing_names() -> set:
    """Which SIGNING NAMES the scanner already reads.

    Resolved through the models rather than compared as client strings, because a client
    name and an IAM prefix are not the same thing often enough to matter."""
    clients = set()
    for fn in glob.glob(os.path.join(ROOT, "*.py")):
        try:
            src = io.open(fn, encoding="utf-8").read()
        except Exception:
            continue
        clients |= set(re.findall(r'_client\(\s*["\']([a-z0-9\-]+)["\']', src))
        clients |= set(re.findall(r'\.client\(\s*["\']([a-z0-9\-]+)["\']', src))
    names = set()
    for c in clients:
        if not c:
            continue
        m = _model(c) if os.path.isdir(os.path.join(BASE, c)) else None
        names.add(signing_name(m["metadata"]) if m else c)
    return names


def analyse():
    covered = covered_signing_names()
    seen, rows = set(), []
    for svc in sorted(os.listdir(BASE)):
        if not os.path.isdir(os.path.join(BASE, svc)):
            continue
        model = _model(svc)
        if not model:
            continue
        sign = signing_name(model["metadata"])
        if sign in seen:
            continue                      # same service, older API version
        seen.add(sign)
        reads = [o for o in model.get("operations", {}) if READ.match(o)]
        score, cats = 0, {}
        for o in reads:
            for name, (rx, weight) in SIGNALS.items():
                if rx.search(o):
                    score += weight
                    cats.setdefault(name, []).append(o)
        rows.append({
            "service": svc, "signing_name": sign,
            "covered": sign in covered,
            "discontinued": DISCONTINUED.get(svc),
            "reads": len(reads), "score": score, "categories": sorted(cats),
        })
    return rows


def main():
    rows = analyse()
    gaps = [r for r in rows
            if not r["covered"] and r["score"] > 0 and not r["discontinued"]]
    gaps.sort(key=lambda r: -r["score"])
    dead = [r for r in rows if r["discontinued"] and not r["covered"]]

    print(f"services (deduplicated by signing name) : {len(rows)}")
    print(f"covered by OverWatch                    : {sum(1 for r in rows if r['covered'])}")
    print(f"UNCOVERED, live, with security reads    : {len(gaps)}")
    if dead:
        print(f"excluded as discontinued                : "
              f"{', '.join(f'{r['service']} ({r['discontinued']})' for r in dead)}")
    print()
    print(f"{'score':>5}  {'service':<28} {'reads':>5}  categories")
    print("-" * 92)
    for r in gaps[:40]:
        print(f"{r['score']:>5}  {r['service']:<28} {r['reads']:>5}  "
              f"{','.join(r['categories'])[:44]}")
    out = os.path.join(ROOT, "coverage_gap.json")
    with io.open(out, "w", encoding="utf-8") as fh:
        json.dump(gaps, fh, indent=1)
    print(f"\nfull ranked list -> {out}")
    print("Confirm a service is LIVE before building: a high score says the surface "
          "would be worth reading, not that anyone can still have it.")


if __name__ == "__main__":
    sys.exit(main())
