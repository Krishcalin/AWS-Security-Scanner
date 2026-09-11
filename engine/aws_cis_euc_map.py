#!/usr/bin/env python3
"""CIS AWS End User Compute Services Benchmark v1.2.0 — all 34 recommendations.

Mapping-as-data, like its three siblings (Foundations, Compute, Database, Storage).
``scripts/cis_euc_benchmark.py`` renders it; ``tests/test_cis_euc_mapping.py``
asserts both directions.

NOTHING FROM THE SOURCE DOCUMENT IS REPRODUCED HERE. Recommendation NUMBERS are
references; every label and note below is this project's own analysis, written
from the AWS APIs. CIS Benchmarks may not be redistributed and the PDF is
deliberately not in this repository.

WHAT READING THIS BENCHMARK TURNED UP
--------------------------------------
It is a better document than the Storage benchmark -- 13 of its 34 recommendations
are Automated, where Storage had none -- and most of section 5 maps onto fields the
API returns plainly. Three things are worth recording because no amount of squinting
at the recommendation text reveals them; they came from reading the pinned service
models:

1. **WorkDocs (all of section 4) is structurally unreachable for an agentless
   config scanner.** Every ``workdocs`` API is document- or user-scoped and takes an
   ``AuthenticationToken``, which is issued to a signed-in WorkDocs *user*, not to a
   role. There is no admin control-plane API returning the site settings that 4.3
   through 4.8 are about. The operations that ARE reachable -- DescribeUsers,
   GetDocument, SearchResources -- read customer documents, which is a workload-DATA
   read this product refuses by charter. So six rows are BLOCKED, and the blocker is
   a deliberate refusal rather than an unbuilt feature. See BLOCKERS.

2. **2.17 cannot be audited from the account being scanned.** It asks that WorkSpaces
   API requests travel through a VPC interface endpoint. That is a property of the
   CALLER's network path, not of the account's configuration, and nothing in the
   account records it. The stated audit asks the operator to pass ``--endpoint-url``
   themselves and confirm the value came back, which tests nothing. Its remediation
   additionally creates an endpoint for ``elasticloadbalancing``, a different service.
   ``WorkspaceAccessProperties.AccessEndpointConfig`` is real and readable, but it
   governs client STREAMING traffic (``STREAMING_WSP``) and answers a different
   question.

3. **The benchmark never asks two questions the APIs answer directly.** Whether
   WorkSpaces users are local administrators of their own desktop
   (``WorkspaceCreationProperties.UserEnabledAsLocalAdministrator``) and whether an
   AppStream fleet still permits IMDSv1 (``Fleet.DisableIMDSV1``). Both are read and
   reported -- as ``WKS-08`` and ``APS-05`` -- and both deliberately carry no
   ``CIS-EUC`` key, because the absence is the finding.
"""
from __future__ import annotations

from typing import Dict, Tuple

__all__ = [
    "RECOMMENDATIONS", "SECTIONS", "FAMILY_SECTION", "BLOCKERS", "VERDICTS",
    "COVERED", "ELSEWHERE", "NO_CHECK", "BLOCKED", "UNSOUND",
    "checks_for", "by_verdict", "recommendation_for",
]

# ── the vocabulary ───────────────────────────────────────────────────────────
#: A named check decides it and can FAIL on it.
COVERED = "covered"
#: Decided, but by a check outside this benchmark's own services -- the IAM or
#: segmentation pillars, which already fail the condition generically.
ELSEWHERE = "elsewhere"
#: Decidable from the AWS control plane, not currently checked. The real backlog.
NO_CHECK = "gap"
#: No read-only control-plane path exists, or the only path reads workload DATA and
#: is refused by charter. NOT a gap. See BLOCKERS.
BLOCKED = "blocked"
#: The recommendation's own audit procedure does not test the thing it recommends.
#: Distinct from a gap (we could build it) and from a blocked row (nothing can read
#: it): here the source's method is unsound, so implementing it faithfully would
#: produce a check that passes or fails for reasons unrelated to the control.
UNSOUND = "unsound"

VERDICTS = (COVERED, ELSEWHERE, NO_CHECK, BLOCKED, UNSOUND)

#: What each BLOCKED row is waiting on, and why waiting is the right answer.
BLOCKERS: Dict[str, str] = {
    "IN_GUEST": (
        "state inside the streaming instance or desktop image -- an applied OS "
        "hardening baseline. There is no read-only control-plane path to it: AWS "
        "returns the image id and its creation time, never its contents. SSM "
        "Inventory is the only agentless in-guest surface this product has, and a "
        "WorkSpaces or AppStream image is not an SSM-managed instance."),
    "WORKDOCS_ADMIN": (
        "an administrative API that does not exist. The WorkDocs site settings these "
        "rows govern -- the IP allow list, invite and external-invite rules, public "
        "sharing, inactive-user policy, the site activity feed -- are reachable only "
        "through the WorkDocs web admin control panel. Every operation in the "
        "workdocs service model is document- or user-scoped and requires an "
        "AuthenticationToken issued to a signed-in WorkDocs user rather than to an "
        "IAM role, and the operations a token would unlock (DescribeUsers, "
        "GetDocument, SearchResources) read customer documents. Reading those would "
        "breach the read-only-of-CONFIG charter, so this is a refusal, not a gap: "
        "these rows stay blocked even if a token were available."),
}

#: (number, name, how many recommendations the section holds)
SECTIONS: Tuple[Tuple[str, str, int], ...] = (
    ("2", "WorkSpaces", 18),
    ("3", "WorkSpaces Web", 1),
    ("4", "WorkDocs", 8),
    ("5", "AppStream 2.0", 7),
)

#: Check-id family -> the section it belongs to. The CIS-EUC key lands only on a
#: check named by a covered row AND belonging to that row's own section, so a
#: benchmark mapping cannot quietly re-label checks owned by other pillars.
FAMILY_SECTION: Dict[str, str] = {
    "WKS": "2", "WSW": "3", "APS": "5",
}
# Section 4 (WorkDocs) has no family on purpose: nothing is buildable there.

#: number -> (label, verdict, checks, note)
#: Labels are this project's own words for what the recommendation reaches for.
RECOMMENDATIONS: Dict[str, Tuple[str, str, Tuple[str, ...], str]] = {

    # ── 2 WorkSpaces ─────────────────────────────────────────────────────────
    "2.1": ("An IAM principal, not the root user, administers the desktop fleet",
            ELSEWHERE, (),
            "Generic IAM hygiene. `IAM-*` already fails root usage and over-broad "
            "administrative policies; a WorkSpaces-specific restatement would "
            "duplicate them and drift."),
    "2.2": ("Second factor in front of desktop sign-in", COVERED, ("WKS-06",),
            "Read from the directory the WorkSpaces fleet is registered against: "
            "`ds:DescribeDirectories` returns `RadiusStatus`. Scoped to directories "
            "WorkSpaces actually uses, so a directory serving something else is not "
            "failed for a control it does not need."),
    "2.3": ("Desktop root and user volumes encrypted at rest", COVERED, ("WKS-01",),
            "`RootVolumeEncryptionEnabled` and `UserVolumeEncryptionEnabled` are "
            "returned per WorkSpace. Encryption is fixed at launch and cannot be "
            "added later, which is why the remediation rebuilds rather than edits."),
    "2.4": ("Desktops isolated in their own VPC with private subnets",
            NO_CHECK, (),
            "Buildable: `WorkspaceDirectory.SubnetIds` plus the EC2 subnet and "
            "route-table reads already in the VPC section would decide it. Not "
            "built. The security core of it -- whether desktops get public IPs "
            "directly -- is decided by `WKS-09`."),
    "2.5": ("Desktop egress mediated rather than direct-to-internet",
            COVERED, ("WKS-09",),
            "Covered at the decidable point. The source audits route tables for a "
            "NAT gateway, and its own Additional Information concedes that a "
            "centralised-egress architecture makes that audit wrong. "
            "`WorkspaceCreationProperties.EnableInternetAccess` is the unambiguous "
            "fact underneath: true attaches a public address to every desktop, "
            "which is the state the NAT design exists to avoid."),
    "2.6": ("Browser-based access to desktops turned off", COVERED, ("WKS-02",),
            "`WorkspaceAccessProperties.DeviceTypeWeb` is ALLOW or DENY."),
    "2.7": ("Access restricted to devices holding a client certificate",
            NO_CHECK, (),
            "Buildable: `CertificateBasedAuthProperties.Status` is ENABLED or "
            "DISABLED. Not built. A Level-2 control that only means anything once "
            "an internal CA is issuing device certificates."),
    "2.8": ("Desktop access constrained to known source networks",
            COVERED, ("WKS-03",),
            "A directory with an empty `ipGroupIds` is using the default group, "
            "which the source itself describes as permitting every source address."),
    "2.9": ("Desktop sign-in events captured for later correlation",
            NO_CHECK, (),
            "Buildable from `events:ListRules` plus the rule's event pattern. Not "
            "built, and it is the one row here that would need a new EventBridge "
            "read rather than a field already on a response."),
    "2.10": ("Desktops receive operating-system patches on a maintenance window",
             COVERED, ("WKS-04",),
             "`WorkspaceCreationProperties.EnableMaintenanceMode`. The source notes "
             "that managing updates by another tool is a legitimate alternative, so "
             "the finding is LOW and says so."),
    "2.11": ("The desktop image is hardened to an OS benchmark", BLOCKED, (),
             "Blocker: IN_GUEST."),
    "2.12": ("Only approved desktop bundle types may be provisioned",
             UNSOUND, (),
             "Its audit concludes that if every desktop shows the same bundle then "
             "the approved bundle was used. Uniformity is not approval: a fleet "
             "uniformly on an unapproved bundle passes, and a fleet correctly "
             "running two approved bundles fails. The remediation is to open an AWS "
             "support case, which is a procurement action rather than a setting. "
             "Nothing here is worth implementing faithfully."),
    "2.13": ("Desktop images rebuilt often enough to carry current patches",
             NO_CHECK, (),
             "Buildable: `DescribeWorkspaceImages(ImageType='OWNED')` returns "
             "`Created`. Not built."),
    "2.14": ("Desktops nobody has connected to are removed", COVERED, ("WKS-05",),
             "`DescribeWorkspacesConnectionStatus.LastKnownUserConnectionTimestamp`. "
             "An idle desktop is a licence being paid for and an account that still "
             "logs in, so this is reported as hygiene rather than as exposure."),
    "2.15": ("The desktop security group does not admit the whole internet",
             ELSEWHERE, (),
             "`SEG-*` and `VPC-*` already fail an all-traffic 0.0.0.0/0 ingress rule "
             "on any security group, including this one. Re-checking it per service "
             "would report the same rule twice under two names."),
    "2.16": ("Streaming endpoints negotiate FIPS-validated cryptography",
             NO_CHECK, (),
             "Buildable: `WorkspaceDirectory.EndpointEncryptionMode` is STANDARD_TLS "
             "or FIPS_VALIDATED. Not built, and deliberately so for now -- outside a "
             "regime that demands FIPS 140-2 the standard mode is not a weakness, so "
             "a finding here would be noise for most accounts."),
    "2.17": ("Management API calls travel over private connectivity",
             UNSOUND, (),
             "Not auditable from the account being scanned, and its stated audit "
             "does not attempt to be. Whether an API call traversed a VPC endpoint "
             "is a property of the CALLER's network path; the account records "
             "nothing about it. The audit instructs the operator to supply "
             "`--endpoint-url` themselves and confirm the value they supplied came "
             "back, which would pass from any network. The remediation compounds it "
             "by creating an `elasticloadbalancing` endpoint. "
             "`AccessEndpointConfig` is readable and real, but it governs client "
             "STREAMING_WSP traffic and answers a different question."),
    "2.18": ("The second-factor transport is the strongest protocol on offer",
             COVERED, ("WKS-07",),
             "`RadiusSettings.AuthenticationProtocol` is one of PAP, CHAP, "
             "MS-CHAPv1, MS-CHAPv2. The source is careful to call MS-CHAPv2 the "
             "strongest of those four rather than strong, and that is the right "
             "framing: MS-CHAPv2 has known weaknesses and is recommended here only "
             "because AWS Directory Service offers nothing better. `WKS-07` fails "
             "the three that are worse and says why."),

    # ── 3 WorkSpaces Web ─────────────────────────────────────────────────────
    "3.1": ("Managed-browser session and navigation events are recorded",
            COVERED, ("WSW-02",),
            "Already covered before this benchmark was read. `WSW-02` fails a portal "
            "with neither user-access nor session logging configured."),

    # ── 4 WorkDocs ───────────────────────────────────────────────────────────
    "4.1": ("An IAM principal administers the document site", ELSEWHERE, (),
            "Generic IAM hygiene, as 2.1."),
    "4.2": ("Second factor in front of document-site sign-in", ELSEWHERE, (),
            "The same directory-level RADIUS setting `WKS-06` reads. It is filed "
            "here rather than covered because `WKS-06` is scoped to directories "
            "registered with WorkSpaces: a directory serving only WorkDocs is not "
            "reached, and widening the scope would fail directories that have no "
            "reason to carry RADIUS."),
    "4.3": ("Document-site access limited to known source networks", BLOCKED, (),
            "Blocker: WORKDOCS_ADMIN."),
    "4.4": ("Site-wide activity reviewed and retained", BLOCKED, (),
            "Blocker: WORKDOCS_ADMIN."),
    "4.5": ("New collaborators only from approved email domains", BLOCKED, (),
            "Blocker: WORKDOCS_ADMIN."),
    "4.6": ("Only administrators may invite people outside the organisation",
            BLOCKED, (), "Blocker: WORKDOCS_ADMIN."),
    "4.7": ("Public, unauthenticated share links are not permitted", BLOCKED, (),
            "Blocker: WORKDOCS_ADMIN. The one row here it is most galling to be "
            "unable to check: a public share link is the document-store equivalent "
            "of a public S3 bucket, which this product fails loudly on."),
    "4.8": ("Dormant accounts lose access to the document site", BLOCKED, (),
            "Blocker: WORKDOCS_ADMIN."),

    # ── 5 AppStream 2.0 ──────────────────────────────────────────────────────
    "5.1": ("Streaming instances run inside a customer VPC", COVERED, ("APS-02",),
            "`Fleet.VpcConfig.SubnetIds`. A fleet with no subnets is not in your "
            "network at all. The source's stronger ask -- a dedicated VPC with two "
            "private subnets -- is a topology judgement; the decidable half is "
            "whether the fleet is attached to a VPC."),
    "5.2": ("Streaming traffic reaches users over private connectivity",
            COVERED, ("APS-03",),
            "`Stack.AccessEndpoints` with `EndpointType` STREAMING and a `VpceId`. "
            "Unlike 2.17, this one IS a property of the account and the API returns "
            "it."),
    "5.3": ("A streaming session cannot run indefinitely", COVERED, ("APS-04",),
            "`Fleet.MaxUserDurationInSeconds`, against the source's 600-minute bound."),
    "5.4": ("A dropped session is reclaimed promptly", COVERED, ("APS-04",),
            "`Fleet.DisconnectTimeoutInSeconds`, against the source's 5-minute bound."),
    "5.5": ("An idle session is disconnected", COVERED, ("APS-04",),
            "`Fleet.IdleDisconnectTimeoutInSeconds`, against the source's 10-minute "
            "bound. Zero means never, which the check treats as failing rather than "
            "as a very large number."),
    "5.6": ("Streaming instances are not given direct internet addresses",
            COVERED, ("APS-01",),
            "`Fleet.EnableDefaultInternetAccess`. The AppStream twin of `WKS-09`."),
    "5.7": ("Streaming images rebuilt often enough to carry current patches",
            COVERED, ("APS-06",),
            "`DescribeImages(Type='PRIVATE').CreatedTime`, against the source's "
            "30-day bound. Public base images are excluded: their age is AWS's "
            "business, not the account's."),
}


# ── helpers ─────────────────────────────────────────────────────────────────
def checks_for(recommendation: str) -> Tuple[str, ...]:
    """The checks named against one recommendation, or () if none."""
    row = RECOMMENDATIONS.get(recommendation)
    return row[2] if row else ()


def by_verdict(verdict: str) -> Tuple[str, ...]:
    """Every recommendation carrying one verdict, in numeric order."""
    return tuple(sorted(
        (rec for rec, row in RECOMMENDATIONS.items() if row[1] == verdict),
        key=lambda r: (int(r.split(".", 1)[0]), int(r.split(".", 1)[1]))))


def recommendation_for(check_id: str) -> str:
    """The one recommendation a check calls home, or '' if it answers none.

    Same precedence as the Database and Storage mappings: a check can be named by
    several rows, and the one it belongs to is the row in its OWN service section.
    `APS-04` is named by 5.3, 5.4 and 5.5; it comes home to 5.3, the lowest.
    """
    fam = check_id.rsplit("-", 1)[0]
    section = FAMILY_SECTION.get(fam)
    named = [rec for rec, row in RECOMMENDATIONS.items() if check_id in row[2]]
    if not named:
        return ""
    own = [r for r in named if r.split(".", 1)[0] == section]
    pool = own or named
    return min(pool, key=lambda r: (int(r.split(".", 1)[0]),
                                    int(r.split(".", 1)[1])))
