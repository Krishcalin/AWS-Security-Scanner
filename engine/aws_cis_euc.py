"""Pure decisions for the CIS AWS End User Compute checks: WorkSpaces and AppStream.

Mirrors `aws_cis_compute.py`, `aws_cis_db.py` and `aws_cis_storage.py`: no boto3, no
network, NO CLOCK. The two age questions take `now` as an argument so a test can pin
it; a module that reads the clock cannot be checked against its own output, which is
a lesson this repository learned the expensive way on the CCM generator.

EVERY FIELD NAME AND ENUM BELOW CAME FROM THE PINNED BOTOCORE MODEL, read rather than
recalled. The ones carrying weight:

    workspaces  Workspace
        RootVolumeEncryptionEnabled / UserVolumeEncryptionEnabled   bool
    workspaces  WorkspaceDirectory
        WorkspaceAccessProperties.DeviceTypeWeb        ['ALLOW', 'DENY']
        WorkspaceCreationProperties.EnableInternetAccess            bool
        WorkspaceCreationProperties.EnableMaintenanceMode           bool
        WorkspaceCreationProperties.UserEnabledAsLocalAdministrator bool
        ipGroupIds                                     list[str]
        EndpointEncryptionMode      ['STANDARD_TLS', 'FIPS_VALIDATED']
    ds  DirectoryDescription
        RadiusStatus                ['Creating', 'Completed', 'Failed']
        RadiusSettings.AuthenticationProtocol
                                    ['PAP', 'CHAP', 'MS-CHAPv1', 'MS-CHAPv2']
    appstream  Fleet
        MaxUserDurationInSeconds / DisconnectTimeoutInSeconds /
        IdleDisconnectTimeoutInSeconds                 int (SECONDS, not minutes)
        EnableDefaultInternetAccess / DisableIMDSV1    bool
    appstream  Stack
        AccessEndpoints[].EndpointType ['STREAMING'] + VpceId

Two of those repay the reading. `RadiusStatus` is **Completed**, not "Enabled" -- the
source document uses both words in different places and only one is real. And the
AppStream timeouts are in SECONDS while the document and console both speak in
MINUTES, so a check written from the prose would be wrong by a factor of sixty.

ABSENT IS UNKNOWN, NOT FALSE, as everywhere else in this engine. Each posture
reports a `known` flag and the callers stay silent when it is False.
"""
from __future__ import annotations

from typing import Any, Dict, Optional, Sequence

__all__ = [
    "ACCESS_ALLOW", "ACCESS_DENY", "RADIUS_COMPLETED", "WEAK_RADIUS_PROTOCOLS",
    "STRONGEST_RADIUS_PROTOCOL", "MAX_SESSION_SECONDS", "MAX_DISCONNECT_SECONDS",
    "MAX_IDLE_SECONDS", "MAX_IMAGE_AGE_DAYS", "IDLE_WORKSPACE_DAYS",
    "workspace_volume_posture", "directory_posture", "radius_posture",
    "workspace_idle_posture", "fleet_network_posture", "fleet_session_posture",
    "stack_endpoint_posture", "image_age_posture",
]

ACCESS_ALLOW = "ALLOW"
ACCESS_DENY = "DENY"

RADIUS_COMPLETED = "Completed"
STRONGEST_RADIUS_PROTOCOL = "MS-CHAPv2"

#: The three the service offers that are worse than MS-CHAPv2. PAP hands the
#: password to the RADIUS server under nothing but an MD5 keystream derived from the
#: shared secret; CHAP and MS-CHAPv1 are both broken against offline attack. Note
#: what this set implies and the source says outright: MS-CHAPv2 is the strongest of
#: four, which is not the same as strong. There is no good option here, only a least
#: bad one, and a check that pretended otherwise would be lying by omission.
WEAK_RADIUS_PROTOCOLS = frozenset({"PAP", "CHAP", "MS-CHAPv1"})

#: The source's own bounds, converted to the units the API actually returns.
MAX_SESSION_SECONDS = 600 * 60        # 10 hours
MAX_DISCONNECT_SECONDS = 5 * 60       # 5 minutes
MAX_IDLE_SECONDS = 10 * 60            # 10 minutes
MAX_IMAGE_AGE_DAYS = 30
IDLE_WORKSPACE_DAYS = 30


def _d(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _l(value: Any) -> Sequence[Any]:
    return value if isinstance(value, (list, tuple)) else ()


# ── WorkSpaces ──────────────────────────────────────────────────────────────
def workspace_volume_posture(workspace: Optional[dict]) -> Dict[str, Any]:
    """WKS-01 -- is the desktop's storage encrypted at rest?

    Both volumes are reported because they fail independently and mean different
    things: the root volume carries the image and whatever the user installed, the
    user volume carries their documents. Either one unencrypted is a finding, and
    naming which is the first thing an operator needs.
    """
    w = _d(workspace)
    root = w.get("RootVolumeEncryptionEnabled")
    user = w.get("UserVolumeEncryptionEnabled")
    unencrypted = [n for n, v in (("root", root), ("user", user)) if v is False]
    return {
        "id": w.get("WorkspaceId") or "",
        "user_name": w.get("UserName") or "",
        "root_encrypted": root is True,
        "user_encrypted": user is True,
        "known": isinstance(root, bool) or isinstance(user, bool),
        "unencrypted": tuple(unencrypted),
        "any_unencrypted": bool(unencrypted),
        "key": w.get("VolumeEncryptionKey") or "",
    }


def directory_posture(directory: Optional[dict]) -> Dict[str, Any]:
    """WKS-02, WKS-03, WKS-04, WKS-08 and WKS-09 -- the fleet-wide settings.

    All five hang off one `DescribeWorkspaceDirectories` response, so they are
    decided together rather than by five functions that would each re-walk it.
    """
    d = _d(directory)
    access = _d(d.get("WorkspaceAccessProperties"))
    creation = _d(d.get("WorkspaceCreationProperties"))
    web = access.get("DeviceTypeWeb")
    ip_groups = [g for g in _l(d.get("ipGroupIds")) if g]
    internet = creation.get("EnableInternetAccess")
    maintenance = creation.get("EnableMaintenanceMode")
    local_admin = creation.get("UserEnabledAsLocalAdministrator")
    return {
        "id": d.get("DirectoryId") or "",
        "name": d.get("WorkspaceDirectoryName") or d.get("DirectoryName")
                or d.get("Alias") or "",
        "state": d.get("State") or "",
        # WKS-02
        "web_access": web or "",
        "web_known": web in (ACCESS_ALLOW, ACCESS_DENY),
        "web_allowed": web == ACCESS_ALLOW,
        # WKS-03 -- an empty list is the default group, which admits every source.
        "ip_groups": tuple(ip_groups),
        "ip_restricted": bool(ip_groups),
        # WKS-04
        "maintenance_known": isinstance(maintenance, bool),
        "maintenance_enabled": maintenance is True,
        # WKS-08
        "local_admin_known": isinstance(local_admin, bool),
        "users_are_local_admin": local_admin is True,
        # WKS-09
        "internet_known": isinstance(internet, bool),
        "direct_internet": internet is True,
        "endpoint_encryption": d.get("EndpointEncryptionMode") or "",
    }


def radius_posture(ds_directory: Optional[dict]) -> Dict[str, Any]:
    """WKS-06 and WKS-07 -- is there a second factor, and how is it carried?

    Read from Directory Service rather than from WorkSpaces: the RADIUS
    configuration belongs to the directory, and both WorkSpaces and WorkDocs sit on
    top of it.
    """
    d = _d(ds_directory)
    status = d.get("RadiusStatus") or ""
    settings = _d(d.get("RadiusSettings"))
    protocol = settings.get("AuthenticationProtocol") or ""
    servers = [s for s in _l(settings.get("RadiusServers")) if s]
    return {
        "id": d.get("DirectoryId") or "",
        "name": d.get("Name") or d.get("Alias") or "",
        "status": status,
        # Configured means a server set exists; ACTIVE means the service completed
        # the handshake. A Failed RADIUS is worse than none: the console shows MFA
        # as set up while sign-in falls back to a single factor.
        "configured": bool(servers) or bool(status),
        "active": status == RADIUS_COMPLETED,
        "failed": status == "Failed",
        "protocol": protocol,
        "protocol_known": bool(protocol),
        "weak_protocol": protocol in WEAK_RADIUS_PROTOCOLS,
        "servers": tuple(servers),
    }


def workspace_idle_posture(status: Optional[dict], now_epoch: float,
                           max_days: int = IDLE_WORKSPACE_DAYS) -> Dict[str, Any]:
    """WKS-05 -- has anybody connected to this desktop recently?

    `now_epoch` is passed in rather than read, so the boundary can be pinned in a
    test instead of drifting with the calendar.
    """
    s = _d(status)
    last = s.get("LastKnownUserConnectionTimestamp")
    ts = _epoch(last)
    if ts is None:
        # Never connected at all. A desktop that has been provisioned, is being
        # billed, and has never been used is the strongest form of this finding,
        # not an unknown.
        return {"id": s.get("WorkspaceId") or "", "known": True, "never": True,
                "idle": True, "days": None,
                "connection_state": s.get("ConnectionState") or ""}
    days = max(0.0, (now_epoch - ts) / 86400.0)
    return {
        "id": s.get("WorkspaceId") or "",
        "known": True,
        "never": False,
        "idle": days > max_days,
        "days": int(days),
        "connection_state": s.get("ConnectionState") or "",
    }


# ── AppStream ───────────────────────────────────────────────────────────────
def fleet_network_posture(fleet: Optional[dict]) -> Dict[str, Any]:
    """APS-01, APS-02 and APS-05 -- where the streaming instance sits, and what
    its metadata service will answer."""
    f = _d(fleet)
    vpc = _d(f.get("VpcConfig"))
    subnets = [s for s in _l(vpc.get("SubnetIds")) if s]
    internet = f.get("EnableDefaultInternetAccess")
    imds_disabled = f.get("DisableIMDSV1")
    return {
        "name": f.get("Name") or "",
        "state": f.get("State") or "",
        "subnets": tuple(subnets),
        "in_vpc": bool(subnets),
        "security_groups": tuple(g for g in _l(vpc.get("SecurityGroupIds")) if g),
        "internet_known": isinstance(internet, bool),
        "direct_internet": internet is True,
        # DisableIMDSV1 True means v1 is OFF, which is the good state. The field is
        # named for the action rather than the posture, so the check reads it once
        # here and never again.
        "imds_known": isinstance(imds_disabled, bool),
        "imdsv1_enabled": imds_disabled is False,
        "iam_role": f.get("IamRoleArn") or "",
    }


def fleet_session_posture(fleet: Optional[dict]) -> Dict[str, Any]:
    """APS-04 -- three session bounds, in SECONDS.

    The document and the console both speak in minutes; the API does not. A check
    written from the prose would compare 600 minutes against 36000 seconds and pass
    everything.
    """
    f = _d(fleet)
    session = f.get("MaxUserDurationInSeconds")
    disconnect = f.get("DisconnectTimeoutInSeconds")
    idle = f.get("IdleDisconnectTimeoutInSeconds")
    over = []
    if isinstance(session, int) and session > MAX_SESSION_SECONDS:
        over.append(f"max session {session // 60}min > {MAX_SESSION_SECONDS // 60}min")
    if isinstance(disconnect, int) and disconnect > MAX_DISCONNECT_SECONDS:
        over.append(f"disconnect timeout {disconnect // 60}min > "
                    f"{MAX_DISCONNECT_SECONDS // 60}min")
    # Zero is not "very small", it is the service's way of saying never disconnect
    # an idle session, which is the worst value rather than the best.
    if isinstance(idle, int) and (idle == 0 or idle > MAX_IDLE_SECONDS):
        over.append("idle disconnect disabled" if idle == 0 else
                    f"idle disconnect {idle // 60}min > {MAX_IDLE_SECONDS // 60}min")
    return {
        "name": f.get("Name") or "",
        "known": any(isinstance(v, int) for v in (session, disconnect, idle)),
        "over": tuple(over),
        "any_over": bool(over),
        "max_session": session,
        "disconnect": disconnect,
        "idle": idle,
    }


def stack_endpoint_posture(stack: Optional[dict]) -> Dict[str, Any]:
    """APS-03 -- does the stack stream over a VPC endpoint or over the internet?"""
    s = _d(stack)
    eps = [_d(e) for e in _l(s.get("AccessEndpoints"))]
    streaming = [e for e in eps
                 if e.get("EndpointType") == "STREAMING" and e.get("VpceId")]
    return {
        "name": s.get("Name") or "",
        "endpoints": tuple(e.get("VpceId") or "" for e in streaming),
        "private_streaming": bool(streaming),
    }


def image_age_posture(created: Any, now_epoch: float,
                      max_days: int = MAX_IMAGE_AGE_DAYS) -> Dict[str, Any]:
    """APS-06 -- how long ago was this image built?"""
    ts = _epoch(created)
    if ts is None:
        return {"known": False, "stale": False, "days": None}
    days = max(0.0, (now_epoch - ts) / 86400.0)
    return {"known": True, "stale": days > max_days, "days": int(days)}


def _epoch(value: Any) -> Optional[float]:
    """A boto3 timestamp (tz-aware datetime, or a number) as epoch seconds."""
    if value is None:
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    ts = getattr(value, "timestamp", None)
    if callable(ts):
        try:
            return float(ts())
        except Exception:
            return None
    return None
