#!/usr/bin/env python3
"""aws_registry_connectors.py — operator-declared NON-AWS registry connectors (Batch 6 · R2).

A registry connector tells OverWatch *which* non-AWS OCI registry to pull from and *where its
pull credential lives* — never the credential itself. It resolves a connector's ``secret_ref``
(``secretsmanager://`` / ``ssm://``, the SAME scheme cnapp_connectors/cnapp_onboarding use) to a
transient plaintext and shapes it into the ``creds`` dict ``aws_registry_oci`` consumes. That's the
whole job: NO network primitive lives here (the pull's egress stays in ``aws_layer_fetch``), so this
module is a pure, offline-testable leaf.

One deliberate finding from scoping: GHCR, Docker Hub, Harbor, AND Azure ACR — in BOTH ACR's admin
and service-principal modes (``docker login <registry> -u <sp-client-id> -p <sp-secret>`` works
verbatim) — all authenticate through the SAME standard Docker Registry v2 Bearer-realm dance already
implemented in ``aws_registry_oci.obtain_bearer``. So there is NO per-registry network auth adapter
to write; the only registry-specific knowledge is the well-known API host for the friendly types
(``ghcr.io`` / ``registry-1.docker.io``) and how the operator's credential maps to Basic vs a
supplied Bearer. GCR / Google Artifact Registry stays DEFERRED (its OAuth needs RS256 JWT signing;
the air-gap wheelhouse ships no ``cryptography``).

CHARTER: read-only (a pull never mutates the registry), config-driven (no hardcoded FOREIGN egress
host — the friendly-type default hosts here are passed IN as the per-call allowlist, they are not an
egress primitive), secret-as-a-ref-only (plaintext resolved transiently at pull time, never
persisted/returned — :func:`mask_connector` drops the ref to a ``secret_configured`` bool).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from cnapp_onboarding import _RESOLVABLE_SCHEMES, SecretReader

REGISTRY_TYPES = ("ghcr", "dockerhub", "harbor", "acr", "generic")
# Friendly-type → well-known Registry v2 API host. harbor/acr/generic are operator-hosted, so the
# host is REQUIRED in config (there is no universal default). These are allowlist inputs, never an
# egress literal — the sole egress file (aws_layer_fetch) has no foreign host.
_DEFAULT_HOSTS = {"ghcr": "ghcr.io", "dockerhub": "registry-1.docker.io"}
_AUTH_MODES = ("anonymous", "basic", "token")


class RegistryConnectorError(Exception):
    """A registry-connector config is malformed — raised at the CONFIG boundary (parse), never
    mid-pull, so a bad connector is rejected on load rather than silently pulling with no/bad auth."""


@dataclass(frozen=True)
class RegistryConnector:
    """A declared non-AWS registry. ``images`` are explicit refs to scan now (repo[:tag|@digest]);
    ``repositories`` are repos to ENUMERATE (R3). ``secret_ref`` is a resolvable ref, never a
    secret. ``username`` is non-secret (a Docker ID / GitHub user / robot name / SP client-id)."""
    connector_id: str
    type: str                                    # ghcr | dockerhub | harbor | acr | generic
    host: str
    name: str = ""
    enabled: bool = False                        # safe-by-default: disabled connectors never pull
    auth: str = "anonymous"                      # anonymous | basic | token
    username: Optional[str] = None               # non-secret Basic username (None for token/anon)
    secret_ref: Optional[str] = None             # secretsmanager:// | ssm:// (never plaintext)
    images: List[str] = field(default_factory=list)
    repositories: List[str] = field(default_factory=list)
    newest_n: int = 5                            # per-repo enumeration bound (R3)
    max_image_bytes: Optional[int] = None
    insecure_skip_scan: bool = False             # reserved; never loosens TLS
    config: Dict = field(default_factory=dict)   # non-secret extras


def default_host(type_: str) -> str:
    return _DEFAULT_HOSTS.get(type_, "")


def parse_connector(d: Dict) -> RegistryConnector:
    """CONFIG-boundary parse+validate. Raises RegistryConnectorError on anything malformed so a bad
    connector never reaches a pull. Fills the well-known host for ghcr/dockerhub; requires an
    explicit host for harbor/acr/generic; requires a ``secret_ref`` when auth is basic/token."""
    if not isinstance(d, dict):
        raise RegistryConnectorError("connector must be an object")
    cid = str(d.get("connector_id") or d.get("id") or "").strip()
    if not cid:
        raise RegistryConnectorError("connector_id is required")
    rtype = str(d.get("type") or "generic").strip().lower()
    if rtype not in REGISTRY_TYPES:
        raise RegistryConnectorError(f"unknown registry type {rtype!r} (one of {REGISTRY_TYPES})")
    host = str(d.get("host") or default_host(rtype) or "").strip().lower()
    if not host:
        raise RegistryConnectorError(f"host is required for type {rtype!r}")
    if "://" in host or "/" in host:
        raise RegistryConnectorError("host must be a bare registry host[:port], no scheme/path")
    auth = str(d.get("auth") or ("basic" if (d.get("secret_ref") and d.get("username"))
                                 else ("token" if d.get("secret_ref") else "anonymous"))).lower()
    if auth not in _AUTH_MODES:
        raise RegistryConnectorError(f"unknown auth mode {auth!r} (one of {_AUTH_MODES})")
    secret_ref = d.get("secret_ref")
    if secret_ref is not None:
        secret_ref = str(secret_ref)
        if not secret_ref.startswith(_RESOLVABLE_SCHEMES):
            raise RegistryConnectorError(
                f"secret_ref must be a resolvable {_RESOLVABLE_SCHEMES} reference")
    if auth in ("basic", "token") and not secret_ref:
        raise RegistryConnectorError(f"auth {auth!r} requires a secret_ref")
    username = d.get("username")
    if auth == "basic" and not username:
        raise RegistryConnectorError("basic auth requires a username")
    images = [str(x) for x in (d.get("images") or []) if str(x).strip()]
    repositories = [str(x) for x in (d.get("repositories") or []) if str(x).strip()]
    try:
        newest_n = max(1, int(d.get("newest_n", 5)))
    except (TypeError, ValueError):
        raise RegistryConnectorError("newest_n must be an integer")
    mib = d.get("max_image_bytes")
    if mib is not None:
        try:
            mib = int(mib)
        except (TypeError, ValueError):
            raise RegistryConnectorError("max_image_bytes must be an integer")
    return RegistryConnector(
        connector_id=cid, type=rtype, host=host, name=str(d.get("name") or cid),
        enabled=bool(d.get("enabled", False)), auth=auth,
        username=(str(username) if username is not None else None),
        secret_ref=secret_ref, images=images, repositories=repositories,
        newest_n=newest_n, max_image_bytes=mib,
        insecure_skip_scan=bool(d.get("insecure_skip_scan", False)),
        config=dict(d.get("config") or {}))


def load_connectors(raw) -> List[RegistryConnector]:
    """Parse a list (or ``{"registries": [...]}``) of connector dicts, skipping malformed ones
    fail-SAFE (a bad entry is dropped, not fatal — mirrors _load_controls/_load_policies). The
    server logs the drop; a rejected connector simply never pulls."""
    if isinstance(raw, dict):
        raw = raw.get("registries") or raw.get("connectors") or []
    out: List[RegistryConnector] = []
    seen: set = set()
    for entry in (raw or []):
        try:
            rc = parse_connector(entry)
        except RegistryConnectorError:
            continue
        if rc.connector_id in seen:
            continue
        seen.add(rc.connector_id)
        out.append(rc)
    return out


def qualify_ref(rc: RegistryConnector, image: str) -> str:
    """Host-qualify an image ref so ``aws_registry_oci.parse_ref`` resolves it to THIS registry (a
    bare ``team/app:1.0`` — or a single-segment ``backend:prod`` — would otherwise be read as Docker
    Hub, sending THIS connector's credential to a third party). Idempotent if already qualified.

    The tag/digest MUST be stripped before host detection: a registry host is the first path segment
    ONLY when there is a ``/`` and that segment looks like a host (``.``/``:``/``localhost``). A
    single-segment ``backend:prod`` has a tag colon, NOT a ``host:port`` colon — it is NOT qualified."""
    img = (image or "").strip()
    if img.startswith(rc.host + "/"):
        return img
    path = img.split("@", 1)[0]                   # drop a digest before host detection
    if "/" in path:
        first = path.split("/", 1)[0]
        if "." in first or ":" in first or first == "localhost":
            return img                           # already registry-qualified (host in the first segment)
    return f"{rc.host}/{img}"


def image_refs(rc: RegistryConnector) -> List[str]:
    """The explicit, host-qualified image refs this connector scans directly (R1/R2)."""
    return [qualify_ref(rc, i) for i in rc.images]


def resolve_creds(rc: RegistryConnector, *, secret_reader: SecretReader) -> Optional[dict]:
    """Shape the connector's credential into the ``creds`` dict ``aws_registry_oci`` consumes,
    resolving the ``secret_ref`` TRANSIENTLY via the injected reader (plaintext never persisted).
      * anonymous → None (public pull)
      * basic     → {"username": <non-secret>, "password": <resolved secret>}
      * token     → {"bearer": <resolved secret>}   (a pre-minted registry Bearer/PAT-as-token)
    Raises RegistryConnectorError if a required secret is missing/empty (fail-closed — never a
    silent anonymous fallthrough that could pull the wrong/no image)."""
    if rc.auth == "anonymous":
        return None
    if not rc.secret_ref:
        raise RegistryConnectorError(f"{rc.connector_id}: auth {rc.auth!r} requires a secret_ref")
    secret = secret_reader(rc.secret_ref)
    if not secret:
        raise RegistryConnectorError(f"{rc.connector_id}: secret_ref resolved empty")
    if rc.auth == "token":
        return {"bearer": str(secret)}
    if not rc.username:
        raise RegistryConnectorError(f"{rc.connector_id}: basic auth requires a username")
    return {"username": rc.username, "password": str(secret)}


def _severity_counts(res) -> Dict[str, int]:
    """CRITICAL/HIGH/total CVE counts from a SideScanResult (or zeros if the scan was not ok)."""
    crit = high = total = 0
    for m in (getattr(res, "vulns", None) or []):
        total += 1
        s = (getattr(m, "severity", "") or "").upper()
        if s == "CRITICAL":
            crit += 1
        elif s == "HIGH":
            high += 1
    return {"vuln_count": total, "critical": crit, "high": high}


def registry_image_view(rc: RegistryConnector, ref: str, result) -> Dict:
    """Shape one pulled OCI image (a ``aws_registry_sbom.RegistryImageResult``) into the SAME
    image-row dict the ECR ``list_registry_images`` returns, so ``SupplyChain.tsx`` renders it with
    zero UI change. ``deployed`` is always False (a non-AWS registry image has no in-account
    RUNS_IMAGE edge — it is registry-only by definition); ``scan_source`` is ``oci-sidescan:<type>``
    so the provenance chip reads honestly. CVE counts come straight off the SideScanResult."""
    counts = _severity_counts(getattr(result, "result", None))
    return {
        "connector_id": rc.connector_id, "registry_type": rc.type, "host": rc.host,
        "node_id": result.node_id, "repository": _repo_of(ref, rc.host),
        "image_uri": result.node_id.split("@")[0].split(":")[0] if "@" in result.node_id else result.node_id,
        "digest": result.digest, "tags": list(result.tags),
        "ok": result.ok, "note": result.note,
        "deployed": False, "scan_sources": [f"oci-sidescan:{rc.type}"] if result.ok else [],
        "components": len(result.components),
        "subject_key": (result.doc_id or result.node_id),
        **counts,
    }


def _repo_of(ref: str, host: str) -> str:
    """The bare repository path of a host-qualified ref (strip host + tag/digest)."""
    body = ref[len(host) + 1:] if ref.startswith(host + "/") else ref
    for sep in ("@", ":"):
        if sep in body.rsplit("/", 1)[-1]:
            body = body.rsplit(sep, 1)[0]
    return body


def scan_connector(rc: RegistryConnector, *, request, blob_get, secret_reader: SecretReader,
                   feed, epss, kev, exploits=frozenset(),
                   notes: Optional[List[str]] = None) -> List:
    """Impure BOUNDARY (all egress via the injected ``request`` / ``blob_get`` seams from
    ``aws_layer_fetch``; the credential via the injected ``secret_reader``). Resolve creds
    transiently, enumerate targets (explicit ``images`` + each ``repositories`` entry's tags,
    bounded by ``newest_n``), and pull+scan each image through ``aws_registry_oci.scan_oci_image``
    (which reuses the shared rootfs/OSV engine). Returns a list of ``(ref, RegistryImageResult)``.

    SAFE-BY-DEFAULT: a disabled connector scans nothing. Never raises — a creds/enumeration/pull
    failure is a note + an ``ok=False`` result, never a partial or a crash mid-sweep."""
    import aws_registry_oci as OCI
    n = notes if notes is not None else []
    if not rc.enabled:
        return []
    try:
        creds = resolve_creds(rc, secret_reader=secret_reader)
    except RegistryConnectorError as e:
        n.append(f"{rc.connector_id}: credential unavailable — {e}")
        return []
    except Exception:                                # a secret-store failure must never 500 the caller
        n.append(f"{rc.connector_id}: credential resolution failed (secret store error)")
        return []

    targets: List[str] = list(image_refs(rc))
    for repo in rc.repositories:
        try:
            bearer = OCI.obtain_bearer(rc.host, repo, creds, request=request)
        except Exception as e:                       # enumeration is best-effort (fail-open)
            n.append(f"{rc.connector_id}: auth for {repo} failed — {e}")
            continue
        tags = OCI.list_tags(rc.host, repo, bearer, request=request)[:rc.newest_n]
        if not tags:
            n.append(f"{rc.connector_id}: no tags enumerated for {repo}")
        targets += [f"{rc.host}/{repo}:{t}" for t in tags]

    seen: set = set()
    out: List = []
    for ref in targets:
        if ref in seen:
            continue
        seen.add(ref)
        # HOST-CONSISTENCY GUARD (charter: the credential + the per-call allowlist must be the CONFIG
        # host). If a ref resolves to any host other than rc.host — a mis-qualification, or a
        # dotless/odd host string — REFUSE it rather than pull, so the connector's secret can never
        # travel to a third-party registry (e.g. a bare "backend:prod" mis-parsing to Docker Hub).
        parsed_host, _, _ = OCI.parse_ref(ref)
        if parsed_host != rc.host:
            n.append(f"{rc.connector_id}: refusing {ref} — resolves to {parsed_host!r}, "
                     f"not the connector host {rc.host!r}")
            continue
        res = OCI.scan_oci_image(ref, creds, request=request, blob_get=blob_get, feed=feed,
                                 epss=epss, kev=kev, exploits=exploits,
                                 max_image_bytes=rc.max_image_bytes, notes=n)
        out.append((ref, res))
    return out


def mask_connector(rc: RegistryConnector) -> Dict:
    """API-safe view: the ``secret_ref`` is DROPPED to a ``secret_configured`` bool (never expose
    even the ref over the API), mirroring cnapp_connectors._mask_connector."""
    return {
        "connector_id": rc.connector_id, "type": rc.type, "host": rc.host, "name": rc.name,
        "enabled": rc.enabled, "auth": rc.auth, "username": rc.username,
        "secret_configured": bool(rc.secret_ref),
        "images": list(rc.images), "repositories": list(rc.repositories),
        "newest_n": rc.newest_n, "max_image_bytes": rc.max_image_bytes,
    }
