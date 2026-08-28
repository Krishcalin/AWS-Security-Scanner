#!/usr/bin/env python3
"""cnapp_server.py — the ASGI entrypoint for the hosted OverWatch hub.

    uvicorn cnapp_server:create_app_from_env --factory --host 0.0.0.0 --port 8080

serves the JSON API under ``/api`` and (if built) the React SPA at ``/``. The
``PlatformService`` is wired from environment variables, so the SAME image runs a
single-node sqlite hub or a Postgres HA hub with no code change. Air-gap friendly: no
build-time or run-time internet fetch — AWS via VPC endpoints, the vuln bundle from
disk, the SPA from the prebuilt ``frontend/dist``.

Environment:
  CNAPP_DB_URL           state backend URL (default ``sqlite:///data/overwatch.db``;
                         ``postgres://…`` selects Postgres — see aws_state_dialect.parse_state_url).
  CNAPP_STATIC_DIR       built SPA path (default ``frontend/dist``; served only if present).
  CNAPP_HUB_ROLE_ARN     hub role ARN stamped into onboarding launch URLs.
  CNAPP_CFN_TEMPLATE_URL scanner-role CFN template URL for the quick-create link.
  CNAPP_VULN_DB          OSV/EPSS/KEV bundle path (mounted read-only; optional).
  CNAPP_PROJECTS         Projects (LBI/MBI/HBI business-impact groupings) as a JSON list, or a
                         path to a JSON file — read-only, config-driven, optional. Shape:
                         [{id,name,tier,match:{accounts,resource_globs}}]. Fail-safe (bad → none).
  CNAPP_CONTROLS         Controls (saved-WQL-query-as-Control) as a JSON list, or a path to a
                         JSON file — read-only, config-driven, optional. Shape:
                         [{id,name,query,severity?,section?,description?}]. Fail-safe (bad → none).
  CNAPP_POLICIES         Policies (policy-as-code custom rules) as a JSON list, or a path to a
                         JSON file — read-only, config-driven, optional. Shape:
                         [{id,name,match:{op?,graph?,finding?},severity?,pack?}]. Fail-safe (bad → none).
  CNAPP_REGISTRIES       Non-AWS registry connectors (GHCR/Docker Hub/Harbor/ACR) to agentlessly
                         pull + side-scan, as a JSON list or a path to a JSON file — config-driven,
                         optional, disabled-by-default. Shape: [{connector_id,type,host?,auth?,
                         username?,secret_ref?,images?,repositories?}]. Fail-safe (bad → none); a
                         secret is a secretsmanager://|ssm:// REF, never plaintext.
  OVERWATCH_AIRGAP       "1" documents the sealed posture — no behavioural branch (all
                         optional seams already default off); the runbook enforces it.

AUTH IS FAIL-CLOSED. A production deployment MUST pass a ``current_principal`` dependency
that maps the authenticated caller (IdP/JWT claims) to a ``cnapp_api.Principal``. Left
unset here, every route returns 403 until real auth is wired — a forgotten auth wiring can
never silently grant access. NEVER ship with a permissive hook.
"""
from __future__ import annotations

import os


def _secret_unconfigured(*_a, **_k):
    # Fail loud (not silent, not plaintext): a real deployment injects a Secrets Manager /
    # SSM Parameter Store resolver. Onboarding refuses until then; reads still serve.
    raise RuntimeError(
        "configure a secret store: wire secret_writer/secret_reader in build_service() to "
        "your SSM Parameter Store / Secrets Manager (secrets are stored ONLY as "
        "secretsmanager://|ssm:// refs, never plaintext)")


def _secret_seams():
    """``(secret_writer, secret_reader)`` for this deployment.

    Configured => AWS Secrets Manager. Unconfigured => the pair above, which
    raises with instructions. Resolved ONCE per build_service() call so a
    misconfiguration surfaces at startup rather than on the first onboarding.
    """
    from hub import cnapp_secrets

    seams = cnapp_secrets.build_from_env()
    if seams is None:
        return _secret_unconfigured, _secret_unconfigured
    return seams


def _load_projects():
    """Load read-only Project defs (LBI/MBI/HBI business-impact groupings) from CNAPP_PROJECTS
    — either a JSON list, or a path to a JSON file. Fail-SAFE: any error → no projects (the
    feature is simply absent, never a server crash). Local env/file read only — no network, so
    the zero-telemetry boundary is untouched. Shape: [{id,name,tier,match:{accounts,resource_globs}}]."""
    import json
    raw = os.environ.get("CNAPP_PROJECTS", "").strip()
    if not raw:
        return []
    try:
        data = json.loads(raw) if raw.startswith("[") else json.load(open(raw, encoding="utf-8"))
        return [p for p in data if isinstance(p, dict) and p.get("id")]
    except Exception:
        return []


def _load_controls():
    """Load read-only Control defs (saved-WQL-query-as-Control) from CNAPP_CONTROLS — either a
    JSON list, or a path to a JSON file. Fail-SAFE (mirror _load_projects): any error → no
    controls. Local env/file read only. Shape: [{id,name,query,severity?,section?,description?}].
    A def must carry an id AND a dict query to be admitted; the query itself is validated (and
    fail-safe) later by the WQL compiler at read time."""
    import json
    raw = os.environ.get("CNAPP_CONTROLS", "").strip()
    if not raw:
        return []
    try:
        data = json.loads(raw) if raw.startswith("[") else json.load(open(raw, encoding="utf-8"))
        return [c for c in data if isinstance(c, dict) and c.get("id") and isinstance(c.get("query"), dict)]
    except Exception:
        return []


def _load_policies():
    """Load read-only Policy defs (policy-as-code custom rules) from CNAPP_POLICIES — a JSON list
    or a path to a JSON file. Fail-SAFE (mirror _load_controls): any error → no policies. Local
    env/file read only. Shape: [{id,name,match:{op?,graph?,finding?},severity?,section?,pack?}].
    A def must carry an id AND a dict match; the rule is fully validated (fail-safe) by the policy
    compiler at read time."""
    import json
    raw = os.environ.get("CNAPP_POLICIES", "").strip()
    if not raw:
        return []
    try:
        data = json.loads(raw) if raw.startswith("[") else json.load(open(raw, encoding="utf-8"))
        return [p for p in data if isinstance(p, dict) and p.get("id") and isinstance(p.get("match"), dict)]
    except Exception:
        return []


def _load_registry_connectors():
    """Load non-AWS registry connector defs (Batch 6) from CNAPP_REGISTRIES — a JSON list or a path
    to a JSON file. Fail-SAFE (mirror _load_policies): any error → no connectors. Local env/file
    read only. Shape: [{connector_id,type,host?,auth?,username?,secret_ref?,images?,repositories?}].
    Each entry is fully validated (and fail-safe per-entry) by aws_registry_connectors.parse at
    service init; a malformed entry is simply dropped and never pulls."""
    import json
    raw = os.environ.get("CNAPP_REGISTRIES", "").strip()
    if not raw:
        return []
    try:
        data = json.loads(raw) if raw.startswith("[") else json.load(open(raw, encoding="utf-8"))
        return [c for c in data if isinstance(c, dict)]
    except Exception:
        return []


def build_service():
    """Construct the PlatformService from env. Multi-tenant + metered; fail-closed auth
    is applied at the API layer, not here."""
    from store import aws_state
    from store import cnapp_backend
    from hub import cnapp_connectors
    from hub import cnapp_application
    from hub import cnapp_customcontrol
    from hub import cnapp_metering
    from hub import cnapp_registry
    from hub import cnapp_service
    from hub import cnapp_workspace

    db_url = os.environ.get("CNAPP_DB_URL", "sqlite:///data/overwatch.db")
    # check_same_thread=False: FastAPI serves sync routes from a threadpool; the backend's
    # reentrant lock serializes every access (mirrors AccountRegistry.open).
    be = cnapp_backend.backend_for(db_url, check_same_thread=False)   # connect + migrate + seed
    reg = cnapp_registry.AccountRegistry(be)
    svc = cnapp_service.PlatformService(
        registry=reg,
        # Persisted, so a hub restart no longer blanks every screen that renders a
        # scan. The in-memory store is still the right thing in tests and the
        # sample-mode generators, which build a service per process.
        results=cnapp_service.BackendResultStore(be),
        hub_role_arn=os.environ.get("CNAPP_HUB_ROLE_ARN", ""),
        cfn_template_url=os.environ.get("CNAPP_CFN_TEMPLATE_URL", ""),
        # AWS Secrets Manager when CNAPP_SECRETS_BACKEND says so, otherwise the
        # fail-loud placeholders below. Unconfigured stays a REFUSAL rather than a
        # fallback: a hub that quietly kept plaintext, or silently dropped the
        # write, would be worse than one that will not onboard.
        secret_writer=_secret_seams()[0],
        secret_reader=_secret_seams()[1],
        state=aws_state.StateStore(be),
        workspaces=cnapp_workspace.WorkspaceStore(be),
        metering=cnapp_metering.MeteringStore(be),
        connectors=cnapp_connectors.ConnectorStore(be),
        projects=_load_projects(),
        controls=_load_controls(),
        # Authored controls (v16) share the SAME backend as every other store, so a
        # deployment gets one connection pool rather than a second one per feature.
        custom_controls=cnapp_customcontrol.CustomControlStore(be),
        applications=cnapp_application.ApplicationStore(be),
        policies=_load_policies(),
        registry_connectors=_load_registry_connectors(),
    )
    # The one Backend this service was built on. Exposed so an auth provider (or any
    # other add-on store) shares this connection/pool instead of opening a second one
    # against the same database — two pools would double the connection count and,
    # on sqlite, contend for the same file lock.
    svc.backend = be
    return svc


def create_app_from_env(*, service=None, current_principal=None):
    """Build the hosted ASGI app. ``uvicorn cnapp_server:create_app_from_env --factory``.
    ``current_principal`` defaults to None ⇒ fail-closed (every route 403) until a real
    IdP dependency is injected."""
    from hub import cnapp_api
    svc = service if service is not None else build_service()
    static_dir = os.environ.get("CNAPP_STATIC_DIR", os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend", "dist"))
    return cnapp_api.create_hosted_app(svc, static_dir=static_dir,
                                       current_principal=current_principal)


def create_app(*, service=None):
    """The image's entry point: pick the auth provider from ``CNAPP_AUTH_MODE``.

        local  -> create_app_with_local_auth  (built-in users; self-hosted)
        idp    -> create_app_from_env         (fail-closed until a principal is
                                               injected by your own factory)

    WHY THIS EXISTS. The image used to default to ``create_app_from_env``, whose
    ``current_principal`` is None => EVERY ROUTE 403. That is safe, but it is
    silent: a fresh deployment looks like a broken permissions setup rather than
    an unconfigured one, and the only way to find out is to read the source. An
    unset mode now stops the process with a message naming the choice.

    Both factories above keep their exact previous behaviour; this only chooses.
    """
    mode = (os.environ.get("CNAPP_AUTH_MODE") or "").strip().lower()
    if mode == "local":
        return create_app_with_local_auth(service=service)
    if mode == "idp":
        return create_app_from_env(service=service)
    raise SystemExit(
        "CNAPP_AUTH_MODE is not set. Choose how this hub authenticates:\n"
        "  CNAPP_AUTH_MODE=local  built-in users; bootstrap the first admin with\n"
        "                         OVERWATCH_BOOTSTRAP_USER / _PASSWORD\n"
        "  CNAPP_AUTH_MODE=idp    you inject current_principal from your own IdP\n"
        "                         (uvicorn hub.cnapp_server:create_app_from_env)\n"
        "Refusing to start rather than serve 403 on every route.")


def create_app_with_local_auth(*, service=None):
    """The hosted app with the BUILT-IN local authentication provider wired in.

    `create_app_from_env` above stays fail-closed and unchanged. This is a second,
    explicit entrypoint for a self-hosted install with no IdP in front of it:

        uvicorn cnapp_server:create_app_with_local_auth --factory

    It is not a "permissive hook" in the sense the module docstring warns about —
    every request must present a valid session cookie, and an unauthenticated one
    still resolves to an empty Principal, which is deny-all. What it adds is a way
    to OBTAIN that session. An operator who authenticates at their own edge keeps
    using `create_app_from_env` and injects their IdP dependency instead.

    The first administrator comes from OVERWATCH_BOOTSTRAP_USER /
    OVERWATCH_BOOTSTRAP_PASSWORD, applied once against an empty user table. There is
    no default credential and nothing is printed — see cnapp_authn.bootstrap_admin.
    """
    from hub import cnapp_api
    from hub import cnapp_authn
    from hub import cnapp_authn_api
    from hub import cnapp_workspace

    svc = service if service is not None else build_service()
    backend = getattr(svc, "backend", None)
    if backend is None:                       # a caller-supplied service (tests)
        raise RuntimeError("service was built without an exposed backend; "
                           "pass one built by build_service()")
    store = cnapp_authn.UserStore(backend)
    workspaces = svc.workspaces if getattr(svc, "workspaces", None) is not None         else cnapp_workspace.WorkspaceStore(backend)
    cnapp_authn.bootstrap_admin(store, workspaces)

    static_dir = os.environ.get("CNAPP_STATIC_DIR", os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend", "dist"))
    return cnapp_api.create_hosted_app(
        svc, static_dir=static_dir,
        current_principal=cnapp_authn_api.session_principal_dependency(store, workspaces),
        configure_api=lambda api: cnapp_authn_api.add_auth_routes(api, store, workspaces),
    )


if __name__ == "__main__":                                 # pragma: no cover - manual run
    import uvicorn
    uvicorn.run(create_app_from_env(), host=os.environ.get("HOST", "0.0.0.0"),
                port=int(os.environ.get("PORT", "8080")))
