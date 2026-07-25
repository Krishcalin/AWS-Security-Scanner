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


def build_service():
    """Construct the PlatformService from env. Multi-tenant + metered; fail-closed auth
    is applied at the API layer, not here."""
    import aws_state
    import cnapp_backend
    import cnapp_connectors
    import cnapp_metering
    import cnapp_registry
    import cnapp_service
    import cnapp_workspace

    db_url = os.environ.get("CNAPP_DB_URL", "sqlite:///data/overwatch.db")
    # check_same_thread=False: FastAPI serves sync routes from a threadpool; the backend's
    # reentrant lock serializes every access (mirrors AccountRegistry.open).
    be = cnapp_backend.backend_for(db_url, check_same_thread=False)   # connect + migrate + seed
    reg = cnapp_registry.AccountRegistry(be)
    return cnapp_service.PlatformService(
        registry=reg,
        results=cnapp_service.InMemoryResultStore(),       # in-memory; a re-scan repopulates
        hub_role_arn=os.environ.get("CNAPP_HUB_ROLE_ARN", ""),
        cfn_template_url=os.environ.get("CNAPP_CFN_TEMPLATE_URL", ""),
        secret_writer=_secret_unconfigured,
        secret_reader=_secret_unconfigured,
        state=aws_state.StateStore(be),
        workspaces=cnapp_workspace.WorkspaceStore(be),
        metering=cnapp_metering.MeteringStore(be),
        connectors=cnapp_connectors.ConnectorStore(be),
    )


def create_app_from_env(*, service=None, current_principal=None):
    """Build the hosted ASGI app. ``uvicorn cnapp_server:create_app_from_env --factory``.
    ``current_principal`` defaults to None ⇒ fail-closed (every route 403) until a real
    IdP dependency is injected."""
    import cnapp_api
    svc = service if service is not None else build_service()
    static_dir = os.environ.get("CNAPP_STATIC_DIR", os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "frontend", "dist"))
    return cnapp_api.create_hosted_app(svc, static_dir=static_dir,
                                       current_principal=current_principal)


if __name__ == "__main__":                                 # pragma: no cover - manual run
    import uvicorn
    uvicorn.run(create_app_from_env(), host=os.environ.get("HOST", "0.0.0.0"),
                port=int(os.environ.get("PORT", "8080")))
