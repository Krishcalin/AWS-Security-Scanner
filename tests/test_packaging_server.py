"""Phase-4 Slice-2 · B2/B3 — the ASGI launcher wires a working multi-tenant service and
FAILS CLOSED, and the requirements files are fully pinned (reproducible offline installs)."""
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
import cnapp_server


# ── B3: the launcher ──────────────────────────────────────────────────────────
def test_build_service_wires_multitenant_metered(monkeypatch):
    monkeypatch.setenv("CNAPP_DB_URL", ":memory:")
    svc = cnapp_server.build_service()
    assert svc.workspaces is not None and svc.metering is not None and svc.state is not None
    assert svc.get_workspace("ws-default") is not None       # backend_for seeded it


def test_app_is_fail_closed_by_default(monkeypatch):
    import cnapp_api
    if not cnapp_api._HAVE_FASTAPI:
        pytest.skip("fastapi not installed")
    monkeypatch.setenv("CNAPP_DB_URL", ":memory:")
    monkeypatch.setenv("CNAPP_STATIC_DIR", os.path.join(ROOT, "does-not-exist"))
    from fastapi.testclient import TestClient
    c = TestClient(cnapp_server.create_app_from_env())        # current_principal None
    assert c.get("/api/accounts").status_code == 403          # deny all until auth wired


def test_secret_store_fails_loud_not_plaintext():
    with pytest.raises(RuntimeError):
        cnapp_server._secret_unconfigured("acct", "plaintext")


# ── B2: pinned requirements (provable, air-gap-reproducible) ──────────────────
def _reqs(name):
    lines = []
    for ln in open(os.path.join(ROOT, name), encoding="utf-8").read().splitlines():
        ln = ln.strip()
        if ln and not ln.startswith("#") and not ln.startswith("-r "):
            lines.append(ln)
    return lines


@pytest.mark.parametrize("name", ["requirements.txt", "requirements-core.txt"])
def test_requirements_fully_pinned(name):
    for ln in _reqs(name):
        # every dependency must be == pinned (no floating >=/~=/unpinned) for offline repro
        assert re.match(r"^[A-Za-z0-9_.\-]+(\[[a-z,]+\])?==[0-9][^ ]*$", ln), \
            f"{name}: '{ln}' is not =='pinned"


def test_core_is_subset_of_hub():
    core = {re.split(r"[\[=]", l)[0] for l in _reqs("requirements-core.txt")}
    hub = {re.split(r"[\[=]", l)[0] for l in _reqs("requirements.txt")}
    assert core <= hub                                        # the hub image is a superset


# ── B4: offline Docker build invariants ───────────────────────────────────────
def test_dockerfile_installs_offline():
    df = open(os.path.join(ROOT, "Dockerfile"), encoding="utf-8").read()
    assert "--no-index" in df                                 # no network at build time
    assert "--find-links" in df and "wheelhouse" in df
    assert "USER overwatch" in df                             # non-root runtime
    assert "--factory" in df                                  # no import-time app side effect


def test_dockerignore_keeps_prebuilt_spa():
    di = open(os.path.join(ROOT, ".dockerignore"), encoding="utf-8").read()
    lines = {ln.strip() for ln in di.splitlines() if ln.strip() and not ln.startswith("#")}
    # the prebuilt SPA (git-ignored but shipped in the offline bundle) must reach the
    # build context — an accidental `frontend/dist` or bare `dist` exclusion breaks air-gap
    assert "frontend/dist" not in lines and "dist" not in lines and "frontend" not in lines

