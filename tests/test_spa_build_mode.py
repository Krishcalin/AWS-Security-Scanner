"""
The shipped SPA must be built in LIVE mode, deterministically.

WHY THIS TEST EXISTS, MEASURED RATHER THAN ASSUMED
`frontend/src/api/client.ts` defaults `VITE_DATA_SOURCE` to `'sample'`, which reads
static fixtures and never calls the API. Nothing set it anywhere — not the build
script, not either Dockerfile, not CI — so the hub image shipped a console that
showed three demo accounts, never asked who anyone was, and did not contain the
sign-in, user-menu or logout code AT ALL. Vite tree-shakes it: building both ways
and grepping the bundles, `auth/me`, `auth/logout` and `Signed in as` are present in
the live bundle and absent from the sample one.

So an entire authentication feature could pass every unit test, work perfectly in
development, and be missing from the artifact customers install.

The second half is just as bad. `build_offline_bundle.sh` used to SKIP the SPA build
when `frontend/dist/index.html` already existed, which made the mode of the image
depend on whatever the build host had lying around — the same commit produced an
authenticated product on one machine and an auth-less demo on another.

These are text assertions over the build script because the artifact itself
(`frontend/dist`) is gitignored and absent in CI. Checking the recipe is the only
check available, and it is the thing that actually drifted.
"""
from __future__ import annotations

import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "build_offline_bundle.sh")


def _script() -> str:
    with open(SCRIPT, encoding="utf-8") as fh:
        return fh.read()


def test_the_spa_is_built_in_live_mode():
    """Without this the hub image serves fixtures and has no login."""
    src = _script()
    assert re.search(r"VITE_DATA_SOURCE=live\s+npm run build", src), (
        "scripts/build_offline_bundle.sh must build the SPA with "
        "VITE_DATA_SOURCE=live — client.ts defaults to 'sample', which ships a "
        "console with no authentication code in it at all")


def test_the_spa_build_is_not_skipped_when_a_stale_dist_exists():
    """A conditional rebuild makes the shipped mode depend on the build host."""
    src = _script()
    assert "! -f frontend/dist/index.html" not in src, (
        "the SPA build must not be skipped when frontend/dist already exists: the "
        "same commit then produces an authenticated product on one machine and an "
        "auth-less demo on another")


def test_the_dockerfiles_say_the_prebuilt_spa_must_be_live():
    """Both images COPY a prebuilt dist rather than building it, so the requirement
    has to be stated where somebody doing it by hand will read it."""
    for name in ("Dockerfile", os.path.join("deploy", "local", "Dockerfile")):
        path = os.path.join(ROOT, name)
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
        if "frontend/dist" not in src:
            continue
        assert "VITE_DATA_SOURCE=live" in src, (
            f"{name} copies a prebuilt frontend/dist but never says it must be "
            f"built with VITE_DATA_SOURCE=live")


# ── caching: the one file that must never be cached ─────────────────────────
def test_index_html_is_never_cached_and_hashed_assets_are(tmp_path):
    """A SPA's index.html is the ONLY pointer to its content-hashed bundle, so
    it must be revalidated every time and the bundle may be cached forever.

    Served with no Cache-Control at all, index.html falls to the browser's
    HEURISTIC freshness rule — roughly a tenth of the time since Last-Modified,
    with no request to the server. A console updated minutes after it was last
    opened then keeps loading the PREVIOUS bundle, and a feature that shipped is
    simply absent: no error, nothing in the log, and a served /assets/*.js that
    demonstrably contains the new code.

    That is not hypothetical. It is how the Roles & Access nav entry came to be
    missing from a console whose bundle already had it.
    """
    from fastapi.testclient import TestClient

    import cnapp_api

    static = tmp_path / "dist"
    (static / "assets").mkdir(parents=True)
    (static / "index.html").write_text(
        "<!doctype html><script src=/assets/index-abc.js></script>",
        encoding="utf-8")
    (static / "assets" / "index-abc.js").write_text("console.log(1)",
                                                    encoding="utf-8")

    # A bare stub: the static-serving path never touches the service, and
    # building a real one here would test the wrong thing slowly.
    class _StubService:
        pass

    app = cnapp_api.create_hosted_app(_StubService(), static_dir=str(static))
    client = TestClient(app)

    root = client.get("/")
    assert root.status_code == 200
    assert "no-store" in root.headers.get("cache-control", "")

    # A client-side deep link resolves to index.html and must not be cached
    # either — otherwise the fallback re-introduces exactly the same staleness.
    deep = client.get("/roles")
    assert deep.status_code == 200
    assert "no-store" in deep.headers.get("cache-control", "")

    asset = client.get("/assets/index-abc.js")
    assert asset.status_code == 200
    assert "immutable" in asset.headers.get("cache-control", "")
