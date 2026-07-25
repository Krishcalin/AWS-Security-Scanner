# OverWatch hosted hub — offline / air-gap-installable, multi-stage, non-root.
#
# On a CONNECTED build host, first populate ./wheelhouse and build the SPA:
#     scripts/build_offline_bundle.sh
# then build (the runtime install uses --no-index => ZERO network at build time):
#     docker build -t overwatch-hub .
#
# The image reaches AWS via VPC endpoints only; no telemetry, no internet fetch. See
# NETWORK.md and docs/AIRGAP_RUNBOOK.md.

# ---- stage 1: install the pinned wheels from the offline wheelhouse (no network) ----
FROM python:3.12-slim AS deps
WORKDIR /app
COPY requirements.txt ./
COPY wheelhouse/ ./wheelhouse/
RUN pip install --no-cache-dir --no-index --find-links=./wheelhouse -r requirements.txt

# ---- stage 2: minimal non-root runtime ----
FROM python:3.12-slim AS runtime
# python:3.12-slim ships libsqlite3 >= 3.24, satisfying the ON CONFLICT floor the backend
# pre-flights (cnapp_backend.py). Verify in the runbook smoke test.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    CNAPP_DB_URL=sqlite:////data/overwatch.db \
    CNAPP_STATIC_DIR=/app/frontend/dist
WORKDIR /app
COPY --from=deps /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=deps /usr/local/bin /usr/local/bin
# application code + compliance crosswalk data + the prebuilt SPA (dist is INCLUDED in the
# build context via .dockerignore even though it is git-ignored)
COPY *.py ./
COPY compliance/ ./compliance/
COPY frontend/dist/ ./frontend/dist/
# non-root user + a writable /data for the sqlite file and the mounted vuln bundle
RUN useradd -r -u 10001 overwatch && mkdir -p /data && chown -R overwatch:overwatch /data /app
USER overwatch
EXPOSE 8080
# factory entrypoint: no module-level app => no import-time disk side effect. Auth is
# FAIL-CLOSED until a real current_principal is wired (see cnapp_server.py).
CMD ["uvicorn", "cnapp_server:create_app_from_env", "--factory", \
     "--host", "0.0.0.0", "--port", "8080"]
