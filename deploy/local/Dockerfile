# OverWatch — LOCAL DEVELOPMENT image. NOT the shipped artifact.
#
# The production image is the repo-root `Dockerfile`: multi-stage, non-root, and
# installed with `pip --no-index --find-links=./wheelhouse` so the build makes ZERO
# network calls. That is a charter property (air-gap installable) and it is why the
# root Dockerfile cannot be built on a machine without a populated ./wheelhouse.
#
# This file is the developer-convenience twin: same runtime, but it resolves wheels
# from PyPI so a laptop can build without running scripts/build_offline_bundle.sh
# first. Keeping it SEPARATE means the shipped image's no-network guarantee is never
# weakened for local convenience — the two cannot be confused, and CI keeps building
# the real one.
#
#     docker compose -f deploy/local/docker-compose.yml up --build
#
FROM python:3.12-slim AS deps
WORKDIR /app
COPY requirements.txt ./
# CONNECTED build, unlike the shipped image. psycopg[binary] is in requirements, so
# the Postgres backend works without a compiler in the image.
RUN pip install --no-cache-dir -r requirements.txt

FROM python:3.12-slim AS runtime
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    CNAPP_STATIC_DIR=/app/frontend/dist \
    OVERWATCH_LOCAL_DEV=1
WORKDIR /app
COPY --from=deps /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=deps /usr/local/bin /usr/local/bin
COPY *.py ./
COPY compliance/ ./compliance/
COPY frontend/dist/ ./frontend/dist/
COPY deploy/local/local_server.py ./local_server.py
# Non-root, matching the production image. /data is unused on the Postgres path but
# is kept so switching CNAPP_DB_URL back to sqlite:// still works for a quick test.
RUN useradd -r -u 10001 overwatch && mkdir -p /data && chown -R overwatch:overwatch /data /app
USER overwatch
EXPOSE 8080
# The BUILT-IN local-authn provider: a real sign-in page backed by app_user /
# app_session, not a permissive hook. Every request still needs a valid session and
# an unauthenticated one resolves to an empty Principal, which is deny-all — so the
# fail-closed posture of `create_app_from_env` is preserved, this just adds a way to
# obtain a session.
#
# `local_server.py` (unauthenticated superadmin, no login) stays in the image for a
# no-login smoke test, but it is deliberately NOT the default any more.
CMD ["uvicorn", "cnapp_server:create_app_with_local_auth", "--factory", \
     "--host", "0.0.0.0", "--port", "8080"]
