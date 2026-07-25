#!/usr/bin/env bash
# Assemble the OverWatch air-gap bundle on a CONNECTED build host. Produces a single
# tarball to carry across the air-gap: a pinned wheelhouse + the prebuilt SPA + the Docker
# image + the deploy artifacts. NOTHING in this script runs on the air-gapped side.
#
#   scripts/build_offline_bundle.sh [version]
#
# Env: WHEEL_PLATFORM (default manylinux2014_x86_64), PYTHON_VERSION (default 3.12).
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${1:-$(grep -m1 '^VERSION' aws_live_scanner.py | cut -d'"' -f2)}"
ARCH="${WHEEL_PLATFORM:-manylinux2014_x86_64}"
PYV="${PYTHON_VERSION:-3.12}"
OUT="overwatch-airgap-${VERSION}"

echo ">> [1/5] downloading pinned wheels (arch=${ARCH}, py=${PYV}) -> wheelhouse/"
rm -rf wheelhouse && mkdir -p wheelhouse
pip download -r requirements.txt -d wheelhouse \
    --platform "${ARCH}" --python-version "${PYV}" --only-binary=:all:

echo ">> [2/5] ensuring the React SPA is built (needs npm; connected host only)"
if [ -d frontend ] && [ ! -f frontend/dist/index.html ]; then
    ( cd frontend && npm ci && npm run build )
fi
[ -f frontend/dist/index.html ] || { echo "!! frontend/dist missing and could not be built"; exit 1; }

echo ">> [3/5] building the Docker image (offline install from wheelhouse)"
docker build -t "overwatch-hub:${VERSION}" .

echo ">> [4/5] docker save"
docker save "overwatch-hub:${VERSION}" -o "${OUT}-image.tar"

echo ">> [5/5] assembling the transfer tarball"
tar czf "${OUT}.tar.gz" \
    "${OUT}-image.tar" wheelhouse frontend/dist deploy \
    requirements.txt requirements-core.txt NETWORK.md docs/AIRGAP_RUNBOOK.md
rm -f "${OUT}-image.tar"

echo ">> done: ${OUT}.tar.gz"
echo ">> carry this single file across the air-gap; then follow docs/AIRGAP_RUNBOOK.md"
