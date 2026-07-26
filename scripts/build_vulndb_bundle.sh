#!/usr/bin/env bash
# Build a SIGNED offline OverWatch vulnerability feed on a CONNECTED build host, then carry
# the tiny signed artifact across the air-gap. NOTHING here runs on the air-gapped side.
#
#   scripts/build_vulndb_bundle.sh <ed25519-private-seed.key> [out-dir]
#
# The private seed is produced once by:  python scripts/overwatch_vulndb.py keygen
# Ship ONLY the matching .pub into the runtime image (pin it as --vuln-db-pubkey); keep the
# .key offline with the feed publisher.
#
# Design (matches build_offline_bundle.sh): the internet FETCH is curl in THIS bash script —
# outside the Python zero-telemetry tripwire. The Python assembler (overwatch_vulndb.py) only
# reads the staged local files and imports no network primitive, so the runtime's egress
# surface is provably unchanged. Env: ECOSYSTEMS (comma list) overrides the default set.
set -euo pipefail
cd "$(dirname "$0")/.."

KEY="${1:?usage: build_vulndb_bundle.sh <private-seed.key> [out-dir]}"
OUT="${2:-vulndb-out}"
STAGE="$(mktemp -d)"
trap 'rm -rf "${STAGE}"' EXIT
mkdir -p "${OUT}/osv"

# OSV GCS bucket ecosystem directories the matching engine can hit (see DEFAULT_ECOSYSTEMS).
DEFAULT_ECOS="Debian,Ubuntu,Alpine,Rocky Linux,AlmaLinux,Red Hat,Amazon Linux,openSUSE,SUSE,npm,PyPI,Go,RubyGems,crates.io,Maven"
ECOS="${ECOSYSTEMS:-$DEFAULT_ECOS}"
OSV_BASE="https://osv-vulnerabilities.storage.googleapis.com"
EPSS_URL="https://epss.cyentia.com/epss_scores-current.csv.gz"
KEV_URL="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

echo ">> [1/4] fetching OSV bulk archives per ecosystem -> ${OUT}/osv/"
IFS=',' read -ra ECO_ARR <<< "${ECOS}"
for eco in "${ECO_ARR[@]}"; do
    enc="${eco// /%20}"                       # URL-encode the space in "Red Hat" etc.
    safe="${eco// /_}"
    echo "   - ${eco}"
    curl -fsSL "${OSV_BASE}/${enc}/all.zip" -o "${OUT}/osv/${safe}.zip" \
        || echo "     (skip ${eco}: not available)"
done

echo ">> [2/4] fetching EPSS scores + CISA KEV"
curl -fsSL "${EPSS_URL}" -o "${STAGE}/epss.csv.gz"
curl -fsSL "${KEV_URL}"  -o "${STAGE}/kev.json"

echo ">> [3/4] assembling + signing the feed (pure-stdlib, no network)"
python scripts/overwatch_vulndb.py build \
    --osv "${OUT}/osv" \
    --epss "${STAGE}/epss.csv.gz" \
    --kev "${STAGE}/kev.json" \
    ${ECOSYSTEMS:+--ecosystems "${ECOSYSTEMS}"} \
    --out "${OUT}/overwatch-vulndb.json" \
    --key "${KEY}"

echo ">> [4/4] done"
echo "   feed : ${OUT}/overwatch-vulndb.json      (mount read-only, pass to --vuln-db)"
echo "   sig  : ${OUT}/overwatch-vulndb.json.sig  (verified in-boundary)"
echo "   man  : ${OUT}/overwatch-vulndb.json.manifest.json"
echo "Carry the feed + .sig across the air-gap; run the scanner with:"
echo "   --vuln-db ${OUT}/overwatch-vulndb.json --vuln-db-pubkey <your-key.pub>"
