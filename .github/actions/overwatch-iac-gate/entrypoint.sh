#!/usr/bin/env bash
# OverWatch IaC shift-left gate. SHELL-ONLY (no committed Python under .github/ so the repo's
# zero-telemetry tripwire has nothing to inspect) + PURE LOCAL: it runs the offline IaC SAST,
# writes SARIF for PR annotations, and sets the exit code from the severity/policy gate. It calls
# NO cloud API and NO OverWatch hub — the opposite of the image-scan action (which ingests). No
# token, no egress: findings reach the PR only via GitHub's own code-scanning upload step.
set -euo pipefail

: "${OW_PATH:=.}"
: "${OW_FAIL_ON:=HIGH}"
: "${OW_SARIF:=overwatch-iac.sarif}"
: "${OW_POLICY:=}"

case "$OW_FAIL_ON" in
  CRITICAL|HIGH|MEDIUM|LOW) : ;;
  *) echo "::error::fail-on must be one of CRITICAL|HIGH|MEDIUM|LOW"; exit 1 ;;
esac
if [ ! -e "$OW_PATH" ]; then
  echo "::error::path not found: $OW_PATH"; exit 1
fi

# The scanner lives in engine/; resolve it relative to this action, whichever checkout
# layout is in play (the action may be vendored under .github/actions or referenced by ref).
# The legacy repo-root paths are kept as FALLBACKS so the action still works when it is
# pinned to a ref from before the engine/hub/store split. aws_offline_scanner has no
# cross-package imports, so it still runs by path -- only the path moved.
SCANNER=""
for cand in \
  "$GITHUB_WORKSPACE/engine/aws_offline_scanner.py" \
  "$(dirname "$0")/../../../engine/aws_offline_scanner.py" \
  "engine/aws_offline_scanner.py" \
  "$GITHUB_WORKSPACE/aws_offline_scanner.py" \
  "$(dirname "$0")/../../../aws_offline_scanner.py" \
  "aws_offline_scanner.py"; do
  if [ -f "$cand" ]; then SCANNER="$cand"; break; fi
done
if [ -z "$SCANNER" ]; then
  echo "::error::engine/aws_offline_scanner.py not found (check out the OverWatch repo before this step)"; exit 1
fi

ARGS=("$SCANNER" "$OW_PATH" --sarif "$OW_SARIF" --fail-on "$OW_FAIL_ON")
if [ -n "$OW_POLICY" ]; then
  if [ ! -f "$OW_POLICY" ]; then echo "::error::policy file not found: $OW_POLICY"; exit 1; fi
  ARGS+=(--policy "$OW_POLICY")
fi

# Run the gate. Exit 0 = clean, 1 = do not proceed (a finding or policy breached the
# gate, or a policy could not be evaluated in an enforcing environment), 2 = the build
# was NOT verified: either a usage/environment error, or the gate proceeded without a
# completed evaluation (an unparseable policy in audit mode, a break-glass override, or
# a target with no IaC files and no --allow-empty). Both non-zero codes fail the step,
# which is the point: an evaluation that did not happen is never a pass. The scanner's
# own `[gate]` lines above say which case this was, and --gate-record writes it as JSON.
set +e
python3 "${ARGS[@]}"
RC=$?
set -e
case "$RC" in
  0) echo "OverWatch IaC gate passed (no findings at or above ${OW_FAIL_ON})." ;;
  1) echo "::error::OverWatch IaC gate failed — findings at or above ${OW_FAIL_ON}, a policy fired, or a policy could not be evaluated. See SARIF annotations and the [gate] lines above." ;;
  2) echo "::error::OverWatch IaC gate UNVERIFIED (exit 2) — this is not a pass. Either the scan hit a usage/environment error, or it proceeded without a completed evaluation. See the [gate] lines above." ;;
  *) echo "::error::OverWatch IaC scan errored (exit ${RC})." ;;
esac
exit "$RC"
