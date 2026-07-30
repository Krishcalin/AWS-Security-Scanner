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

# The scanner lives at the repo root; resolve it relative to this action, whichever checkout
# layout is in play (the action may be vendored under .github/actions or referenced by ref).
SCANNER=""
for cand in \
  "$GITHUB_WORKSPACE/aws_offline_scanner.py" \
  "$(dirname "$0")/../../../aws_offline_scanner.py" \
  "aws_offline_scanner.py"; do
  if [ -f "$cand" ]; then SCANNER="$cand"; break; fi
done
if [ -z "$SCANNER" ]; then
  echo "::error::aws_offline_scanner.py not found (check out the OverWatch repo before this step)"; exit 1
fi

ARGS=("$SCANNER" "$OW_PATH" --sarif "$OW_SARIF" --fail-on "$OW_FAIL_ON")
if [ -n "$OW_POLICY" ]; then
  if [ ! -f "$OW_POLICY" ]; then echo "::error::policy file not found: $OW_POLICY"; exit 1; fi
  ARGS+=(--policy "$OW_POLICY")
fi

# Run the gate. Exit 0 = clean, 1 = a finding/policy breached the gate (fail the build),
# 2 = usage/environment error (surfaced distinctly).
set +e
python3 "${ARGS[@]}"
RC=$?
set -e
case "$RC" in
  0) echo "OverWatch IaC gate passed (no findings at or above ${OW_FAIL_ON})." ;;
  1) echo "::error::OverWatch IaC gate failed — findings at or above ${OW_FAIL_ON} (or a policy fired). See SARIF annotations." ;;
  *) echo "::error::OverWatch IaC scan errored (exit ${RC})." ;;
esac
exit "$RC"
