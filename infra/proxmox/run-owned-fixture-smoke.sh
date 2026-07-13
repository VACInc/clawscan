#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
clawscan_bin="${CLAWSCAN_BIN:-$repo_root/bin/clawscan}"
output_root="${1:-$repo_root/.runner-smoke}"
gate_runner="$repo_root/infra/proxmox/run-security-gate.sh"

[[ -x "$clawscan_bin" ]] || { echo "missing executable ClawScan binary: $clawscan_bin" >&2; exit 2; }
[[ -x "$gate_runner" ]] || { echo "missing security gate runner: $gate_runner" >&2; exit 2; }
mkdir -p "$output_root/pass-skill" "$output_root/pass-plugin" "$output_root/rejected-probe"

CLAWSCAN_BIN="$clawscan_bin" "$gate_runner" \
  "$repo_root/testdata/fixtures/pipeline-safe-skill" \
  "$output_root/pass-skill"
jq -e '.status == "passed" and .reason == "free/static security scan passed"' \
  "$output_root/pass-skill/security-gate.json" >/dev/null

CLAWSCAN_BIN="$clawscan_bin" "$gate_runner" \
  "$repo_root/testdata/fixtures/pipeline-safe-plugin" \
  "$output_root/pass-plugin"
jq -e '.status == "passed" and .reason == "free/static security scan passed"' \
  "$output_root/pass-plugin/security-gate.json" >/dev/null

probe_status=0
CLAWSCAN_BIN="$clawscan_bin" "$gate_runner" \
  "$repo_root/testdata/fixtures/probe-skill" \
  "$output_root/rejected-probe" || probe_status=$?
[[ "$probe_status" -eq 42 ]] || {
  echo "owned hostile probe did not fail closed with exit 42" >&2
  exit 1
}
jq -e '
  .status == "failed" and
  .stage == "security-scan" and
  .reason == "failed due to security scan" and
  (.failures | length) > 0
' "$output_root/rejected-probe/security-gate.json" >/dev/null

echo "owned fixture security-gate smoke passed"
echo "$output_root/pass-skill/security-gate.json"
echo "$output_root/pass-plugin/security-gate.json"
echo "$output_root/rejected-probe/security-gate.json"
