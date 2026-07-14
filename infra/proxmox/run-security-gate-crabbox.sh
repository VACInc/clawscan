#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
output_root="$repo_root/.security-gate"
gate_exit=0

mkdir "$output_root"
sudo /opt/observatory-template/validate-observatory-template.sh \
  > "$output_root/template-validation.txt"
CLAWSCAN_BIN="$repo_root/bin/clawscan" \
  "$repo_root/infra/proxmox/run-security-gate.sh" \
  "$repo_root/artifact" "$output_root" || gate_exit=$?

jq -n --argjson gateExit "$gate_exit" '{gateExit: $gateExit}' \
  > "$output_root/runner-exit.json"

# Crabbox downloads artifacts only after a successful command. The controller
# independently evaluates the downloaded scan and runner exit before it may
# start a model relay or behavior VM.
exit 0
