#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

die() { echo "gated Observatory failed: $*" >&2; exit 1; }
[[ "$#" -eq 3 ]] || die "usage: run-gated-observatory.sh CONFIG TARGET NEW_OUTPUT_DIRECTORY"

config="$(realpath -- "$1")"
target="$(realpath -- "$2")"
output_root="$(realpath -m -- "$3")"
observatory_bin="${OBSERVATORY_BIN:-$repo_root/bin/observatory}"
clawscan_bin="${CLAWSCAN_BIN:-$repo_root/bin/clawscan}"
crabbox_command="${OBSERVATORY_CRABBOX_COMMAND:?set OBSERVATORY_CRABBOX_COMMAND to the audited credential wrapper}"
crabbox_config="${OBSERVATORY_CRABBOX_CONFIG:?set OBSERVATORY_CRABBOX_CONFIG to the dedicated mode-0600 config}"
proxmox_template_id="${OBSERVATORY_PROXMOX_TEMPLATE_ID:?set OBSERVATORY_PROXMOX_TEMPLATE_ID}"
proxmox_bridge="${OBSERVATORY_PROXMOX_BRIDGE:?set OBSERVATORY_PROXMOX_BRIDGE}"
proxmox_ca_file="${OBSERVATORY_PROXMOX_CA_FILE:?set OBSERVATORY_PROXMOX_CA_FILE}"
relay_listen="${OBSERVATORY_RELAY_LISTEN:?set OBSERVATORY_RELAY_LISTEN to the literal controller address and port}"
key_command="${OBSERVATORY_MINIMAX_API_KEY_COMMAND:?set OBSERVATORY_MINIMAX_API_KEY_COMMAND to an executable path}"
relay_script="${OBSERVATORY_MINIMAX_RELAY_SCRIPT:-$repo_root/infra/proxmox/minimax-secret-relay.mjs}"

[[ -r "$config" && -d "$target" ]] || die "config and target must exist"
[[ -x "$observatory_bin" && -x "$clawscan_bin" && -x "$crabbox_command" && -x "$key_command" ]] || \
  die "Observatory, ClawScan, Crabbox wrapper, and key command must be executable"
[[ -r "$crabbox_config" && -r "$proxmox_ca_file" && -r "$relay_script" ]] || \
  die "Crabbox config, Proxmox CA, and relay must be readable"
[[ "$proxmox_template_id" =~ ^[1-9][0-9]{2,8}$ ]] || die "invalid template ID"
[[ "$proxmox_bridge" =~ ^vmbr[0-9]{1,4}$ && "$proxmox_bridge" != "vmbr0" && "$proxmox_bridge" != "vmbr1" ]] || \
  die "the pipeline refuses vmbr0/vmbr1"
[[ "$relay_listen" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{4,5}$ ]] || die "relay listen must be literal IPv4:port"
[[ ! -e "$output_root" ]] || die "output directory already exists"

umask 077
mkdir "$output_root"
mkdir "$output_root/gate-stage" "$output_root/security-gate" "$output_root/empty-ca-directory"
stage="$output_root/gate-stage"
security_dir="$output_root/security-gate"
result="$output_root/result.json"

write_failure() {
  local stage_name="$1"
  local reason="$2"
  jq -n --arg stage "$stage_name" --arg reason "$reason" '{
    schemaVersion: "observatory.pipeline.v1",
    status: "failed",
    stage: $stage,
    reason: $reason
  }' > "$result"
}

"$observatory_bin" validate-config --live "$config" >/dev/null
"$observatory_bin" stage \
  --output "$stage/target" \
  --metadata "$stage/target-metadata.json" \
  "$target" >/dev/null
install -D -m 0700 "$clawscan_bin" "$stage/bin/clawscan"
install -D -m 0700 "$repo_root/infra/proxmox/run-security-gate.sh" "$stage/infra/proxmox/run-security-gate.sh"
install -D -m 0700 "$repo_root/infra/proxmox/run-security-gate-crabbox.sh" "$stage/infra/proxmox/run-security-gate-crabbox.sh"
install -D -m 0600 "$repo_root/infra/proxmox/clawscan-local-free.yml" "$stage/infra/proxmox/clawscan-local-free.yml"
install -D -m 0600 "$repo_root/infra/proxmox/evaluate-local-free-scan.jq" "$stage/infra/proxmox/evaluate-local-free-scan.jq"

mkdir "$stage/.git-empty-home"
git -C "$stage" -c core.hooksPath="$stage/.git-hooks-disabled" \
  -c core.attributesFile=/dev/null -c core.autocrlf=false init --quiet
git -C "$stage" -c core.hooksPath="$stage/.git-hooks-disabled" \
  -c core.attributesFile=/dev/null -c core.autocrlf=false add --all --force
HOME="$stage/.git-empty-home" XDG_CONFIG_HOME="$stage/.git-empty-home" \
  GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0 \
  git -C "$stage" -c core.hooksPath="$stage/.git-hooks-disabled" \
    -c core.attributesFile=/dev/null -c commit.gpgSign=false \
    -c user.name="ClawHub Observatory" -c user.email=observatory@localhost \
    commit --quiet -m "stage security gate"

gate_run_status=0
(
  cd "$stage"
  CRABBOX_CONFIG="$crabbox_config" \
  CRABBOX_PROXMOX_INSECURE_SKIP_TLS_VERIFY=0 \
  CRABBOX_PROXMOX_INSECURE_TLS=0 \
  SSL_CERT_FILE="$proxmox_ca_file" SSL_CERT_DIR="$output_root/empty-ca-directory" \
  "$crabbox_command" run \
    --provider proxmox --target linux \
    --proxmox-template-id "$proxmox_template_id" \
    --proxmox-bridge "$proxmox_bridge" \
    --proxmox-full-clone=true \
    --stop-after always --ttl 1800s \
    --label "observatory security gate" \
    --script infra/proxmox/run-security-gate-crabbox.sh \
    --download ".security-gate/free-scan.json=$security_dir/free-scan.json" \
    --download ".security-gate/security-gate.json=$security_dir/runner-security-gate.json" \
    --download ".security-gate/runner-exit.json=$security_dir/runner-exit.json" \
    --download "/etc/observatory-runner-release.json=$security_dir/runner-release.json"
) > "$security_dir/crabbox.stdout" 2> "$security_dir/crabbox.stderr" || gate_run_status=$?

if [[ "$gate_run_status" -ne 0 || ! -s "$security_dir/free-scan.json" || ! -s "$security_dir/runner-exit.json" ]]; then
  write_failure "security-scan" "failed due to security scan"
  echo "failed due to security scan"
  echo "$result"
  exit 42
fi

host_gate_status=0
jq -f "$repo_root/infra/proxmox/evaluate-local-free-scan.jq" \
  "$security_dir/free-scan.json" > "$security_dir/security-gate.json" || host_gate_status=$?
runner_gate_exit="$(jq -er '.gateExit | numbers' "$security_dir/runner-exit.json")" || runner_gate_exit=255
if [[ "$host_gate_status" -ne 0 || "$runner_gate_exit" -ne 0 ]] || \
   [[ "$(jq -r '.status // "failed"' "$security_dir/security-gate.json" 2>/dev/null)" != "passed" ]]; then
  write_failure "security-scan" "failed due to security scan"
  echo "failed due to security scan"
  echo "$result"
  exit 42
fi

# The model credential is requested only after the controller has independently
# accepted the free/static evidence. It is inherited by only the bounded relay.
api_key="$($key_command)"
[[ -n "$api_key" && "$api_key" != *$'\n'* && "$api_key" != *$'\r'* ]] || die "MiniMax key command returned invalid output"
relay_receipt="$output_root/minimax-relay-receipt.json"
relay_done="$output_root/minimax-relay.done"
relay_ready="$relay_receipt.ready"
OBSERVATORY_RELAY_LISTEN="$relay_listen" \
OBSERVATORY_MINIMAX_API_KEY="$api_key" \
OBSERVATORY_RELAY_MODEL="MiniMax-M3" \
OBSERVATORY_RELAY_MAX_REQUESTS=16 \
OBSERVATORY_RELAY_RECEIPT="$relay_receipt" \
OBSERVATORY_RELAY_DONE_FILE="$relay_done" \
node "$relay_script" > "$output_root/minimax-relay.stdout" 2> "$output_root/minimax-relay.stderr" &
relay_pid=$!
printf '%s\n' "$relay_pid" > "$output_root/minimax-relay.pid"
printf '%s\n' "node $relay_script (credential inherited; value not recorded)" > "$output_root/minimax-relay.command"
unset api_key
[[ -r "/proc/$relay_pid/stat" ]] || die "MiniMax relay exited during startup"

for _ in $(seq 1 100); do
  [[ -s "$relay_ready" ]] && break
  [[ -r "/proc/$relay_pid/stat" ]] || die "MiniMax relay exited before readiness"
  sleep 0.1
done
[[ -s "$relay_ready" ]] || die "MiniMax relay readiness timed out"

behavior_status=0
"$observatory_bin" scan --config "$config" \
  --output "$output_root/behavior-evidence.json" "$stage/target" \
  > "$output_root/observatory.stdout" 2> "$output_root/observatory.stderr" || behavior_status=$?

# This create-only marker asks the relay to close after in-flight requests. No
# signal or process kill is used; the relay writes its bounded receipt and exits.
( set -o noclobber; printf 'complete\n' > "$relay_done" )
relay_status=0
wait "$relay_pid" || relay_status=$?

if [[ "$behavior_status" -ne 0 || "$relay_status" -ne 0 || ! -s "$output_root/behavior-evidence.json" || ! -s "$relay_receipt" ]]; then
  write_failure "behavior" "behavior capture failed"
  echo "$result"
  exit 1
fi

jq -n \
  --slurpfile securityGate "$security_dir/security-gate.json" \
  --slurpfile relay "$relay_receipt" \
  --arg evidence "$output_root/behavior-evidence.json" '{
    schemaVersion: "observatory.pipeline.v1",
    status: "passed",
    stage: "completed",
    reason: "security scan passed and behavior capture completed",
    securityGate: $securityGate[0],
    modelRelay: $relay[0],
    behaviorEvidence: $evidence
  }' > "$result"
echo "$result"
