#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
target="${1:?usage: run-security-gate.sh TARGET OUTPUT_DIRECTORY}"
output_root="${2:?usage: run-security-gate.sh TARGET OUTPUT_DIRECTORY}"
clawscan_bin="${CLAWSCAN_BIN:-$repo_root/bin/clawscan}"
profile="$repo_root/infra/proxmox/clawscan-local-free.yml"
policy="$repo_root/infra/proxmox/evaluate-local-free-scan.jq"
receipt="${OBSERVATORY_RUNNER_RECEIPT:-/etc/observatory-runner-release.json}"

[[ -x "$clawscan_bin" ]] || { echo "security gate failed: missing ClawScan binary" >&2; exit 2; }
[[ -r "$profile" && -r "$policy" && -r "$receipt" ]] || {
  echo "security gate failed: runner assets are incomplete" >&2
  exit 2
}
mkdir -p "$output_root"
artifact="$output_root/free-scan.json"
gate="$output_root/security-gate.json"
runtime_image="$(jq -er .clawscanRuntimeLocalImage "$receipt")"

# The free lane stays deterministic and cannot inherit optional provider keys.
unset \
  AI_DEFENSE_API_KEY AI_DEFENSE_API_URL ANTHROPIC_API_KEY \
  ANTHROPIC_PROXY_API_KEY ANTHROPIC_PROXY_API_VERSION \
  ANTHROPIC_PROXY_ENDPOINT_URL AWS_PROFILE AWS_REGION \
  GOOGLE_APPLICATION_CREDENTIALS NVIDIA_INFERENCE_KEY OPENAI_API_KEY \
  OPENAI_BASE_URL CLAWSCAN_SKILLSPECTOR_LLM SKILLSPECTOR_LOG_LEVEL \
  SKILLSPECTOR_MODEL SKILLSPECTOR_MODEL_REGISTRY SKILLSPECTOR_PROVIDER \
  SKILLSPECTOR_SSL_VERIFY SKILL_SCANNER_LLM_API_KEY \
  SKILL_SCANNER_LLM_API_VERSION SKILL_SCANNER_LLM_BASE_URL \
  SKILL_SCANNER_LLM_FORCE_JSON_OBJECT SKILL_SCANNER_LLM_MODEL \
  SKILL_SCANNER_LLM_PROVIDER SKILL_SCANNER_LLM_USER \
  SKILL_SCANNER_META_LLM_API_KEY SKILL_SCANNER_META_LLM_API_VERSION \
  SKILL_SCANNER_META_LLM_BASE_URL SKILL_SCANNER_META_LLM_MODEL \
  VIRUSTOTAL_API_KEY

scan_status=0
"$clawscan_bin" "$target" \
  --config "$profile" --profile local-free \
  --sandbox docker --sandbox-image "$runtime_image" \
  --output "$artifact" || scan_status=$?

if [[ ! -s "$artifact" ]]; then
  jq -n --argjson scanExit "$scan_status" '{
    schemaVersion: "observatory.security-gate.v1",
    status: "failed",
    stage: "security-scan",
    reason: "failed due to security scan",
    failures: ["free/static security scan did not produce an artifact"],
    scanExit: $scanExit
  }' > "$gate"
  echo "failed due to security scan"
  echo "$gate"
  exit 42
fi

jq -f "$policy" "$artifact" > "$gate"
if [[ "$scan_status" -ne 0 ]]; then
  jq --argjson scanExit "$scan_status" \
    '.status="failed" | .reason="failed due to security scan" |
     .failures += ["ClawScan exited nonzero"] | .scanExit=$scanExit' \
    "$gate" > "$gate.nonzero"
  mv "$gate.nonzero" "$gate"
fi

if [[ "$(jq -r .status "$gate")" != "passed" ]]; then
  echo "failed due to security scan"
  echo "$gate"
  exit 42
fi

echo "free/static security scan passed"
echo "$gate"
