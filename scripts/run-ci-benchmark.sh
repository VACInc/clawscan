#!/usr/bin/env bash
set -euo pipefail

mkdir -p "$(dirname "$OUTPUT_PATH")"

args=(benchmark "$BENCHMARK_ID" --output "$OUTPUT_PATH")
if [[ -n "$SPLIT" ]]; then
  args+=(--split "$SPLIT")
fi
if [[ -n "$IDS" ]]; then
  args+=(--ids "$IDS")
else
  args+=(--limit "$LIMIT" --offset "$OFFSET")
fi
if [[ -n "$PREDICTIONS_OUTPUT" ]]; then
  mkdir -p "$(dirname "$PREDICTIONS_OUTPUT")"
  args+=(--predictions-output "$PREDICTIONS_OUTPUT")
fi
if [[ -n "$CONFIG_PATH" ]]; then
  args+=(--config "$CONFIG_PATH")
fi
if [[ -n "$PROFILE" ]]; then
  args+=(--profile "$PROFILE")
else
  scanner_values="${SCANNERS:-}"
  read -r -a scanners <<<"$(printf '%s' "$scanner_values" | tr ',' ' ')"
  if [[ "${#scanners[@]}" -eq 0 ]]; then
    echo "Either profile or scanners must be set." >&2
    exit 1
  fi
  for scanner in "${scanners[@]}"; do
    args+=(--scanner "$scanner")
  done
fi

./dist/clawscan "${args[@]}"
