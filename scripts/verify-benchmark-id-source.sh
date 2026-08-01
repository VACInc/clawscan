#!/usr/bin/env bash
set -euo pipefail

: "${GITHUB_ENV:?GITHUB_ENV is required}"
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"

ids_source="${IDS_SOURCE:-}"
ids_sha256="${IDS_SHA256:-}"

if [[ -z "$ids_source" ]]; then
  echo "BENCHMARK_IDS=" >>"$GITHUB_ENV"
  exit 0
fi

verified_source="$ids_source"
case "$ids_source" in
  http://*)
    echo "remote benchmark IDs must use HTTPS" >&2
    exit 1
    ;;
  https://*)
    if ! [[ "$ids_sha256" =~ ^[0-9a-f]{64}$ ]]; then
      echo "ids_sha256 is required for remote benchmark IDs" >&2
      exit 1
    fi
    verified_source="$RUNNER_TEMP/benchmark-ids.jsonl"
    curl --fail --location --proto '=https' --tlsv1.2 \
      --output "$verified_source" "$ids_source"
    ;;
esac

if [[ -n "$ids_sha256" ]]; then
  actual_sha256="$(sha256sum "$verified_source" | awk '{ print $1 }')"
  if [[ "$actual_sha256" != "$ids_sha256" ]]; then
    echo "benchmark IDs SHA-256 mismatch: expected $ids_sha256, got $actual_sha256" >&2
    exit 1
  fi
fi

echo "BENCHMARK_IDS=$verified_source" >>"$GITHUB_ENV"
