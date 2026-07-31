#!/usr/bin/env bash
set -euo pipefail

# Fork-safe, build-only release packaging.
#
# This script produces installable archives locally. It never publishes, never
# contacts a registry, and never assumes ownership of the official @openclaw
# namespace. Publication remains an explicit, separate action.

version="${1:-dev}"
commit="$(git rev-parse --short HEAD 2>/dev/null || printf 'unknown')"
date="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
dist_dir="dist"
clawscan_package="github.com/openclaw/clawscan/cmd/clawscan"
observatory_package="github.com/openclaw/clawscan/cmd/observatory"

# ClawScan ships for every supported cross-platform target. Observatory is a
# Linux control-host tool: its runner integration is Linux only, so packaging it
# elsewhere would promise a surface that does not exist.
platforms=(
  "darwin/amd64"
  "darwin/arm64"
  "linux/amd64"
  "linux/arm64"
  "windows/amd64"
)
observatory_platforms=(
  "linux/amd64"
  "linux/arm64"
)

contains() {
  local needle="$1"
  shift
  local candidate
  for candidate in "$@"; do
    if [[ "$candidate" == "$needle" ]]; then
      return 0
    fi
  done
  return 1
}

missing=()
for tool in go tar zip shasum; do
  command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
done
if [[ ${#missing[@]} -gt 0 ]]; then
  printf 'Missing required packaging tools: %s\n' "${missing[*]}" >&2
  exit 1
fi

rm -rf "$dist_dir"
mkdir -p "$dist_dir"

ldflags="-s -w -X main.version=${version} -X main.commit=${commit} -X main.date=${date}"

for platform in "${platforms[@]}"; do
  os="${platform%/*}"
  arch="${platform#*/}"
  name="clawscan_${version}_${os}_${arch}"
  workdir="${dist_dir}/${name}"
  binary="clawscan"

  if [[ "$os" == "windows" ]]; then
    binary="clawscan.exe"
  fi

  mkdir -p "$workdir"
  GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 go build -trimpath -ldflags "$ldflags" -o "${workdir}/${binary}" "$clawscan_package"
  cp README.md "${workdir}/README.md"
  cp LICENSE "${workdir}/LICENSE"

  if contains "$platform" "${observatory_platforms[@]}"; then
    GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 go build -trimpath -ldflags "$ldflags" -o "${workdir}/observatory" "$observatory_package"
    mkdir -p "${workdir}/docs"
    cp docs/observatory.md "${workdir}/docs/observatory.md"
    cp docs/release-gate-ledger.md "${workdir}/docs/release-gate-ledger.md"
    cp examples/observatory.yml "${workdir}/observatory.example.yml"
    cat >"${workdir}/LIMITATIONS.md" <<'LIMITS'
# Observatory limitations

Observatory publishes observed behavior for one synthetic task in one isolated
environment. It does not prove that a target is safe.

- Evidence is observational. A grade is a separate derived projection and is
  never part of the evidence schema.
- One task exercises one path. Dormant branches, delayed triggers, and
  version-specific behavior can be missed.
- GUI and channel-plugin coverage is shallow, and tool-argument metadata can be
  incomplete. Those gaps are reported in the evidence coverage fields.
- The behavior lane requires an independently isolated remote runner. It refuses
  ClawScan Docker sandbox mode.
- Deep or repeated redirect trials are rejected by configuration on purpose.
- Live runs require an operator-approved disposable VM lifecycle. Nothing in
  this archive provisions infrastructure by itself.
LIMITS
    cat >"${workdir}/PROOF-PACKET.md" <<'PROOF'
# Proof packet

This archive does not embed a live proof packet. A published Observatory proof
packet is produced by an approved owned-fixture run and contains, at minimum:

- source and runner-template commit SHAs
- sanitized commands and configuration shape
- runner-release and runtime-image receipts
- public skill and plugin evidence, with separate grades
- pipeline summaries
- teardown and protected-resource proofs
- generated static evidence pages
- checksums and a proof index

Raw capture bundles, raw traces, raw subprocess output, credential-wrapper logs,
private endpoints, and private hostnames stay outside the packet.
PROOF
  fi

  if [[ "$os" == "windows" ]]; then
    (cd "$dist_dir" && zip -qr "${name}.zip" "$name")
  else
    (cd "$dist_dir" && tar -czf "${name}.tar.gz" "$name")
  fi
done

(cd "$dist_dir" && shasum -a 256 ./*.tar.gz ./*.zip > checksums.txt)

printf 'Built release artifacts in %s/\n' "$dist_dir"
printf 'This build published nothing. Publication is a separate explicit action.\n'
