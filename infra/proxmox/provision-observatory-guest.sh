#!/usr/bin/env bash
set -euo pipefail

lock_file="${1:-/opt/observatory-template/template.lock}"
[[ "${EUID}" -eq 0 ]] || { echo "run as root" >&2; exit 2; }
[[ -r "$lock_file" ]] || { echo "missing template lock: $lock_file" >&2; exit 2; }

# The lock is repository-owned constants only.
# shellcheck disable=SC1090
source "$lock_file"

require_lock() {
  local name="$1"
  [[ -n "${!name:-}" ]] || { echo "missing lock value: $name" >&2; exit 2; }
}

for name in \
  OBSERVATORY_RUNNER_SCHEMA NODE_VERSION NODE_LINUX_X64_SHA256 \
  OPENCLAW_VERSION OPENCLAW_DIST_INTEGRITY \
  CLAWSCAN_RUNTIME_INDEX_IMAGE CLAWSCAN_RUNTIME_INDEX_DIGEST \
  CLAWSCAN_RUNTIME_IMAGE CLAWSCAN_RUNTIME_AMD64_DIGEST \
  CLAWSCAN_RUNTIME_LOCAL_IMAGE CLAWSCAN_RUNTIME_OCI_TAG \
  SKILLSPECTOR_REF CISCO_AI_SKILL_SCANNER_VERSION AGENTVERUS_SCANNER_VERSION
do
  require_lock "$name"
done

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  ca-certificates curl docker.io git jq nftables openssh-server procps \
  qemu-guest-agent rsync skopeo strace sudo systemd tar util-linux xz-utils

install -d -m 0755 /opt/observatory-template /opt/observatory-runtime

if ! getent group crabbox >/dev/null; then
  groupadd crabbox
fi
if ! id crabbox >/dev/null 2>&1; then
  useradd --create-home --gid crabbox --shell /bin/bash crabbox
fi
install -d -m 0750 -o crabbox -g crabbox /work/crabbox
cat > /etc/sudoers.d/90-crabbox <<'EOF'
crabbox ALL=(ALL:ALL) NOPASSWD: ALL
EOF
chown root:root /etc/sudoers.d/90-crabbox
chmod 0440 /etc/sudoers.d/90-crabbox
visudo -cf /etc/sudoers.d/90-crabbox >/dev/null

if ! getent group observatory >/dev/null; then
  groupadd --system observatory
fi
if ! id observatory >/dev/null 2>&1; then
  useradd --system --create-home --gid observatory --shell /usr/sbin/nologin observatory
fi
usermod --lock --shell /usr/sbin/nologin observatory
[[ "$(id -gn observatory)" == "observatory" ]] || { echo "observatory primary group is not dedicated" >&2; exit 2; }
read -r -a observatory_groups <<<"$(id -G observatory)"
[[ "${#observatory_groups[@]}" -eq 1 ]] || { echo "observatory must not have supplementary groups" >&2; exit 2; }
if runuser -u observatory -- sudo -n true >/dev/null 2>&1; then
  echo "observatory must not have passwordless sudo" >&2
  exit 2
fi

node_archive="node-v${NODE_VERSION}-linux-x64.tar.xz"
node_url="https://nodejs.org/dist/v${NODE_VERSION}/${node_archive}"
node_tmp="$(mktemp --tmpdir observatory-node.XXXXXXXXXX.tar.xz)"
curl -fL --retry 3 --output "$node_tmp" "$node_url"
printf '%s  %s\n' "$NODE_LINUX_X64_SHA256" "$node_tmp" | sha256sum -c -
tar -xJf "$node_tmp" -C /opt
rm -f "$node_tmp"
node_root="/opt/node-v${NODE_VERSION}-linux-x64"
for binary in node npm npx corepack; do
  ln -sfn "$node_root/bin/$binary" "/usr/local/bin/$binary"
done
node --version | grep -Fx "v${NODE_VERSION}"
node -e 'require("node:sqlite"); if (Number(process.versions.node.split(".")[0]) < 24) process.exit(1)'

install -d -m 0755 /opt/observatory-runtime/openclaw
npm install \
  --prefix /opt/observatory-runtime/openclaw \
  --omit=dev --no-audit --no-fund --save-exact \
  "openclaw@${OPENCLAW_VERSION}"
jq -e --arg integrity "$OPENCLAW_DIST_INTEGRITY" \
  '.packages["node_modules/openclaw"].integrity == $integrity' \
  /opt/observatory-runtime/openclaw/package-lock.json >/dev/null
ln -sfn /opt/observatory-runtime/openclaw/node_modules/.bin/openclaw /usr/local/bin/openclaw
openclaw --version | grep -F "$OPENCLAW_VERSION"

systemctl enable docker qemu-guest-agent ssh
if ! getent group docker >/dev/null; then
  groupadd --system docker
fi
usermod -a -G docker crabbox

runtime_archive=/opt/observatory-template/clawscan-runtime-amd64.oci.tar
index_manifest="$(mktemp --tmpdir observatory-runtime-index.XXXXXXXXXX.json)"
skopeo inspect --raw "docker://${CLAWSCAN_RUNTIME_INDEX_IMAGE}" > "$index_manifest"
index_digest="$(skopeo manifest-digest "$index_manifest")"
[[ "$index_digest" == "$CLAWSCAN_RUNTIME_INDEX_DIGEST" ]] || {
  echo "ClawScan runtime index digest mismatch" >&2
  exit 2
}
jq -e --arg digest "$CLAWSCAN_RUNTIME_AMD64_DIGEST" '
  any(.manifests[];
    .digest == $digest and
    .platform.os == "linux" and
    .platform.architecture == "amd64")
' "$index_manifest" >/dev/null || {
  echo "pinned ClawScan runtime amd64 child is absent from the pinned index" >&2
  exit 2
}
rm -f "$index_manifest"

skopeo copy --preserve-digests \
  --override-os linux --override-arch amd64 \
  "docker://${CLAWSCAN_RUNTIME_IMAGE}" \
  "oci-archive:${runtime_archive}:${CLAWSCAN_RUNTIME_OCI_TAG}"
runtime_manifest="$(mktemp --tmpdir observatory-runtime-manifest.XXXXXXXXXX.json)"
skopeo inspect --raw "oci-archive:${runtime_archive}:${CLAWSCAN_RUNTIME_OCI_TAG}" > "$runtime_manifest"
runtime_digest="$(skopeo manifest-digest "$runtime_manifest")"
[[ "$runtime_digest" == "$CLAWSCAN_RUNTIME_AMD64_DIGEST" ]] || {
  echo "ClawScan runtime OCI archive digest mismatch" >&2
  exit 2
}
runtime_config_digest="$(jq -er '.config.digest | select(test("^sha256:[a-f0-9]{64}$"))' "$runtime_manifest")"
rm -f "$runtime_manifest"
chmod 0400 "$runtime_archive"

cat > /usr/local/sbin/observatory-load-runtime-image <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
receipt=/etc/observatory-runner-release.json
archive=/opt/observatory-template/clawscan-runtime-amd64.oci.tar
image="$(jq -r .clawscanRuntimeLocalImage "$receipt")"
digest="$(jq -r .clawscanRuntimeAmd64Digest "$receipt")"
tag="$(jq -r .clawscanRuntimeOciTag "$receipt")"
expected_config="$(jq -r .clawscanRuntimeConfigDigest "$receipt")"
verify_dir="$(mktemp -d --tmpdir observatory-runtime-load.XXXXXXXXXX)"
trap 'rm -rf "$verify_dir"' EXIT
manifest="$verify_dir/manifest.json"
loaded_config="$verify_dir/loaded-config.json"
skopeo inspect --raw "oci-archive:${archive}:${tag}" > "$manifest"
resolved="$(skopeo manifest-digest "$manifest")"
[[ "$resolved" == "$digest" ]]
[[ "$(jq -r .config.digest "$manifest")" == "$expected_config" ]]
skopeo copy "oci-archive:${archive}:${tag}" "docker-daemon:${image}" >/dev/null
skopeo inspect --config --raw "docker-daemon:${image}" > "$loaded_config"
[[ "sha256:$(sha256sum "$loaded_config" | awk '{print $1}')" == "$expected_config" ]]
docker image inspect "$image" >/dev/null
EOF
chmod 0555 /usr/local/sbin/observatory-load-runtime-image

cat > /etc/systemd/system/observatory-runtime-image-load.service <<'EOF'
[Unit]
Description=Load the pinned ClawScan runtime image
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/observatory-load-runtime-image
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
systemctl enable observatory-runtime-image-load.service

lock_sha256="$(sha256sum "$lock_file" | awk '{print $1}')"
openclaw_lock_sha256="$(sha256sum /opt/observatory-runtime/openclaw/package-lock.json | awk '{print $1}')"
dpkg-query -W -f='${binary:Package}\t${Version}\n' | LC_ALL=C sort > /opt/observatory-template/dpkg.manifest
chmod 0444 /opt/observatory-template/dpkg.manifest
dpkg_manifest_sha256="$(sha256sum /opt/observatory-template/dpkg.manifest | awk '{print $1}')"
jq -n \
  --argjson schemaVersion "$OBSERVATORY_RUNNER_SCHEMA" \
  --arg lockSha256 "$lock_sha256" \
  --arg ubuntuImageUrl "$UBUNTU_IMAGE_URL" \
  --arg ubuntuImageSha256 "$UBUNTU_IMAGE_SHA256" \
  --arg nodeVersion "$NODE_VERSION" \
  --arg openClawVersion "$OPENCLAW_VERSION" \
  --arg openClawDistIntegrity "$OPENCLAW_DIST_INTEGRITY" \
  --arg openClawPackageLockSha256 "$openclaw_lock_sha256" \
  --arg dpkgManifestSha256 "$dpkg_manifest_sha256" \
  --arg clawscanRuntimeIndexImage "$CLAWSCAN_RUNTIME_INDEX_IMAGE" \
  --arg clawscanRuntimeIndexDigest "$CLAWSCAN_RUNTIME_INDEX_DIGEST" \
  --arg clawscanRuntimeImage "$CLAWSCAN_RUNTIME_IMAGE" \
  --arg clawscanRuntimeAmd64Digest "$CLAWSCAN_RUNTIME_AMD64_DIGEST" \
  --arg clawscanRuntimeLocalImage "$CLAWSCAN_RUNTIME_LOCAL_IMAGE" \
  --arg clawscanRuntimeOciTag "$CLAWSCAN_RUNTIME_OCI_TAG" \
  --arg clawscanRuntimeConfigDigest "$runtime_config_digest" \
  --arg skillSpectorRef "$SKILLSPECTOR_REF" \
  --arg ciscoVersion "$CISCO_AI_SKILL_SCANNER_VERSION" \
  --arg agentVerusVersion "$AGENTVERUS_SCANNER_VERSION" \
  '{
    schemaVersion: $schemaVersion,
    lockSha256: $lockSha256,
    ubuntuImageUrl: $ubuntuImageUrl,
    ubuntuImageSha256: $ubuntuImageSha256,
    nodeVersion: $nodeVersion,
    openClawVersion: $openClawVersion,
    openClawDistIntegrity: $openClawDistIntegrity,
    openClawPackageLockSha256: $openClawPackageLockSha256,
    dpkgManifestSha256: $dpkgManifestSha256,
    clawscanRuntimeIndexImage: $clawscanRuntimeIndexImage,
    clawscanRuntimeIndexDigest: $clawscanRuntimeIndexDigest,
    clawscanRuntimeImage: $clawscanRuntimeImage,
    clawscanRuntimeAmd64Digest: $clawscanRuntimeAmd64Digest,
    clawscanRuntimeLocalImage: $clawscanRuntimeLocalImage,
    clawscanRuntimeOciTag: $clawscanRuntimeOciTag,
    clawscanRuntimeConfigDigest: $clawscanRuntimeConfigDigest,
    skillSpectorRef: $skillSpectorRef,
    ciscoVersion: $ciscoVersion,
    agentVerusVersion: $agentVerusVersion
  }' > /etc/observatory-runner-release.json
chmod 0444 /etc/observatory-runner-release.json

echo "Observatory runner provisioning complete"
