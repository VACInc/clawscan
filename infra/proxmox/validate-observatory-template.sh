#!/usr/bin/env bash
set -euo pipefail

fail() { echo "runner validation failed: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "missing command $1"; }

[[ "${EUID}" -eq 0 ]] || fail "run as root"

for command in \
  ctr docker findmnt jq mount mountpoint nft node openclaw passwd pgrep runuser sha256sum \
  skopeo stat strace sudo systemctl systemd-run tar
do
  need "$command"
done

lock_file=/opt/observatory-template/template.lock
[[ -r "$lock_file" ]] || fail "missing template lock"
# shellcheck disable=SC1090
source "$lock_file"
[[ -r /etc/observatory-runner-release.json ]] || fail "missing release receipt"
receipt=/etc/observatory-runner-release.json
expected_lock_sha256="$(sha256sum "$lock_file" | awk '{print $1}')"
expected_openclaw_lock_sha256="$(sha256sum /opt/observatory-runtime/openclaw/package-lock.json | awk '{print $1}')"
expected_dpkg_manifest_sha256="$(sha256sum /opt/observatory-template/dpkg.manifest | awk '{print $1}')"
jq -e \
  --argjson schema "$OBSERVATORY_RUNNER_SCHEMA" \
  --arg lock "$expected_lock_sha256" \
  --arg ubuntuUrl "$UBUNTU_IMAGE_URL" \
  --arg ubuntuSha "$UBUNTU_IMAGE_SHA256" \
  --arg node "$NODE_VERSION" \
  --arg openclaw "$OPENCLAW_VERSION" \
  --arg openclawIntegrity "$OPENCLAW_DIST_INTEGRITY" \
  --arg openclawLock "$expected_openclaw_lock_sha256" \
  --arg dpkgManifest "$expected_dpkg_manifest_sha256" \
  --arg indexImage "$CLAWSCAN_RUNTIME_INDEX_IMAGE" \
  --arg indexDigest "$CLAWSCAN_RUNTIME_INDEX_DIGEST" \
  --arg runtimeImage "$CLAWSCAN_RUNTIME_IMAGE" \
  --arg runtimeDigest "$CLAWSCAN_RUNTIME_AMD64_DIGEST" \
  --arg localImage "$CLAWSCAN_RUNTIME_LOCAL_IMAGE" \
  --arg ociTag "$CLAWSCAN_RUNTIME_OCI_TAG" \
  --arg skillspector "$SKILLSPECTOR_REF" \
  --arg cisco "$CISCO_AI_SKILL_SCANNER_VERSION" \
  --arg agentverus "$AGENTVERUS_SCANNER_VERSION" '
  .schemaVersion == $schema and
  .lockSha256 == $lock and
  .ubuntuImageUrl == $ubuntuUrl and
  .ubuntuImageSha256 == $ubuntuSha and
  .nodeVersion == $node and
  .openClawVersion == $openclaw and
  .openClawDistIntegrity == $openclawIntegrity and
  .openClawPackageLockSha256 == $openclawLock and
  .dpkgManifestSha256 == $dpkgManifest and
  .clawscanRuntimeIndexImage == $indexImage and
  .clawscanRuntimeIndexDigest == $indexDigest and
  .clawscanRuntimeImage == $runtimeImage and
  .clawscanRuntimeAmd64Digest == $runtimeDigest and
  .clawscanRuntimeLocalImage == $localImage and
  .clawscanRuntimeOciTag == $ociTag and
  (.clawscanRuntimeConfigDigest | test("^sha256:[a-f0-9]{64}$")) and
  .skillSpectorRef == $skillspector and
  .ciscoVersion == $cisco and
  .agentVerusVersion == $agentverus
' /etc/observatory-runner-release.json >/dev/null

[[ "$(id -u observatory)" -ne 0 ]] || fail "observatory is root"
[[ "$(id -gn observatory)" == "observatory" ]] || fail "observatory primary group mismatch"
[[ "$(getent passwd observatory | cut -d: -f7)" == "/usr/sbin/nologin" ]] || fail "observatory login shell is not locked"
[[ "$(passwd -S observatory | awk '{print $2}')" == "L" ]] || fail "observatory password is not locked"
read -r -a groups <<<"$(id -G observatory)"
[[ "${#groups[@]}" -eq 1 ]] || fail "observatory has supplementary groups"
if sudo -n -u observatory sudo -n true >/dev/null 2>&1; then
  fail "observatory has passwordless sudo"
fi
if pgrep -u observatory >/dev/null 2>&1; then
  fail "observatory has a preexisting process"
fi

runuser -u crabbox -- sudo -n true >/dev/null || fail "control user lacks passwordless sudo"
id -nG crabbox | tr ' ' '\n' | grep -Fx docker >/dev/null || fail "control user cannot use Docker"
[[ "$(node --version)" == "v${NODE_VERSION}" ]] || fail "Node version mismatch"
runuser -u observatory -- node -e 'require("node:sqlite"); if (Number(process.versions.node.split(".")[0]) < 24) process.exit(1)'
runuser -u observatory -- openclaw --version | grep -F "$OPENCLAW_VERSION" >/dev/null || fail "OpenClaw version mismatch"
[[ "$(stat -fc %T /sys/fs/cgroup)" == "cgroup2fs" ]] || fail "cgroup v2 is required"
systemctl is-enabled qemu-guest-agent >/dev/null
systemctl is-active qemu-guest-agent >/dev/null
systemctl is-enabled docker >/dev/null
systemctl is-enabled ssh >/dev/null
systemctl is-active ssh >/dev/null
systemctl is-active observatory-runtime-image-load.service >/dev/null
test "$(stat -c '%a:%U:%G' /etc/sudoers.d/90-crabbox)" = "440:root:root" || fail "unsafe sudoers ownership/mode"
test "$(stat -c '%a:%U:%G' /opt/observatory-template/clawscan-runtime-amd64.oci.tar)" = "400:root:root" || fail "unsafe runtime archive ownership/mode"

runtime_archive=/opt/observatory-template/clawscan-runtime-amd64.oci.tar
probe_root="$(mktemp -d /run/observatory-template-check.XXXXXXXXXX)"
runtime_manifest="$probe_root/runtime-manifest.json"
cleanup() {
  if mountpoint -q "$probe_root/mnt"; then
    umount "$probe_root/mnt"
  fi
  rm -rf "$probe_root"
}
trap cleanup EXIT

skopeo inspect --raw "oci-archive:${runtime_archive}:${CLAWSCAN_RUNTIME_OCI_TAG}" > "$runtime_manifest"
[[ "$(skopeo manifest-digest "$runtime_manifest")" == "$CLAWSCAN_RUNTIME_AMD64_DIGEST" ]] || fail "runtime archive manifest digest mismatch"
runtime_config_digest="$(jq -er .config.digest "$runtime_manifest")"
[[ "$runtime_config_digest" == "$(jq -er .clawscanRuntimeConfigDigest "$receipt")" ]] || fail "runtime archive config digest mismatch"
[[ "$(ctr --namespace moby images list | awk -v ref="$CLAWSCAN_RUNTIME_LOCAL_IMAGE" '$1 == ref { print $3; exit }')" == "$CLAWSCAN_RUNTIME_AMD64_DIGEST" ]] || fail "containerd runtime image digest mismatch"
# The exact tag-to-manifest binding is verified through containerd above; this
# verifies that the Docker daemon can resolve the same pinned local tag.
docker image inspect "$CLAWSCAN_RUNTIME_LOCAL_IMAGE" >/dev/null || fail "loaded runtime image is unavailable through Docker"

chmod 0711 "$probe_root"
install -d -m 0700 -o observatory -g observatory "$probe_root/mnt" "$probe_root/tmp" "$probe_root/var-tmp"
mount -t tmpfs -o "size=1048576,nosuid,nodev,mode=0700,uid=$(id -u observatory),gid=$(id -g observatory)" observatory-template-check "$probe_root/mnt"
[[ "$(findmnt -n -o FSTYPE --target "$probe_root/mnt")" == "tmpfs" ]] || fail "bounded tmpfs mount failed"
runuser -u observatory -- strace -qq -o "$probe_root/mnt/strace.log" /usr/bin/true

agent_uid="$(id -u observatory)"
cat > "$probe_root/firewall.nft" <<EOF
table inet observatory_template_check {
  chain output {
    type filter hook output priority filter; policy accept;
    meta skuid $agent_uid ip daddr != 127.0.0.1 drop
  }
}
EOF
nft --check --file "$probe_root/firewall.nft"

cat > "$probe_root/tmp/hardening-probe.mjs" <<'EOF'
import fs from "node:fs";
import net from "node:net";

const mustFail = (label, fn) => {
  try {
    fn();
  } catch {
    return;
  }
  throw new Error(`${label} unexpectedly succeeded`);
};

mustFail("protected-system write", () => fs.writeFileSync("/etc/observatory-template-forbidden", "x"));
mustFail("inaccessible template read", () => fs.readFileSync("/opt/observatory-template/template.lock"));
fs.writeFileSync("/tmp/observatory-template-write-ok", "ok", { mode: 0o600 });

await new Promise((resolve, reject) => {
  const server = net.createServer();
  server.unref();
  const timer = setTimeout(() => reject(new Error("socket bind denial timed out")), 1000);
  server.once("error", (error) => {
    clearTimeout(timer);
    if (error.code === "EACCES" || error.code === "EPERM") resolve();
    else reject(error);
  });
  server.listen({ host: "127.0.0.1", port: 0 }, () => {
    clearTimeout(timer);
    server.close();
    reject(new Error("socket bind unexpectedly succeeded"));
  });
});

await new Promise((resolve, reject) => {
  const socket = net.connect({ host: "127.0.0.2", port: 9 });
  socket.unref();
  const timer = setTimeout(() => {
    socket.destroy();
    // systemd's IPAddressDeny= filter may silently drop the packet instead of
    // returning EPERM. A bounded timeout still proves the forbidden endpoint
    // was unreachable; only a completed connection is a failure.
    resolve();
  }, 1000);
  socket.once("error", (error) => {
    clearTimeout(timer);
    socket.destroy();
    if (error.code === "EACCES" || error.code === "EPERM") resolve();
    else reject(error);
  });
  socket.once("connect", () => {
    clearTimeout(timer);
    socket.destroy();
    reject(new Error("denied network connection unexpectedly succeeded"));
  });
});
EOF
chown observatory:observatory "$probe_root/tmp/hardening-probe.mjs"
chmod 0500 "$probe_root/tmp/hardening-probe.mjs"

tmp_unit="observatory-template-check-$$"
systemd-run --quiet --wait --collect --pipe --unit="$tmp_unit" \
  --property=User=observatory \
  --property=Group=observatory \
  --property=CapabilityBoundingSet= \
  --property=AmbientCapabilities= \
  --property=NoNewPrivileges=yes \
  --property=PrivateDevices=yes \
  --property=PrivateIPC=yes \
  --property=PrivateMounts=yes \
  --property="BindPaths=$probe_root/tmp:/tmp $probe_root/var-tmp:/var/tmp" \
  --property=ProtectClock=yes \
  --property=ProtectControlGroups=yes \
  --property=ProtectHome=tmpfs \
  --property=ProtectHostname=yes \
  --property=ProtectKernelLogs=yes \
  --property=ProtectKernelModules=yes \
  --property=ProtectKernelTunables=yes \
  --property=ProtectProc=invisible \
  --property=PrivateNetwork=yes \
  --property=ProtectSystem=strict \
  --property=ProcSubset=pid \
  --property=RestrictAddressFamilies=AF_INET \
  --property=RestrictNamespaces=yes \
  --property=RestrictRealtime=yes \
  --property=RestrictSUIDSGID=yes \
  --property=LockPersonality=yes \
  --property=MemorySwapMax=0 \
  --property=MemoryMax=134217728 \
  --property=CPUQuota=25% \
  --property=TasksMax=16 \
  --property=LimitNOFILE=64 \
  --property=LimitFSIZE=1048576 \
  --property=RuntimeMaxSec=15s \
  --property=TimeoutStopSec=2s \
  --property=KillMode=control-group \
  --property=SendSIGKILL=yes \
  --property=IPAddressDeny=any \
  --property=IPAddressAllow=127.0.0.1 \
  --property=SocketBindDeny=any \
  --property="ReadOnlyPaths=$probe_root/mnt" \
  --property="ReadWritePaths=$probe_root/tmp $probe_root/var-tmp" \
  --property="InaccessiblePaths=/opt/observatory-template" \
  --property="WorkingDirectory=$probe_root/tmp" \
  --property=SystemCallArchitectures=native \
  --property="SystemCallFilter=~bind listen accept accept4 io_uring_setup io_uring_register io_uring_enter" \
  --property=SystemCallErrorNumber=EPERM \
  --property=UMask=0077 \
  /usr/bin/strace -qq -o /tmp/hardening-probe.strace \
    /usr/local/bin/node /tmp/hardening-probe.mjs

printf 'runner validation passed\n'
jq -c . /etc/observatory-runner-release.json
