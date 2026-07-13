package observatory

const writeConfigScript = `import fs from "node:fs";
import path from "node:path";

const runtime = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const workspace = process.env.OBSERVATORY_WORKSPACE;
const configPath = process.env.OPENCLAW_CONFIG_PATH;
const home = process.env.OBSERVATORY_HOME;
const state = process.env.OPENCLAW_STATE_DIR;
const lane = process.env.OBSERVATORY_LANE;
const targetRoot = process.env.OBSERVATORY_TARGET_ROOT;
if (!workspace || !configPath || !home || !state || !lane || !targetRoot) throw new Error("missing Observatory lane paths");
const model = runtime.model;
const markers = runtime.canaries;
const skillIdPattern = /^[a-z0-9][a-z0-9-]{0,63}$/;
if (runtime.targetKind === "skill" && !skillIdPattern.test(runtime.targetId)) throw new Error("invalid staged skill identifier");
for (const id of ["workspace-identity", "workspace-memory", "cloud-credentials", "openclaw-credentials"]) {
  if (typeof markers?.[id] !== "string" || !/^OBS-CANARY-[a-f0-9]{48}$/.test(markers[id])) throw new Error("missing private canary marker");
}
const config = {
  wizard: {
    lastRunAt: new Date().toISOString(),
    lastRunVersion: "observatory",
    lastRunMode: "local",
    securityAcknowledgedAt: new Date().toISOString(),
  },
  agents: {
    defaults: {
      model: { primary: model.provider + "/" + model.id },
      sandbox: { mode: "off" },
    },
    list: [{
      id: "observatory",
      default: true,
      workspace,
      model: { primary: model.provider + "/" + model.id },
      skills: lane === "exercise" && runtime.targetKind === "skill" ? [runtime.targetId] : [],
    }],
  },
  models: {
    mode: "replace",
    providers: {
      [model.provider]: {
        baseUrl: model.baseUrl,
        apiKey: "local",
        api: model.api,
        models: [{
          id: model.id,
          name: "Observatory local model",
          reasoning: false,
          input: ["text"],
          cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
          contextWindow: model.contextWindow,
          maxTokens: model.maxTokens,
        }],
      },
    },
  },
  tools: {
    profile: "coding",
    deny: [
      "group:sessions", "cron", "gateway", "message", "skill_workshop",
      "image", "image_generate", "music_generate", "video_generate",
    ],
    elevated: { enabled: false },
    exec: { security: "full", ask: "off", timeoutSec: runtime.timeoutSeconds },
  },
};
if (runtime.targetKind === "plugin") {
  config.plugins = lane === "exercise" ? {
    enabled: true,
    allow: [runtime.targetId],
    deny: [],
    load: { paths: [targetRoot] },
    entries: {
      [runtime.targetId]: {
        enabled: true,
        hooks: { allowPromptInjection: false, allowConversationAccess: false },
      },
    },
  } : { enabled: true, allow: [], deny: [], load: { paths: [] }, entries: {} };
} else {
  config.plugins = { enabled: false };
}
fs.mkdirSync(path.join(workspace, "memory"), { recursive: true });
fs.mkdirSync(path.join(home, ".aws"), { recursive: true });
fs.mkdirSync(state, { recursive: true });
fs.writeFileSync(path.join(workspace, "SOUL.md"), "Synthetic Observatory identity\n" + markers["workspace-identity"] + "\n", { mode: 0o600 });
fs.writeFileSync(path.join(workspace, "memory", "private.md"), markers["workspace-memory"] + "\n", { mode: 0o600 });
fs.writeFileSync(path.join(home, ".aws", "credentials"), "[default]\naws_access_key_id=" + markers["cloud-credentials"] + "\nregion=us-east-1\n", { mode: 0o600 });
fs.writeFileSync(path.join(state, "credentials.json"), JSON.stringify({ marker: markers["openclaw-credentials"] }) + "\n", { mode: 0o600 });
const redirectSeeds = Array.isArray(runtime.redirectSeeds) ? runtime.redirectSeeds : [];
const redirectFilePattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
for (const seed of redirectSeeds) {
  if (!seed || typeof seed.file !== "string" || typeof seed.body !== "string" || !redirectFilePattern.test(seed.file)) throw new Error("invalid synthetic redirect seed");
  fs.writeFileSync(path.join(workspace, seed.file), seed.body, { mode: 0o600 });
}
fs.mkdirSync(path.dirname(configPath), { recursive: true });
fs.writeFileSync(configPath, JSON.stringify(config, null, 2) + "\n", { mode: 0o600 });
`

// inventoryScript snapshots a bounded, curated set of persistence surfaces within
// one lane root and emits deterministic "mode<TAB>digest<TAB>relpath" lines. The
// analyzer diffs a before/after pair to confirm residual mutations. The staged
// target directory is intentionally excluded: it is the target itself, not a
// residual persistence surface. Only file digests are recorded, never contents,
// so seeded canary values never leave the guest through the inventory.
const inventoryScript = `import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

const root = path.resolve(process.argv[2]);
const output = process.argv[3];
if (!process.argv[2] || !output) throw new Error("usage: inventory.mjs LANE_ROOT OUTPUT");

const MAX_ENTRIES = 20000;
const MAX_HASH_BYTES = 1 << 20;
const MAX_OUTPUT_BYTES = 8 << 20;
const MAX_PATH_BYTES = 4096;
const MAX_DEPTH = 64;

const roots = [
  "state",
  "home/.bashrc", "home/.bash_profile", "home/.bash_login", "home/.bash_logout",
  "home/.profile", "home/.zshrc", "home/.zprofile", "home/.zshenv", "home/.zlogin", "home/.kshrc",
  "home/.config", "home/.local", "home/.ssh", "home/.openclaw", "home/.crontab", "home/.cron", "home/bin",
  "workspace/SOUL.md", "workspace/AGENTS.md", "workspace/CLAUDE.md", "workspace/memory", "workspace/.openclaw",
];

const lines = [];
let truncated = false;
let outputBytes = 0;

function modeOf(stat) {
  return (stat.mode & 0o7777).toString(8).padStart(4, "0");
}

function absent(error) {
  return error && (error.code === "ENOENT" || error.code === "ENOTDIR");
}

function recordLine(line) {
  const bytes = Buffer.byteLength(line + "\n");
  if (outputBytes + bytes > MAX_OUTPUT_BYTES) {
    truncated = true;
    return false;
  }
  lines.push(line);
  outputBytes += bytes;
  return true;
}

function record(absolute, relative, depth) {
  // Reject control characters so a target-controlled filename cannot forge or
  // split an inventory line. An unrepresentable path makes the inventory
  // incomplete and therefore fail closed during bundle parsing.
  if (/[\u0000-\u001f]/.test(relative) || Buffer.byteLength(relative) > MAX_PATH_BYTES || depth > MAX_DEPTH) {
    truncated = true;
    return;
  }
  let stat;
  try {
    stat = fs.lstatSync(absolute);
  } catch (error) {
    if (!absent(error)) truncated = true;
    return;
  }
  if (stat.isSymbolicLink()) {
    recordLine(modeOf(stat) + "\tsymlink\t" + relative);
    return;
  }
  if (stat.isDirectory()) {
    walk(absolute, relative, depth);
    return;
  }
  if (!stat.isFile()) {
    recordLine(modeOf(stat) + "\tspecial\t" + relative);
    return;
  }
  let digest;
  if (stat.size > MAX_HASH_BYTES) {
    digest = "large:" + stat.size;
  } else {
    try {
      digest = crypto.createHash("sha256").update(fs.readFileSync(absolute)).digest("hex");
    } catch (error) {
      if (!absent(error)) truncated = true;
      return;
    }
  }
  recordLine(modeOf(stat) + "\t" + digest + "\t" + relative);
}

function walk(absolute, relative, depth) {
  if (truncated || lines.length >= MAX_ENTRIES || depth >= MAX_DEPTH) {
    truncated = true;
    return;
  }
  let entries;
  try {
    entries = fs.readdirSync(absolute, { withFileTypes: true });
  } catch (error) {
    if (!absent(error)) truncated = true;
    return;
  }
  entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  for (const entry of entries) {
    if (truncated || lines.length >= MAX_ENTRIES) {
      truncated = true;
      return;
    }
    record(path.join(absolute, entry.name), relative + "/" + entry.name, depth + 1);
  }
}

for (const rel of roots) {
  if (truncated || lines.length >= MAX_ENTRIES) {
    truncated = true;
    break;
  }
  record(path.join(root, rel), rel, 0);
}

lines.sort();
if (truncated) lines.push("# truncated");
const rendered = lines.join("\n") + "\n";
if (output === "-") process.stdout.write(rendered);
else fs.writeFileSync(output, rendered, { mode: 0o600 });
`

const applyTargetModesScript = `import fs from "node:fs";
import path from "node:path";

const manifest = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const root = path.resolve(process.argv[3]);
const modePattern = /^[0-7]{4}$/;

function entryPath(entry) {
  if (!entry || typeof entry.path !== "string" || !modePattern.test(entry.mode)) throw new Error("invalid target mode entry");
  if (entry.path === ".") return root;
  const parts = entry.path.split("/");
  if (path.posix.isAbsolute(entry.path) || parts.some((part) => part === "" || part === "." || part === "..")) throw new Error("unsafe target mode path");
  const candidate = path.resolve(root, ...parts);
  if (!candidate.startsWith(root + path.sep)) throw new Error("target mode path escaped root");
  return candidate;
}

const directories = [...manifest.directories].sort((left, right) => left.path.split("/").length - right.path.split("/").length);
for (const entry of directories) {
  const candidate = entryPath(entry);
  fs.mkdirSync(candidate, { recursive: true, mode: 0o700 });
  const stat = fs.lstatSync(candidate);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error("target directory mode entry is not a directory");
}
for (const entry of manifest.files) {
  const candidate = entryPath(entry);
  const stat = fs.lstatSync(candidate);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error("target file mode entry is not a regular file");
  fs.chmodSync(candidate, Number.parseInt(entry.mode, 8));
}
directories.reverse();
for (const entry of directories) fs.chmodSync(entryPath(entry), Number.parseInt(entry.mode, 8));
`

const remoteAgentScript = `#!/usr/bin/env bash
set -euo pipefail
umask 077

if [ "$#" -ne 5 ]; then
  printf 'usage: run-agent.sh ROOT TRACE_DIR SESSION RUNTIME_JSON PROMPT\n' >&2
  exit 64
fi

ROOT=$1
TRACE_DIR=$2
SESSION=$3
RUNTIME_JSON=$4
PROMPT=$5
OPENCLAW_COMMAND=$(node -e 'const r=require(process.argv[1]); process.stdout.write(r.openclawCommand)' "$RUNTIME_JSON")
AGENT_USER=$(node -e 'const r=require(process.argv[1]); process.stdout.write(r.agentUser)' "$RUNTIME_JSON")
CAPTURE_FILE_BLOCKS=$(node -e 'const r=require(process.argv[1]); process.stdout.write(String(r.captureFileBlocks))' "$RUNTIME_JSON")
WORKSPACE="$ROOT/workspace"
STATE="$ROOT/state"
HOME_DIR="$ROOT/home"

# Only when the controlled sink is enabled, expose a clearly synthetic sink URL to
# the contained agent through the otherwise-empty child environment. Both lanes get
# the same value; only the exercise lane has a target that can act on it. When the
# sink is disabled the variable is not introduced at all.
MOCK_EGRESS_URL=$(node -e 'const r=require(process.argv[1]); const m=r.mockEgress; process.stdout.write(m && m.enabled ? ("http://"+m.host+":"+m.port+"/observatory-mock-egress") : "")' "$RUNTIME_JSON")
MOCK_ENV=()
[ -n "$MOCK_EGRESS_URL" ] && MOCK_ENV=("OBSERVATORY_MOCK_EGRESS_URL=$MOCK_EGRESS_URL")

# Bash applies this RLIMIT_FSIZE (in 1024-byte blocks) to the trace and both
# redirected streams, and every descendant inherits it.
ulimit -f "$CAPTURE_FILE_BLOCKS"
exec strace -f -qq -s 0 -yy -e signal=none \
  -e trace=open,openat,openat2,creat,link,linkat,symlink,symlinkat,unlink,unlinkat,rename,renameat,renameat2,mkdir,mkdirat,rmdir,truncate,ftruncate,chdir,fchdir,clone,clone3,fork,vfork,unshare,execve,execveat,connect,sendto,sendmsg,sendmmsg,write,writev \
  -u "$AGENT_USER" -o "$TRACE_DIR/trace" \
  env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    ${MOCK_ENV[@]+"${MOCK_ENV[@]}"} \
    HOME="$HOME_DIR" TMPDIR=/tmp OBSERVATORY_WORKSPACE="$WORKSPACE" OPENCLAW_STATE_DIR="$STATE" OPENCLAW_CONFIG_PATH="$STATE/openclaw.json" \
    "$OPENCLAW_COMMAND" agent --local --agent observatory --session-id "$SESSION" \
      --message-file "$PROMPT" --json \
  > "$TRACE_DIR/agent.stdout" 2> "$TRACE_DIR/agent.stderr"
`

const remoteRunScript = `#!/usr/bin/env bash
set -euo pipefail
umask 077

REPO_ROOT=$(pwd)
STAGED_RUNNER="$REPO_ROOT/runner"
RUNTIME_JSON="$STAGED_RUNNER/runtime.json"
RUN_ID=$(node -e 'const r=require(process.argv[1]); process.stdout.write(r.runId)' "$RUNTIME_JSON")
TARGET_SHA256=$(node -e 'const r=require(process.argv[1]); process.stdout.write(r.targetSha256)' "$RUNTIME_JSON")
CAPTURE_CONFIG_SHA256=$(node -e 'const r=require(process.argv[1]); process.stdout.write(r.captureConfigSha256)' "$RUNTIME_JSON")
TARGET_KIND=$(node -e 'const r=require(process.argv[1]); process.stdout.write(r.targetKind)' "$RUNTIME_JSON")
TARGET_ID=$(node -e 'const r=require(process.argv[1]); process.stdout.write(r.targetId || "")' "$RUNTIME_JSON")
OPENCLAW_COMMAND=$(node -e 'const r=require(process.argv[1]); process.stdout.write(r.openclawCommand)' "$RUNTIME_JSON")
AGENT_USER=$(node -e 'const r=require(process.argv[1]); process.stdout.write(r.agentUser)' "$RUNTIME_JSON")
TIMEOUT_SECONDS=$(node -e 'const r=require(process.argv[1]); process.stdout.write(String(r.timeoutSeconds))' "$RUNTIME_JSON")
MAX_MEMORY_BYTES=$(node -e 'const r=require(process.argv[1]); process.stdout.write(String(r.maxMemoryBytes))' "$RUNTIME_JSON")
MAX_LANE_BYTES=$(node -e 'const r=require(process.argv[1]); process.stdout.write(String(r.maxLaneBytes))' "$RUNTIME_JSON")
CPU_QUOTA_PERCENT=$(node -e 'const r=require(process.argv[1]); process.stdout.write(String(r.cpuQuotaPercent))' "$RUNTIME_JSON")
MAX_TASKS=$(node -e 'const r=require(process.argv[1]); process.stdout.write(String(r.maxTasks))' "$RUNTIME_JSON")
NFT_TABLE=$(node -e 'const r=require(process.argv[1]); process.stdout.write(r.firewallTable)' "$RUNTIME_JSON")
WORK_ROOT="/run/observatory-$RUN_ID"
CONTROL="$WORK_ROOT/control"
OUT="$WORK_ROOT/output"
META="$OUT/meta"
BASELINE="$OUT/runtime/baseline"
EXERCISE="$OUT/runtime/exercise"
DOWNLOAD_OUT="$REPO_ROOT/.observatory"

as_root() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
  else
    sudo -n "$@"
  fi
}

fail() {
  printf '%s\n' "$1" >&2
  exit 20
}

command -v node >/dev/null 2>&1 || fail "node is required in the Observatory VM template"
command -v strace >/dev/null 2>&1 || fail "strace is required in the Observatory VM template"
command -v systemd-run >/dev/null 2>&1 || fail "systemd-run is required in the Observatory VM template"
command -v tar >/dev/null 2>&1 || fail "tar is required in the Observatory VM template"
command -v runuser >/dev/null 2>&1 || fail "runuser is required in the Observatory VM template"
command -v nft >/dev/null 2>&1 || fail "nftables is required in the Observatory VM template"
command -v mount >/dev/null 2>&1 || fail "mount is required in the Observatory VM template"
command -v findmnt >/dev/null 2>&1 || fail "findmnt is required in the Observatory VM template"
command -v systemctl >/dev/null 2>&1 || fail "systemctl is required in the Observatory VM template"
command -v "$OPENCLAW_COMMAND" >/dev/null 2>&1 || fail "OpenClaw is required in the Observatory VM template"
id "$AGENT_USER" >/dev/null 2>&1 || fail "dedicated Observatory agent user is missing"
as_root true >/dev/null 2>&1 || fail "passwordless root instrumentation is required"
[ "$(id -u "$AGENT_USER")" -ne 0 ] || fail "Observatory agent user must not be root"
[ "$(id -u "$AGENT_USER")" -ne "$(id -u)" ] || fail "Observatory control and agent users must differ"
[ "$(id -gn "$AGENT_USER")" = "$AGENT_USER" ] || fail "Observatory agent user must have a same-name dedicated primary group"
read -r -a agent_group_ids <<< "$(id -G "$AGENT_USER")"
[ "${#agent_group_ids[@]}" -eq 1 ] || fail "Observatory agent user must not have supplementary groups"
if as_root runuser -u "$AGENT_USER" -- sudo -n true >/dev/null 2>&1; then
  fail "Observatory agent user must not have passwordless sudo"
fi

CONTROL_UID=$(id -u)
CONTROL_GID=$(id -g)
CONTROL_USER=$(id -un)
as_root install -d -m 0711 "$WORK_ROOT"
as_root install -d -m 0711 -o "$CONTROL_UID" -g "$CONTROL_GID" "$CONTROL"
as_root install -m 0600 -o "$CONTROL_UID" -g "$CONTROL_GID" "$STAGED_RUNNER/runtime.json" "$CONTROL/runtime.json"
as_root install -m 0600 -o "$CONTROL_UID" -g "$CONTROL_GID" "$STAGED_RUNNER/firewall.nft" "$CONTROL/firewall.nft"
as_root install -m 0600 -o "$CONTROL_UID" -g "$CONTROL_GID" "$STAGED_RUNNER/prompt.txt" "$CONTROL/prompt.txt"
as_root install -m 0600 -o "$CONTROL_UID" -g "$CONTROL_GID" "$STAGED_RUNNER/write-config.mjs" "$CONTROL/write-config.mjs"
as_root install -m 0600 -o "$CONTROL_UID" -g "$CONTROL_GID" "$STAGED_RUNNER/apply-target-modes.mjs" "$CONTROL/apply-target-modes.mjs"
as_root install -m 0555 -o "$CONTROL_UID" -g "$CONTROL_GID" "$STAGED_RUNNER/inventory.mjs" "$CONTROL/inventory.mjs"
as_root install -m 0600 -o "$CONTROL_UID" -g "$CONTROL_GID" "$STAGED_RUNNER/target-modes.json" "$CONTROL/target-modes.json"
as_root install -m 0500 -o "$CONTROL_UID" -g "$CONTROL_GID" "$STAGED_RUNNER/mock-egress-sink.mjs" "$CONTROL/mock-egress-sink.mjs"
as_root install -m 0700 -o "$CONTROL_UID" -g "$CONTROL_GID" "$STAGED_RUNNER/run-agent.sh" "$CONTROL/run-agent.sh"
RUNTIME_JSON="$CONTROL/runtime.json"
MOCK_EGRESS_ENABLED=$(node -e 'const r=require(process.argv[1]); process.stdout.write(r.mockEgress && r.mockEgress.enabled ? "1" : "0")' "$RUNTIME_JSON")
MOCK_DEADLINE_SECONDS=0
MOCK_RECEIPT_MAX_BYTES=0
MOCK_SINK_PORT=0
if [ "$MOCK_EGRESS_ENABLED" = "1" ]; then
  MOCK_DEADLINE_SECONDS=$(node -e 'const r=require(process.argv[1]); process.stdout.write(String(r.mockEgress.deadlineSeconds))' "$RUNTIME_JSON")
  MOCK_RECEIPT_MAX_BYTES=$(node -e 'const r=require(process.argv[1]); process.stdout.write(String(r.mockEgress.receiptMaxBytes))' "$RUNTIME_JSON")
  MOCK_SINK_PORT=$(node -e 'const r=require(process.argv[1]); process.stdout.write(String(r.mockEgress.port))' "$RUNTIME_JSON")
fi

SSH_PEER=${SSH_CONNECTION:-}
SSH_PEER=${SSH_PEER%% *}
[ -n "$SSH_PEER" ] || fail "SSH_CONNECTION is required to pin the management firewall peer"
as_root node -e 'const fs=require("fs"),net=require("net");const [file,peer]=process.argv.slice(1);if(!net.isIPv4(peer))throw new Error("management peer must be literal IPv4");const marker="@MANAGEMENT_IPV4@",input=fs.readFileSync(file,"utf8");if(input.split(marker).length!==2)throw new Error("firewall management marker is missing or repeated");fs.writeFileSync(file,input.replace(marker,peer),{mode:0o600});' "$CONTROL/firewall.nft" "$SSH_PEER"
if [ "$MOCK_EGRESS_ENABLED" = "1" ]; then
  MOCK_AGENT_UID=$(id -u "$AGENT_USER")
  as_root node -e 'const fs=require("fs");const [file,uid]=process.argv.slice(1);if(!/^[0-9]+$/.test(uid))throw new Error("agent uid must be numeric");const marker="@AGENT_UID@",input=fs.readFileSync(file,"utf8");if(!input.includes(marker))throw new Error("firewall agent-uid marker is missing");fs.writeFileSync(file,input.split(marker).join(uid),{mode:0o600});' "$CONTROL/firewall.nft" "$MOCK_AGENT_UID"
fi
as_root nft -f "$CONTROL/firewall.nft"

as_root install -d -m 0711 "$OUT" "$OUT/runtime"
as_root chown "$(id -u):$(id -g)" "$OUT" "$OUT/runtime"
install -d -m 0700 "$META" "$OUT/baseline" "$OUT/exercise"
printf '%s\n' "$RUN_ID" > "$META/run-id"
printf '%s\n' "$TARGET_SHA256" > "$META/target-sha256"
printf '%s\n' "$CAPTURE_CONFIG_SHA256" > "$META/capture-config-sha256"
printf '%s\n' "$TARGET_KIND" > "$META/target-kind"
node -e 'const r=require(process.argv[1]);process.stdout.write(JSON.stringify(r.canaries)+"\n")' "$RUNTIME_JSON" > "$META/canaries.json"
node -e 'const r=require(process.argv[1]);process.stdout.write(JSON.stringify(r.redirects)+"\n")' "$RUNTIME_JSON" > "$META/redirects.json"
date -u +%Y-%m-%dT%H:%M:%S.%NZ > "$META/started-at"
"$OPENCLAW_COMMAND" --version 2>&1 | head -n 1 > "$META/openclaw-version"
strace --version 2>&1 | head -n 1 > "$META/strace-version"
as_root nft list table inet "$NFT_TABLE" | sha256sum | cut -d' ' -f1 > "$META/firewall-sha256"

seed_lane() {
  local lane=$1
  local root=$2
  local workspace="$root/workspace"
  local state="$root/state"
  local home="$root/home"
  local target_root="$root/target"
  as_root install -d -m 0700 "$root"
  as_root mount -t tmpfs -o "size=$MAX_LANE_BYTES,nosuid,nodev,mode=0700,uid=$(id -u "$AGENT_USER"),gid=$(id -g "$AGENT_USER")" "observatory-$RUN_ID-$lane" "$root"
  [ "$(findmnt -n -o FSTYPE --target "$root")" = "tmpfs" ] || fail "lane storage must be a bounded tmpfs"
  as_root install -d -m 0700 -o "$AGENT_USER" -g "$AGENT_USER" "$workspace" "$workspace/memory" "$state" "$home" "$home/.aws" "$root/tmp" "$root/var-tmp"
  as_root install -m 0600 -o "$AGENT_USER" -g "$AGENT_USER" "$CONTROL/prompt.txt" "$root/prompt.txt"
  if [ "$lane" = "exercise" ]; then
    if [ "$TARGET_KIND" = "skill" ]; then
      target_root="$workspace/skills/$TARGET_ID"
    elif [ "$TARGET_KIND" = "plugin" ]; then
      target_root="$root/plugin/$TARGET_ID"
    else
      fail "unsupported staged target kind"
    fi
    as_root install -d -m 0700 -o "$AGENT_USER" -g "$AGENT_USER" "$target_root"
    as_root cp -a "$REPO_ROOT/target/." "$target_root/"
  fi
  as_root env OBSERVATORY_WORKSPACE="$workspace" OBSERVATORY_HOME="$home" OBSERVATORY_LANE="$lane" OBSERVATORY_TARGET_ROOT="$target_root" \
    OPENCLAW_STATE_DIR="$state" OPENCLAW_CONFIG_PATH="$state/openclaw.json" \
    node "$CONTROL/write-config.mjs" "$RUNTIME_JSON"
  as_root chown -R "$AGENT_USER:$AGENT_USER" "$root"
  if [ "$lane" = "exercise" ]; then
    as_root node "$CONTROL/apply-target-modes.mjs" "$CONTROL/target-modes.json" "$target_root"
    as_root chown -R "$AGENT_USER:$AGENT_USER" "$target_root"
  fi
}

seed_lane baseline "$BASELINE"
seed_lane exercise "$EXERCISE"
as_root runuser -u "$AGENT_USER" -- test -r "$BASELINE/state/openclaw.json" || fail "agent user cannot traverse the baseline lane"
as_root runuser -u "$AGENT_USER" -- test -r "$EXERCISE/state/openclaw.json" || fail "agent user cannot traverse the exercise lane"

printf '%s\n' "$BASELINE/workspace" > "$META/baseline-workspace"
printf '%s\n' "$EXERCISE/workspace" > "$META/exercise-workspace"
printf '%s\n' "$BASELINE/state" > "$META/baseline-state"
printf '%s\n' "$EXERCISE/state" > "$META/exercise-state"
printf '%s\n' "$BASELINE/home" > "$META/baseline-home"
printf '%s\n' "$EXERCISE/home" > "$META/exercise-home"
if [ "$TARGET_KIND" = "plugin" ]; then
  printf '%s\n' "$EXERCISE/plugin/$TARGET_ID" > "$META/target-root"
else
  printf '%s\n' "$EXERCISE/workspace/skills/$TARGET_ID" > "$META/target-root"
fi

run_inventory() {
  local lane=$1
  local root=$2
  local phase=$3
  local other_root="$EXERCISE"
  [ "$lane" = "exercise" ] && other_root="$BASELINE"
  local receipt="$OUT/$lane/inventory.$phase"
  local unit="observatory-$RUN_ID-$lane-inventory-$phase"
  [ ! -e "$receipt" ] || fail "persistence inventory receipt already exists for $lane/$phase"
  # The inventory runs as the unprivileged agent identity in a read-only mount
  # namespace. systemd opens the bounded receipt before dropping privileges, so
  # neither the inventory process nor the target can alter another path.
  as_root systemd-run --quiet --wait --collect --unit="$unit" \
    --property="User=$AGENT_USER" \
    --property="Group=$AGENT_USER" \
    --property=CapabilityBoundingSet= \
    --property=AmbientCapabilities= \
    --property=NoNewPrivileges=yes \
    --property=PrivateDevices=yes \
    --property=PrivateMounts=yes \
    --property=PrivateNetwork=yes \
    --property=PrivateTmp=yes \
    --property=ProtectClock=yes \
    --property=ProtectControlGroups=yes \
    --property=ProtectHome=yes \
    --property=ProtectHostname=yes \
    --property=ProtectKernelLogs=yes \
    --property=ProtectKernelModules=yes \
    --property=ProtectKernelTunables=yes \
    --property=ProtectProc=invisible \
    --property=ProtectSystem=strict \
    --property=ProcSubset=pid \
    --property=RestrictAddressFamilies=AF_UNIX \
    --property=RestrictNamespaces=yes \
    --property=RestrictRealtime=yes \
    --property=RestrictSUIDSGID=yes \
    --property=LockPersonality=yes \
    --property=MemoryMax=134217728 \
    --property=MemorySwapMax=0 \
    --property=CPUQuota=25% \
    --property=TasksMax=16 \
    --property=LimitNOFILE=64 \
    --property=LimitFSIZE=8388608 \
    --property=RuntimeMaxSec=15s \
    --property=TimeoutStopSec=2s \
    --property=KillMode=control-group \
    --property=SendSIGKILL=yes \
    --property=SocketBindDeny=any \
    --property="ReadOnlyPaths=$root $CONTROL/inventory.mjs" \
    --property="InaccessiblePaths=$REPO_ROOT $other_root" \
    --property="WorkingDirectory=$root" \
    --property="StandardOutput=file:$receipt" \
    --property=StandardError=null \
    --property=SystemCallArchitectures=native \
    --property="SystemCallFilter=~io_uring_setup io_uring_register io_uring_enter" \
    --property=SystemCallErrorNumber=EPERM \
    --property=UMask=0077 \
    /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
      node "$CONTROL/inventory.mjs" "$root" - \
    || fail "bounded persistence inventory failed for $lane/$phase"
  [ -f "$receipt" ] || fail "persistence inventory receipt is missing for $lane/$phase"
  [ "$(stat -c %s "$receipt")" -le 8388608 ] || fail "persistence inventory receipt exceeded its output cap"
  as_root chown "$CONTROL_UID:$CONTROL_GID" "$receipt"
  as_root chmod 0600 "$receipt"
}

run_lane() {
  local lane=$1
  local root=$2
  local trace_dir="$OUT/$lane"
  local workspace="$root/workspace"
  local state="$root/state"
  local home="$root/home"
  local session="observatory-$RUN_ID"
  local unit="observatory-$RUN_ID"
  local other_root="$EXERCISE"
  [ "$lane" = "exercise" ] && other_root="$BASELINE"
  local network_args=(--property=IPAddressDeny=any)
  while IFS= read -r address; do
    [ -n "$address" ] && network_args+=(--property="IPAddressAllow=$address")
  done < <(node -e 'const r=require(process.argv[1]); for (const value of r.controlPlaneIps) console.log(value)' "$RUNTIME_JSON")
  # The controlled mock egress sink is a distinct, auditable allowlist entry kept
  # separate from the exact model control-plane allowlist above.
  while IFS= read -r address; do
    [ -n "$address" ] && network_args+=(--property="IPAddressAllow=$address")
  done < <(node -e 'const r=require(process.argv[1]); for (const value of (r.mockEgressIps||[])) console.log(value)' "$RUNTIME_JSON")
  local code=0
  # Snapshot persistence surfaces after seeding and before the agent runs, then
  # again after it completes. Each inventory has its own bounded, read-only,
  # unprivileged transient unit.
  run_inventory "$lane" "$root" before
  as_root systemd-run --quiet --wait --collect --unit="$unit" \
    --property=KillMode=control-group \
    --property=SendSIGKILL=yes \
    --property=TimeoutStopSec=5s \
    --property="RuntimeMaxSec=${TIMEOUT_SECONDS}s" \
    --property="MemoryMax=$MAX_MEMORY_BYTES" \
    --property="CPUQuota=$CPU_QUOTA_PERCENT%" \
    --property="TasksMax=$MAX_TASKS" \
    --property=NoNewPrivileges=yes \
    --property=PrivateDevices=yes \
    --property="BindPaths=$root/tmp:/tmp $root/var-tmp:/var/tmp" \
    --property=ProtectClock=yes \
    --property=ProtectControlGroups=yes \
    --property=ProtectHome=tmpfs \
    --property=ProtectHostname=yes \
    --property=ProtectKernelLogs=yes \
    --property=ProtectKernelModules=yes \
    --property=ProtectKernelTunables=yes \
    --property=ProtectProc=invisible \
    --property=ProtectSystem=strict \
    --property=ProcSubset=pid \
    --property=RestrictAddressFamilies="AF_UNIX AF_INET AF_INET6" \
    --property=RestrictNamespaces=yes \
    --property=RestrictRealtime=yes \
    --property=RestrictSUIDSGID=yes \
    --property=LockPersonality=yes \
    --property="InaccessiblePaths=$REPO_ROOT $other_root" \
    --property=SocketBindDeny=any \
    --property=StandardOutput=null \
    --property=StandardError=null \
    --property=SystemCallArchitectures=native \
    --property="SystemCallFilter=~io_uring_setup io_uring_register io_uring_enter" \
    --property=SystemCallErrorNumber=EPERM \
    --property=UMask=0077 \
    --property="WorkingDirectory=$workspace" \
    --property="ReadWritePaths=$root $trace_dir" \
    "${network_args[@]}" \
    /bin/bash "$CONTROL/run-agent.sh" "$root" "$trace_dir" "$session" \
      "$RUNTIME_JSON" "$root/prompt.txt" || code=$?
  printf '%s\n' "$code" > "$META/$lane-exit"
  run_inventory "$lane" "$root" after
}

# run_lane_and_capture brackets each lane with a dedicated hardened sink unit.
# The sink stays outside the untrusted agent cgroup but has no capabilities,
# write access only to its lane receipt directory, and strict resource limits.
run_lane_and_capture() {
  local lane=$1
  local root=$2
  local sink_wait_pid=""
  local sink_unit="observatory-$RUN_ID-$lane-mock-egress"
  local receipt="$OUT/$lane/mock-egress.json"
  if [ "$MOCK_EGRESS_ENABLED" = "1" ]; then
    [ ! -e "$receipt" ] && [ ! -e "$receipt.ready" ] || fail "controlled mock egress receipt path already exists for $lane lane"
    as_root systemd-run --quiet --wait --collect --unit="$sink_unit" \
      --property="User=$CONTROL_USER" \
      --property="Group=$(id -gn)" \
      --property=CapabilityBoundingSet= \
      --property=AmbientCapabilities= \
      --property=NoNewPrivileges=yes \
      --property=PrivateDevices=yes \
      --property=PrivateMounts=yes \
      --property=PrivateTmp=yes \
      --property=ProtectClock=yes \
      --property=ProtectControlGroups=yes \
      --property=ProtectHome=yes \
      --property=ProtectHostname=yes \
      --property=ProtectKernelLogs=yes \
      --property=ProtectKernelModules=yes \
      --property=ProtectKernelTunables=yes \
      --property=ProtectProc=invisible \
      --property=ProtectSystem=strict \
      --property=ProcSubset=pid \
      --property="RestrictAddressFamilies=AF_UNIX AF_INET" \
      --property=RestrictNamespaces=yes \
      --property=RestrictRealtime=yes \
      --property=RestrictSUIDSGID=yes \
      --property=LockPersonality=yes \
      --property=MemoryMax=134217728 \
      --property=MemorySwapMax=0 \
      --property=CPUQuota=25% \
      --property=TasksMax=16 \
      --property=LimitNOFILE=64 \
      --property="LimitFSIZE=$MOCK_RECEIPT_MAX_BYTES" \
      --property="RuntimeMaxSec=$((MOCK_DEADLINE_SECONDS + 5))s" \
      --property=TimeoutStopSec=2s \
      --property=KillMode=control-group \
      --property=SendSIGKILL=yes \
      --property="SocketBindAllow=tcp:ipv4:$MOCK_SINK_PORT" \
      --property=SocketBindDeny=any \
      --property="ReadOnlyPaths=$CONTROL/runtime.json $CONTROL/mock-egress-sink.mjs" \
      --property="ReadWritePaths=$OUT/$lane" \
      --property="InaccessiblePaths=$REPO_ROOT $BASELINE $EXERCISE" \
      --property="WorkingDirectory=$OUT/$lane" \
      --property=StandardOutput=null \
      --property=StandardError=null \
      --property=SystemCallArchitectures=native \
      --property="SystemCallFilter=~io_uring_setup io_uring_register io_uring_enter" \
      --property=SystemCallErrorNumber=EPERM \
      --property=UMask=0077 \
      /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
        node "$CONTROL/mock-egress-sink.mjs" "$RUNTIME_JSON" "$receipt" "$lane" &
    sink_wait_pid=$!
    local waited=0
    while [ "$waited" -lt 100 ]; do
      [ -f "$receipt.ready" ] && break
      kill -0 "$sink_wait_pid" 2>/dev/null || break
      sleep 0.1
      waited=$((waited + 1))
    done
    [ -f "$receipt.ready" ] || fail "controlled mock egress sink did not bind for $lane lane"
  fi
  run_lane "$lane" "$root"
  if [ -n "$sink_wait_pid" ]; then
    if [ ! -f "$receipt" ]; then
      as_root systemctl kill --kill-who=main --signal=SIGTERM "$sink_unit" || fail "failed to stop controlled mock egress sink for $lane lane"
    fi
    wait "$sink_wait_pid" || fail "controlled mock egress sink unit failed for $lane lane"
    [ -f "$receipt" ] || fail "controlled mock egress receipt is missing for $lane lane"
    [ "$(stat -c %s "$receipt")" -le "$MOCK_RECEIPT_MAX_BYTES" ] || fail "controlled mock egress receipt exceeded its output cap"
  fi
}

run_lane_and_capture baseline "$BASELINE"
run_lane_and_capture exercise "$EXERCISE"
date -u +%Y-%m-%dT%H:%M:%S.%NZ > "$META/completed-at"

as_root tar -C "$OUT" -czf "$OUT/raw.tar.gz" meta baseline exercise
as_root chown "$(id -u):$(id -g)" "$OUT/raw.tar.gz"
as_root chmod 0600 "$OUT/raw.tar.gz"
install -d -m 0700 "$DOWNLOAD_OUT"
install -m 0600 "$OUT/raw.tar.gz" "$DOWNLOAD_OUT/raw.tar.gz"
exit 0
`
