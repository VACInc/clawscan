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
fs.mkdirSync(path.dirname(configPath), { recursive: true });
fs.writeFileSync(configPath, JSON.stringify(config, null, 2) + "\n", { mode: 0o600 });
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

# Bash applies this RLIMIT_FSIZE (in 1024-byte blocks) to the trace and both
# redirected streams, and every descendant inherits it.
ulimit -f "$CAPTURE_FILE_BLOCKS"
exec strace -f -qq -s 0 -yy -ttt -e signal=none \
  -e trace=open,openat,openat2,creat,link,linkat,symlink,symlinkat,unlink,unlinkat,rename,renameat,renameat2,mkdir,mkdirat,rmdir,truncate,ftruncate,chdir,fchdir,clone,clone3,fork,vfork,unshare,execve,execveat,connect,sendto,sendmsg,sendmmsg,write,writev \
  -u "$AGENT_USER" -o "$TRACE_DIR/trace" \
  env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    HOME="$HOME_DIR" TMPDIR=/tmp OBSERVATORY_WORKSPACE="$WORKSPACE" OPENCLAW_STATE_DIR="$STATE" OPENCLAW_CONFIG_PATH="$STATE/openclaw.json" \
    "$OPENCLAW_COMMAND" agent --local --agent observatory --session-id "$SESSION" \
      --message-file "$PROMPT" --json \
  > "$TRACE_DIR/agent.stdout" 2> "$TRACE_DIR/agent.stderr"
`

// toolAuditExportScript reads only OpenClaw's canonical metadata-only audit
// table. It never launches OpenClaw or a Gateway, and the remote runner executes
// it after the untrusted lane has stopped inside a second, read-only systemd
// unit. The OpenClaw schema has no tool argument or result columns, so this
// exporter deliberately cannot publish or correlate either.
const toolAuditExportScript = `import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

const [laneRootArg, outputArg, agentIdArg, maxCallsArg] = process.argv.slice(2);
if (!laneRootArg || !outputArg || !agentIdArg || !maxCallsArg) {
  throw new Error("usage: export-tool-audit.mjs LANE_ROOT OUTPUT AGENT_ID MAX_CALLS");
}
const maxCalls = Number(maxCallsArg);
if (!Number.isSafeInteger(maxCalls) || maxCalls < 1 || maxCalls > 16384) {
  throw new Error("invalid tool-call export bound");
}
if (!/^[a-z_][a-z0-9_-]{0,31}$/.test(agentIdArg)) {
  throw new Error("invalid audit agent id");
}

function requireDirectory(candidate, label) {
  const info = fs.lstatSync(candidate);
  if (!info.isDirectory() || info.isSymbolicLink()) throw new Error(label + " must be a real directory");
}
function requireRegular(candidate, label) {
  const info = fs.lstatSync(candidate);
  if (!info.isFile() || info.isSymbolicLink()) throw new Error(label + " must be a regular non-symlink file");
}
function beneath(candidate, root) {
  return candidate === root || candidate.startsWith(root + path.sep);
}

const laneRoot = path.resolve(laneRootArg);
const stateRoot = path.join(laneRoot, "state");
const sqliteDir = path.join(stateRoot, "state");
const databasePath = path.join(sqliteDir, "openclaw.sqlite");
const outputPath = path.resolve(outputArg);
const outputDir = path.dirname(outputPath);
requireDirectory(laneRoot, "lane root");
requireDirectory(stateRoot, "OpenClaw state root");
requireDirectory(sqliteDir, "OpenClaw SQLite directory");
requireRegular(databasePath, "OpenClaw SQLite database");
requireDirectory(outputDir, "audit output directory");
for (const suffix of ["-wal", "-shm"]) {
  const sidecar = databasePath + suffix;
  if (fs.existsSync(sidecar)) requireRegular(sidecar, "OpenClaw SQLite sidecar");
}
const realLaneRoot = fs.realpathSync(laneRoot);
const realDatabase = fs.realpathSync(databasePath);
const realOutputDir = fs.realpathSync(outputDir);
if (!beneath(realDatabase, realLaneRoot)) throw new Error("OpenClaw SQLite database escaped the lane root");
if (!beneath(realOutputDir, realLaneRoot)) throw new Error("audit output escaped the lane root");
if (fs.existsSync(outputPath)) throw new Error("audit output already exists");

const database = new DatabaseSync(databasePath, { readOnly: true });
try {
  database.exec("PRAGMA query_only=ON; PRAGMA trusted_schema=OFF;");
  const columns = database.prepare("PRAGMA table_info(audit_events)").all();
  const names = new Set(columns.map((column) => String(column.name)));
  const required = [
    "sequence", "event_id", "source_id", "schema_version", "source_sequence", "occurred_at",
    "kind", "action", "status", "error_code", "actor_type", "actor_id", "agent_id", "run_id",
    "tool_call_id", "tool_name",
  ];
  for (const name of required) {
    if (!names.has(name)) throw new Error("audit_events is missing required column " + name);
  }

  const callKey = "CASE " +
    "WHEN tool_call_id IS NULL OR trim(tool_call_id) = '' THEN 'sequence:' || CAST(sequence AS TEXT) " +
    "ELSE 'id:' || tool_call_id END";
  const totalRow = database.prepare(
    "SELECT COUNT(*) AS total_calls FROM (" +
      "SELECT run_id, " + callKey + " AS call_key " +
      "FROM audit_events " +
      "WHERE agent_id = ? AND kind = 'tool_action' " +
      "GROUP BY run_id, call_key" +
    ")"
  ).get(agentIdArg);
  const totalCalls = Number(totalRow?.total_calls);
  if (!Number.isSafeInteger(totalCalls) || totalCalls < 0) throw new Error("invalid total tool-call count");

  const maxEvents = maxCalls * 2;
  const rows = database.prepare(
    "WITH selected_calls AS (" +
      "SELECT run_id, " + callKey + " AS call_key, MIN(sequence) AS first_sequence " +
      "FROM audit_events " +
      "WHERE agent_id = ? AND kind = 'tool_action' " +
      "GROUP BY run_id, call_key " +
      "ORDER BY first_sequence ASC " +
      "LIMIT ?" +
    ") " +
    "SELECT event.event_id, event.sequence, event.schema_version, event.source_sequence, event.occurred_at, event.kind, event.action, event.status, " +
      "event.error_code, event.actor_type, event.actor_id, event.agent_id, event.run_id, event.tool_call_id, event.tool_name " +
    "FROM audit_events AS event " +
    "INNER JOIN selected_calls AS selected " +
      "ON selected.run_id = event.run_id " +
      "AND selected.call_key = CASE " +
        "WHEN event.tool_call_id IS NULL OR trim(event.tool_call_id) = '' THEN 'sequence:' || CAST(event.sequence AS TEXT) " +
        "ELSE 'id:' || event.tool_call_id END " +
    "WHERE event.agent_id = ? AND event.kind = 'tool_action' " +
    "ORDER BY event.sequence DESC " +
    "LIMIT ?"
  ).all(agentIdArg, maxCalls, agentIdArg, maxEvents + 1);
  const eventOverflow = rows.length > maxEvents;
  if (eventOverflow) throw new Error("a tool call has duplicate lifecycle records");

  function requiredText(value, field, max = 1024) {
    if (typeof value !== "string" || value.length < 1 || value.length > max || /[\u0000\r\n]/.test(value)) {
      throw new Error("invalid audit " + field);
    }
    return value;
  }
  function optionalText(value, field, max = 1024) {
    if (value === null || value === undefined) return undefined;
    return requiredText(value, field, max);
  }
  function integer(value, field, minimum) {
    const number = Number(value);
    if (!Number.isSafeInteger(number) || number < minimum) throw new Error("invalid audit " + field);
    return number;
  }

  const events = rows.map((row) => {
    const schemaVersion = integer(row.schema_version, "schemaVersion", 1);
    if (schemaVersion !== 1) throw new Error("unsupported audit schemaVersion");
    const event = {
      eventId: requiredText(row.event_id, "eventId"),
      sequence: integer(row.sequence, "sequence", 1),
      sourceSequence: integer(row.source_sequence, "sourceSequence", 1),
      occurredAt: integer(row.occurred_at, "occurredAt", 0),
      kind: requiredText(row.kind, "kind", 32),
      action: requiredText(row.action, "action", 64),
      status: requiredText(row.status, "status", 32),
      actor: {
        type: requiredText(row.actor_type, "actor.type", 32),
        id: requiredText(row.actor_id, "actor.id"),
      },
      agentId: requiredText(row.agent_id, "agentId", 64),
      runId: requiredText(row.run_id, "runId"),
      redaction: "metadata_only",
    };
    const errorCode = optionalText(row.error_code, "errorCode", 64);
    const toolCallId = optionalText(row.tool_call_id, "toolCallId");
    const toolName = optionalText(row.tool_name, "toolName", 1024);
    if (errorCode !== undefined) event.errorCode = errorCode;
    if (toolCallId !== undefined) event.toolCallId = toolCallId;
    if (toolName !== undefined) event.toolName = toolName;
    return event;
  });

  const document = {
    source: "openclaw-state-sqlite",
    maxCalls,
    events,
    totalCalls,
    truncated: totalCalls > maxCalls,
  };
  const payload = JSON.stringify(document) + "\n";
  if (Buffer.byteLength(payload) > 8 * 1024 * 1024) throw new Error("audit export exceeds 8 MiB");
  fs.writeFileSync(outputPath, payload, { encoding: "utf8", mode: 0o600, flag: "wx" });
} finally {
  database.close();
}
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
AGENT_ID=observatory
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

as_root install -d -m 0711 "$WORK_ROOT"
as_root install -d -m 0700 "$CONTROL"
as_root install -m 0600 "$STAGED_RUNNER/runtime.json" "$CONTROL/runtime.json"
as_root install -m 0600 "$STAGED_RUNNER/firewall.nft" "$CONTROL/firewall.nft"
as_root install -m 0600 "$STAGED_RUNNER/prompt.txt" "$CONTROL/prompt.txt"
as_root install -m 0600 "$STAGED_RUNNER/write-config.mjs" "$CONTROL/write-config.mjs"
as_root install -m 0600 "$STAGED_RUNNER/apply-target-modes.mjs" "$CONTROL/apply-target-modes.mjs"
as_root install -m 0600 "$STAGED_RUNNER/export-tool-audit.mjs" "$CONTROL/export-tool-audit.mjs"
as_root install -m 0600 "$STAGED_RUNNER/target-modes.json" "$CONTROL/target-modes.json"
as_root install -m 0700 "$STAGED_RUNNER/run-agent.sh" "$CONTROL/run-agent.sh"
RUNTIME_JSON="$CONTROL/runtime.json"

SSH_PEER=${SSH_CONNECTION:-}
SSH_PEER=${SSH_PEER%% *}
[ -n "$SSH_PEER" ] || fail "SSH_CONNECTION is required to pin the management firewall peer"
as_root node -e 'const fs=require("fs"),net=require("net");const [file,peer]=process.argv.slice(1);if(!net.isIPv4(peer))throw new Error("management peer must be literal IPv4");const marker="@MANAGEMENT_IPV4@",input=fs.readFileSync(file,"utf8");if(input.split(marker).length!==2)throw new Error("firewall management marker is missing or repeated");fs.writeFileSync(file,input.replace(marker,peer),{mode:0o600});' "$CONTROL/firewall.nft" "$SSH_PEER"
as_root nft -f "$CONTROL/firewall.nft"

as_root install -d -m 0711 "$OUT" "$OUT/runtime"
as_root chown "$(id -u):$(id -g)" "$OUT" "$OUT/runtime"
install -d -m 0700 "$META" "$OUT/baseline" "$OUT/exercise"
printf '%s\n' "$RUN_ID" > "$META/run-id"
printf '%s\n' "$TARGET_SHA256" > "$META/target-sha256"
printf '%s\n' "$CAPTURE_CONFIG_SHA256" > "$META/capture-config-sha256"
printf '%s\n' "$TARGET_KIND" > "$META/target-kind"
node -e 'const r=require(process.argv[1]);process.stdout.write(JSON.stringify(r.canaries)+"\n")' "$RUNTIME_JSON" > "$META/canaries.json"
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
  local code=0
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
}

# capture_tool_audit directly exports OpenClaw's metadata-only audit_events table
# after the untrusted lane unit has been collected. It never launches OpenClaw or
# contacts a Gateway. The exporter runs as the lane user in a second hardened
# unit: lane state is read-only, only a fresh export directory is writable, the
# network is private/denied, capabilities are empty, and time/memory/task/output
# limits are fixed. A missing canonical database is explicit unavailable
# coverage; a present-but-invalid database or failed export aborts the capture.
capture_tool_audit() {
  local lane=$1
  local root=$2
  local other_root="$EXERCISE"
  [ "$lane" = "exercise" ] && other_root="$BASELINE"
  local trace_dir="$OUT/$lane"
  local state="$root/state"
  local sqlite_dir="$state/state"
  local database="$sqlite_dir/openclaw.sqlite"
  local audit_dir="$root/audit-export"
  local audit_output="$audit_dir/output"
  local unit="observatory-$RUN_ID-audit-$lane"
  [ ! -L "$state" ] && [ -d "$state" ] || fail "OpenClaw state root is not a real directory for $lane lane"
  if [ ! -e "$sqlite_dir" ] && [ ! -L "$sqlite_dir" ]; then
    printf 'unavailable\n' > "$META/$lane-audit-status"
    return
  fi
  [ ! -L "$sqlite_dir" ] && [ -d "$sqlite_dir" ] || fail "OpenClaw SQLite directory is not a real directory for $lane lane"
  if [ ! -e "$database" ] && [ ! -L "$database" ]; then
    printf 'unavailable\n' > "$META/$lane-audit-status"
    return
  fi
  [ ! -L "$database" ] && [ -f "$database" ] || fail "OpenClaw SQLite database is not a regular file for $lane lane"
  for sidecar in "$database-wal" "$database-shm"; do
    if [ -e "$sidecar" ] || [ -L "$sidecar" ]; then
      [ ! -L "$sidecar" ] && [ -f "$sidecar" ] || fail "OpenClaw SQLite sidecar is not a regular file for $lane lane"
    fi
  done
  [ ! -e "$audit_dir" ] && [ ! -L "$audit_dir" ] || fail "audit export path already exists for $lane lane"
  as_root install -d -m 0711 -o root -g root "$audit_dir"
  as_root install -d -m 0700 -o "$AGENT_USER" -g "$AGENT_USER" "$audit_output"
  as_root install -m 0444 "$CONTROL/export-tool-audit.mjs" "$audit_dir/export-tool-audit.mjs"
  if ! as_root systemd-run --quiet --wait --collect --unit="$unit" \
      --property="User=$AGENT_USER" \
      --property="Group=$AGENT_USER" \
      --property=KillMode=control-group \
      --property=SendSIGKILL=yes \
      --property=TimeoutStopSec=2s \
      --property=RuntimeMaxSec=20s \
      --property=MemoryMax=134217728 \
      --property=CPUQuota=50% \
      --property=TasksMax=16 \
      --property=LimitFSIZE=8388608 \
      --property=NoNewPrivileges=yes \
      --property=CapabilityBoundingSet= \
      --property=AmbientCapabilities= \
      --property=PrivateDevices=yes \
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
      --property="InaccessiblePaths=$REPO_ROOT $other_root $root/workspace $root/home $root/tmp $root/var-tmp $root/target $root/plugin" \
      --property="ReadOnlyPaths=$root" \
      --property="ReadWritePaths=$audit_output" \
      --property=IPAddressDeny=any \
      --property=SocketBindDeny=any \
      --property=StandardOutput=null \
      --property=StandardError=null \
      --property=SystemCallArchitectures=native \
      --property="SystemCallFilter=~io_uring_setup io_uring_register io_uring_enter" \
      --property=SystemCallErrorNumber=EPERM \
      --property=UMask=0077 \
      --property="WorkingDirectory=$audit_output" \
      /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
        node "$audit_dir/export-tool-audit.mjs" "$root" "$audit_output/audit.json" "$AGENT_ID" "4096"; then
    fail "contained OpenClaw tool-audit export failed for $lane lane"
  fi
  [ ! -L "$audit_output/audit.json" ] && [ -f "$audit_output/audit.json" ] || fail "contained tool-audit export produced no regular receipt for $lane lane"
  as_root install -m 0600 "$audit_output/audit.json" "$trace_dir/audit.json"
  printf 'captured\n' > "$META/$lane-audit-status"
}

run_lane baseline "$BASELINE"
run_lane exercise "$EXERCISE"
capture_tool_audit baseline "$BASELINE"
capture_tool_audit exercise "$EXERCISE"
date -u +%Y-%m-%dT%H:%M:%S.%NZ > "$META/completed-at"

as_root tar -C "$OUT" -czf "$OUT/raw.tar.gz" meta baseline exercise
as_root chown "$(id -u):$(id -g)" "$OUT/raw.tar.gz"
as_root chmod 0600 "$OUT/raw.tar.gz"
install -d -m 0700 "$DOWNLOAD_OUT"
install -m 0600 "$OUT/raw.tar.gz" "$DOWNLOAD_OUT/raw.tar.gz"
exit 0
`
