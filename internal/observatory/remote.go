package observatory

const writeConfigScript = `import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";

const runtime = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const workspace = process.env.OBSERVATORY_WORKSPACE;
const configPath = process.env.OPENCLAW_CONFIG_PATH;
const home = process.env.OBSERVATORY_HOME;
const state = process.env.OPENCLAW_STATE_DIR;
const lane = process.env.OBSERVATORY_LANE;
const targetRoot = process.env.OBSERVATORY_TARGET_ROOT;
// Reserved identifier that no staged target may use, so the baseline lane can
// express "an allowlist that matches nothing" on OpenClaw builds that no longer
// accept plugins.bundledDiscovery.
const observatoryReservedPluginID = "observatory-no-plugin";
// The guest OpenClaw build decides which configuration spelling is valid, and a
// rejected key aborts the lane. The schema is read from the guest CLI itself so
// one runner template revision is not silently pinned to one OpenClaw revision.
// When the probe is unavailable the legacy spelling is kept, which is the schema
// the currently pinned template ships.
let guestConfigSchema = null;
try {
  const probe = execFileSync(typeof runtime.openclawCommand === "string" && runtime.openclawCommand.length > 0 ? runtime.openclawCommand : "openclaw", ["config", "schema"], { encoding: "utf8", timeout: 60000, maxBuffer: 64 * 1024 * 1024, stdio: ["ignore", "pipe", "ignore"] });
  guestConfigSchema = JSON.parse(probe);
} catch { guestConfigSchema = null; }
function guestSchemaSupports(segments) {
  if (!guestConfigSchema) return false;
  let node = guestConfigSchema;
  for (const segment of segments) {
    node = node && node.properties ? node.properties[segment] : null;
    if (!node) return false;
  }
  return true;
}
const execTimeoutKey = guestSchemaSupports(["tools", "exec", "timeoutSeconds"]) ? "timeoutSeconds" : "timeoutSec";
const supportsBundledDiscovery = !guestSchemaSupports(["tools", "exec", "timeoutSeconds"]) || guestSchemaSupports(["plugins", "bundledDiscovery"]);
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
  },
  agents: {
    defaults: {
      model: { primary: model.provider + "/" + model.id },
      sandbox: { mode: "off" },
      timeoutSeconds: runtime.timeoutSeconds,
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
        timeoutSeconds: runtime.timeoutSeconds,
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
    exec: { security: "full", ask: "off", [execTimeoutKey]: runtime.timeoutSeconds },
  },
};
if (runtime.targetKind === "plugin") {
  if (runtime.targetId === observatoryReservedPluginID) throw new Error("staged plugin uses the reserved Observatory identifier");
  if (lane === "exercise" && typeof runtime.targetTool === "string" && runtime.targetTool.length > 0) config.tools.alsoAllow = [runtime.targetTool];
  // plugins.allow is the loader allowlist: when it is set, only the listed IDs
  // are eligible to load. Builds that still accept bundledDiscovery keep the
  // explicit allowlist discovery mode. Builds that dropped it get a reserved ID
  // in the baseline lane, so the allowlist stays non-empty and the eligible set
  // stays empty instead of relying on an empty array being read as deny-all.
  const exercisePlugins = {
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
  };
  const baselinePlugins = {
    enabled: true,
    allow: supportsBundledDiscovery ? [] : [observatoryReservedPluginID],
    deny: [],
    load: { paths: [] },
    entries: {},
  };
  if (supportsBundledDiscovery) {
    exercisePlugins.bundledDiscovery = "allowlist";
    baselinePlugins.bundledDiscovery = "allowlist";
  }
  config.plugins = lane === "exercise" ? exercisePlugins : baselinePlugins;
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
exec strace -f -qq -s 0 -yy -ttt -e signal=none \
  -e trace=open,openat,openat2,creat,link,linkat,symlink,symlinkat,unlink,unlinkat,rename,renameat,renameat2,mkdir,mkdirat,rmdir,truncate,ftruncate,chdir,fchdir,clone,clone3,fork,vfork,unshare,execve,execveat,connect,sendto,sendmsg,sendmmsg,write,writev \
  -u "$AGENT_USER" -o "$TRACE_DIR/trace" \
  env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    ${MOCK_ENV[@]+"${MOCK_ENV[@]}"} \
    HOME="$HOME_DIR" TMPDIR=/tmp OBSERVATORY_WORKSPACE="$WORKSPACE" OPENCLAW_STATE_DIR="$STATE" OPENCLAW_CONFIG_PATH="$STATE/openclaw.json" \
    "$OPENCLAW_COMMAND" agent --local --agent observatory --session-id "$SESSION" \
      --message-file "$PROMPT" --timeout "$(node -e 'const r=require(process.argv[1]); process.stdout.write(String(r.timeoutSeconds))' "$RUNTIME_JSON")" --json \
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
if (beneath(realOutputDir, realLaneRoot)) throw new Error("audit scratch must be isolated from the lane filesystem");
if (fs.existsSync(outputPath)) throw new Error("audit output already exists");

// OpenClaw uses WAL mode. Even a read-only query can require SQLite to create
// shared-memory state after the writer exits, which must never make the lane
// writable. Copy the stopped database and any validated sidecars into this
// exporter's private scratch directory, then recover/query only that copy.
const analysisDatabasePath = path.join(outputDir, "openclaw-audit-copy.sqlite");
fs.copyFileSync(databasePath, analysisDatabasePath, fs.constants.COPYFILE_EXCL);
fs.chmodSync(analysisDatabasePath, 0o600);
for (const suffix of ["-wal", "-shm"]) {
  const source = databasePath + suffix;
  if (!fs.existsSync(source)) continue;
  const destination = analysisDatabasePath + suffix;
  fs.copyFileSync(source, destination, fs.constants.COPYFILE_EXCL);
  fs.chmodSync(destination, 0o600);
}

const database = new DatabaseSync(analysisDatabasePath);
try {
  database.exec("PRAGMA query_only=ON; PRAGMA trusted_schema=OFF;");
  const auditTable = database.prepare(
    "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'audit_events'"
  ).get();
  if (auditTable?.name !== "audit_events") {
    // Released OpenClaw builds can create the shared state database without
    // shipping the optional audit recorder. That is unavailable coverage, not
    // a malformed recorder. Existing-but-incompatible audit tables still fail
    // closed through the strict column checks below.
    const payload = JSON.stringify({
      source: "openclaw-state-sqlite",
      recorderObserved: false,
      maxCalls,
      events: [],
      totalCalls: 0,
      truncated: false,
    }) + "\n";
    database.close();
    fs.writeFileSync(outputPath, payload, { encoding: "utf8", mode: 0o600, flag: "wx" });
    process.exit(0);
  }
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

  // The state database can exist for unrelated local-agent caches even when no
  // audit recorder was installed. A complete agent-run lifecycle is the minimum
  // recorder signal required before an empty tool ledger can mean zero calls.
  const recorderRow = database.prepare(
    "SELECT COUNT(*) AS recorder_runs FROM (" +
      "SELECT run_id FROM audit_events " +
      "WHERE agent_id = ? AND kind = 'agent_run' AND run_id IS NOT NULL AND trim(run_id) <> '' " +
      "GROUP BY run_id " +
      "HAVING SUM(CASE WHEN action = 'agent.run.started' AND status = 'started' THEN 1 ELSE 0 END) > 0 " +
      "AND SUM(CASE WHEN action = 'agent.run.finished' AND status IN ('succeeded','failed','cancelled','timed_out','blocked') THEN 1 ELSE 0 END) > 0" +
    ")"
  ).get(agentIdArg);
  const recorderRuns = Number(recorderRow?.recorder_runs);
  if (!Number.isSafeInteger(recorderRuns) || recorderRuns < 0) throw new Error("invalid audit recorder count");
  const recorderObserved = recorderRuns > 0;

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
    recorderObserved,
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
ACTIVE_RELAY_UNIT=""
ACTIVE_SINK_UNIT=""

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

cleanup_capture_units() {
  set +e
  if [ -n "$ACTIVE_SINK_UNIT" ] && as_root systemctl is-active --quiet "$ACTIVE_SINK_UNIT"; then
    as_root systemctl kill --kill-who=main --signal=SIGTERM "$ACTIVE_SINK_UNIT"
  fi
  if [ -n "$ACTIVE_RELAY_UNIT" ] && as_root systemctl is-active --quiet "$ACTIVE_RELAY_UNIT"; then
    as_root systemctl kill --kill-who=main --signal=SIGTERM "$ACTIVE_RELAY_UNIT"
  fi
}
trap cleanup_capture_units EXIT

command -v node >/dev/null 2>&1 || fail "node is required in the Observatory VM template"
command -v strace >/dev/null 2>&1 || fail "strace is required in the Observatory VM template"
command -v systemd-run >/dev/null 2>&1 || fail "systemd-run is required in the Observatory VM template"
command -v tar >/dev/null 2>&1 || fail "tar is required in the Observatory VM template"
command -v runuser >/dev/null 2>&1 || fail "runuser is required in the Observatory VM template"
command -v nft >/dev/null 2>&1 || fail "nftables is required in the Observatory VM template"
command -v mount >/dev/null 2>&1 || fail "mount is required in the Observatory VM template"
command -v findmnt >/dev/null 2>&1 || fail "findmnt is required in the Observatory VM template"
command -v systemctl >/dev/null 2>&1 || fail "systemctl is required in the Observatory VM template"
command -v pgrep >/dev/null 2>&1 || fail "pgrep is required in the Observatory VM template"
command -v "$OPENCLAW_COMMAND" >/dev/null 2>&1 || fail "OpenClaw is required in the Observatory VM template"
[ "$AGENT_USER" = "observatory" ] || fail "Observatory agent user must be the pinned observatory account"
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
if as_root pgrep -u "$AGENT_USER" >/dev/null 2>&1; then
  fail "Observatory agent UID has preexisting processes"
fi

CONTROL_UID=$(id -u)
CONTROL_GID=$(id -g)
CONTROL_USER=$(id -un)
as_root install -d -m 0711 "$WORK_ROOT"
as_root install -d -m 0711 -o "$CONTROL_UID" -g "$CONTROL_GID" "$CONTROL"
as_root install -m 0600 -o "$CONTROL_UID" -g "$CONTROL_GID" "$STAGED_RUNNER/runtime.json" "$CONTROL/runtime.json"
as_root install -m 0600 -o "$CONTROL_UID" -g "$CONTROL_GID" "$STAGED_RUNNER/firewall.nft" "$CONTROL/firewall.nft"
as_root install -m 0600 -o "$CONTROL_UID" -g "$CONTROL_GID" "$STAGED_RUNNER/baseline-prompt.txt" "$CONTROL/baseline-prompt.txt"
as_root install -m 0600 -o "$CONTROL_UID" -g "$CONTROL_GID" "$STAGED_RUNNER/exercise-prompt.txt" "$CONTROL/exercise-prompt.txt"
as_root install -m 0600 -o "$CONTROL_UID" -g "$CONTROL_GID" "$STAGED_RUNNER/write-config.mjs" "$CONTROL/write-config.mjs"
as_root install -m 0600 -o "$CONTROL_UID" -g "$CONTROL_GID" "$STAGED_RUNNER/apply-target-modes.mjs" "$CONTROL/apply-target-modes.mjs"
as_root install -m 0600 -o "$CONTROL_UID" -g "$CONTROL_GID" "$STAGED_RUNNER/export-tool-audit.mjs" "$CONTROL/export-tool-audit.mjs"
as_root install -m 0555 -o "$CONTROL_UID" -g "$CONTROL_GID" "$STAGED_RUNNER/inventory.mjs" "$CONTROL/inventory.mjs"
as_root install -m 0600 -o "$CONTROL_UID" -g "$CONTROL_GID" "$STAGED_RUNNER/target-modes.json" "$CONTROL/target-modes.json"
as_root install -m 0500 -o "$CONTROL_UID" -g "$CONTROL_GID" "$STAGED_RUNNER/model-relay.mjs" "$CONTROL/model-relay.mjs"
as_root install -m 0500 -o "$CONTROL_UID" -g "$CONTROL_GID" "$STAGED_RUNNER/mock-egress-sink.mjs" "$CONTROL/mock-egress-sink.mjs"
as_root install -m 0700 -o "$CONTROL_UID" -g "$CONTROL_GID" "$STAGED_RUNNER/run-agent.sh" "$CONTROL/run-agent.sh"
RUNTIME_JSON="$CONTROL/runtime.json"
for lane in baseline exercise; do
  expected_prompt_sha=$(node -e 'const r=require(process.argv[1]);const v=r.lanePromptSha256?.[process.argv[2]];if(!/^sha256:[0-9a-f]{64}$/.test(v))process.exit(2);process.stdout.write(v)' "$RUNTIME_JSON" "$lane") \
    || fail "missing bound prompt digest for $lane lane"
  actual_prompt_sha="sha256:$(sha256sum "$CONTROL/$lane-prompt.txt" | cut -d' ' -f1)"
  [ "$actual_prompt_sha" = "$expected_prompt_sha" ] || fail "staged prompt digest mismatch for $lane lane"
done
MODEL_RELAY_DEADLINE_SECONDS=$(node -e 'const r=require(process.argv[1]); process.stdout.write(String(r.modelRelay.deadlineSeconds))' "$RUNTIME_JSON")
MODEL_RELAY_RECEIPT_MAX_BYTES=$(node -e 'const r=require(process.argv[1]); process.stdout.write(String(r.modelRelay.receiptMaxBytes))' "$RUNTIME_JSON")
MODEL_RELAY_PORT=$(node -e 'const r=require(process.argv[1]); process.stdout.write(String(new URL("http://"+r.modelRelay.listenAddress).port))' "$RUNTIME_JSON")
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
AGENT_UID=$(id -u "$AGENT_USER")
as_root node -e 'const fs=require("fs");const [file,agent,control]=process.argv.slice(1);if(!/^[0-9]+$/.test(agent)||!/^[0-9]+$/.test(control))throw new Error("firewall UIDs must be numeric");let input=fs.readFileSync(file,"utf8");for(const [marker,value] of [["@AGENT_UID@",agent],["@CONTROL_UID@",control]]){if(!input.includes(marker))throw new Error("firewall UID marker is missing: "+marker);input=input.split(marker).join(value)}fs.writeFileSync(file,input,{mode:0o600});' "$CONTROL/firewall.nft" "$AGENT_UID" "$CONTROL_UID"
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
  as_root install -m 0600 -o "$AGENT_USER" -g "$AGENT_USER" "$CONTROL/$lane-prompt.txt" "$root/prompt.txt"
  if [ "$lane" = "exercise" ]; then
    if [ "$TARGET_KIND" = "skill" ]; then
      target_root="$workspace/skills/$TARGET_ID"
    elif [ "$TARGET_KIND" = "plugin" ]; then
      target_root="$root/plugin/$TARGET_ID"
    else
      fail "unsupported staged target kind"
    fi
    as_root install -d -m 0700 -o "$AGENT_USER" -g "$AGENT_USER" "$target_root"
    as_root cp -a "$REPO_ROOT/artifact/." "$target_root/"
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
    --property="SystemCallFilter=~bind listen accept accept4 io_uring_setup io_uring_register io_uring_enter" \
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
  # The hostile lane receives only the bounded relay's loopback IP, never the
  # upstream model IP. nftables narrows this cgroup-level IP allowance to the
  # relay's exact TCP port and blocks every adjacent loopback destination.
  while IFS= read -r address; do
    [ -n "$address" ] && network_args+=(--property="IPAddressAllow=$address")
  done < <(node -e 'const r=require(process.argv[1]); for (const value of r.modelRelayIps) console.log(value)' "$RUNTIME_JSON")
  # The controlled mock egress sink is a second exact loopback allowlist entry.
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
    --property=MemorySwapMax=0 \
    --property="CPUQuota=$CPU_QUOTA_PERCENT%" \
    --property="TasksMax=$MAX_TASKS" \
    --property=LimitNOFILE=1024 \
    --property=NoNewPrivileges=yes \
    --property=PrivateDevices=yes \
    --property=PrivateIPC=yes \
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
    --property=RestrictAddressFamilies=AF_INET \
    --property=RestrictNamespaces=yes \
    --property=RestrictRealtime=yes \
    --property=RestrictSUIDSGID=yes \
    --property=LockPersonality=yes \
    --property="InaccessiblePaths=$REPO_ROOT $other_root" \
    --property=SocketBindDeny=any \
    --property=StandardOutput=null \
    --property=StandardError=null \
    --property=SystemCallArchitectures=native \
    --property="SystemCallFilter=~bind listen accept accept4 io_uring_setup io_uring_register io_uring_enter" \
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

# run_lane_and_capture brackets each lane with a mandatory bounded model relay
# and the optional controlled sink. Both stay outside the hostile cgroup, expose
# only exact ports, and write only body-free or bounded private receipts.
run_lane_and_capture() {
  local lane=$1
  local root=$2
  local relay_wait_pid=""
  local relay_unit="observatory-$RUN_ID-$lane-model-relay"
  local relay_receipt="$OUT/$lane/model-relay.json"
  # systemd applies IPAddressAllow to both ends of accepted connections. The
  # hostile agent connects from the kernel-selected 127.0.0.1 source address,
  # so permit that source in addition to the relay bind address. The exact
  # destination port remains enforced by nftables and SocketBindAllow.
  local relay_network_args=(--property=IPAddressDeny=any --property=IPAddressAllow=127.0.0.1)
  while IFS= read -r address; do
    [ -n "$address" ] && relay_network_args+=(--property="IPAddressAllow=$address")
  done < <(node -e 'const r=require(process.argv[1]); for (const value of r.modelRelayIps) console.log(value)' "$RUNTIME_JSON")
  while IFS= read -r address; do
    [ -n "$address" ] && relay_network_args+=(--property="IPAddressAllow=$address")
  done < <(node -e 'const r=require(process.argv[1]); for (const value of r.controlPlaneIps) console.log(value)' "$RUNTIME_JSON")
  [ ! -e "$relay_receipt" ] && [ ! -e "$relay_receipt.ready" ] || fail "model relay receipt path already exists for $lane lane"
  ACTIVE_RELAY_UNIT="$relay_unit"
  as_root systemd-run --quiet --wait --collect --unit="$relay_unit" \
    --property="User=$CONTROL_USER" \
    --property="Group=$(id -gn)" \
    --property=CapabilityBoundingSet= \
    --property=AmbientCapabilities= \
    --property=NoNewPrivileges=yes \
    --property=PrivateDevices=yes \
    --property=PrivateIPC=yes \
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
    --property=RestrictAddressFamilies=AF_INET \
    --property=RestrictNamespaces=yes \
    --property=RestrictRealtime=yes \
    --property=RestrictSUIDSGID=yes \
    --property=LockPersonality=yes \
    --property=MemoryMax=268435456 \
    --property=MemorySwapMax=0 \
    --property=CPUQuota=50% \
    --property=TasksMax=16 \
    --property=LimitNOFILE=64 \
    --property="LimitFSIZE=$MODEL_RELAY_RECEIPT_MAX_BYTES" \
    --property="RuntimeMaxSec=$((MODEL_RELAY_DEADLINE_SECONDS + 5))s" \
    --property=TimeoutStopSec=2s \
    --property=KillMode=control-group \
    --property=SendSIGKILL=yes \
    --property="SocketBindAllow=ipv4:tcp:$MODEL_RELAY_PORT" \
    --property=SocketBindDeny=any \
    --property="ReadOnlyPaths=$CONTROL/runtime.json $CONTROL/model-relay.mjs" \
    --property="ReadWritePaths=$OUT/$lane" \
    --property="InaccessiblePaths=$REPO_ROOT $BASELINE $EXERCISE" \
    --property="WorkingDirectory=$OUT/$lane" \
    --property=StandardOutput=null \
    --property=StandardError=null \
    --property=SystemCallArchitectures=native \
    --property="SystemCallFilter=~io_uring_setup io_uring_register io_uring_enter" \
    --property=SystemCallErrorNumber=EPERM \
    --property=UMask=0077 \
    "${relay_network_args[@]}" \
    /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
      node "$CONTROL/model-relay.mjs" "$RUNTIME_JSON" "$relay_receipt" "$lane" &
  relay_wait_pid=$!
  local relay_waited=0
  while [ "$relay_waited" -lt 100 ]; do
    [ -f "$relay_receipt.ready" ] && break
    kill -0 "$relay_wait_pid" 2>/dev/null || break
    sleep 0.1
    relay_waited=$((relay_waited + 1))
  done
  [ -f "$relay_receipt.ready" ] || fail "bounded model relay did not bind for $lane lane"
  local expected_relay_policy
  expected_relay_policy=$(node -e 'const r=require(process.argv[1]);process.stdout.write(r.modelRelay.policySha256)' "$RUNTIME_JSON")
  [ "$(tr -d '\n' < "$relay_receipt.ready")" = "$expected_relay_policy" ] || fail "bounded model relay readiness policy mismatch for $lane lane"

  local sink_wait_pid=""
  local sink_unit="observatory-$RUN_ID-$lane-mock-egress"
  local receipt="$OUT/$lane/mock-egress.json"
  if [ "$MOCK_EGRESS_ENABLED" = "1" ]; then
    [ ! -e "$receipt" ] && [ ! -e "$receipt.ready" ] || fail "controlled mock egress receipt path already exists for $lane lane"
    ACTIVE_SINK_UNIT="$sink_unit"
    as_root systemd-run --quiet --wait --collect --unit="$sink_unit" \
      --property="User=$CONTROL_USER" \
      --property="Group=$(id -gn)" \
      --property=CapabilityBoundingSet= \
      --property=AmbientCapabilities= \
      --property=NoNewPrivileges=yes \
      --property=PrivateDevices=yes \
      --property=PrivateIPC=yes \
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
      --property="SocketBindAllow=ipv4:tcp:$MOCK_SINK_PORT" \
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
    ACTIVE_SINK_UNIT=""
    [ -f "$receipt" ] || fail "controlled mock egress receipt is missing for $lane lane"
    [ "$(stat -c %s "$receipt")" -le "$MOCK_RECEIPT_MAX_BYTES" ] || fail "controlled mock egress receipt exceeded its output cap"
  fi
  if [ ! -f "$relay_receipt" ]; then
    as_root systemctl kill --kill-who=main --signal=SIGTERM "$relay_unit" || fail "failed to stop bounded model relay for $lane lane"
  fi
  wait "$relay_wait_pid" || fail "bounded model relay unit failed for $lane lane"
  ACTIVE_RELAY_UNIT=""
  [ -f "$relay_receipt" ] || fail "bounded model relay receipt is missing for $lane lane"
  [ "$(stat -c %s "$relay_receipt")" -le "$MODEL_RELAY_RECEIPT_MAX_BYTES" ] || fail "bounded model relay receipt exceeded its output cap"
}

# capture_tool_audit directly exports OpenClaw's metadata-only audit_events table
# after the untrusted lane unit has been collected. It never launches OpenClaw or
# contacts a Gateway. The exporter runs as the lane user in a second hardened
# unit: lane state is read-only, only a fresh export directory is writable, and
# network, capabilities, time, memory, tasks, and output are strictly bounded.
capture_tool_audit() {
  local lane=$1
  local root=$2
  local other_root="$EXERCISE"
  [ "$lane" = "exercise" ] && other_root="$BASELINE"
  local trace_dir="$OUT/$lane"
  local state="$root/state"
  local sqlite_dir="$state/state"
  local database="$sqlite_dir/openclaw.sqlite"
  local audit_copy_max_bytes=67108864
  local audit_dir="$OUT/runtime/audit-$lane"
  local audit_output="$audit_dir/output"
  local unit="observatory-$RUN_ID-audit-$lane"
  if as_root test -L "$state" || ! as_root test -d "$state"; then
    fail "OpenClaw state root is not a real directory for $lane lane"
  fi
  if ! as_root test -e "$sqlite_dir" && ! as_root test -L "$sqlite_dir"; then
    printf 'unavailable\n' > "$META/$lane-audit-status"
    return
  fi
  if as_root test -L "$sqlite_dir" || ! as_root test -d "$sqlite_dir"; then
    fail "OpenClaw SQLite directory is not a real directory for $lane lane"
  fi
  if ! as_root test -e "$database" && ! as_root test -L "$database"; then
    printf 'unavailable\n' > "$META/$lane-audit-status"
    return
  fi
  if as_root test -L "$database" || ! as_root test -f "$database"; then
    fail "OpenClaw SQLite database is not a regular file for $lane lane"
  fi
  for sidecar in "$database-wal" "$database-shm"; do
    if as_root test -e "$sidecar" || as_root test -L "$sidecar"; then
      if as_root test -L "$sidecar" || ! as_root test -f "$sidecar"; then
        fail "OpenClaw SQLite sidecar is not a regular file for $lane lane"
      fi
    fi
  done
  local audit_copy_bytes
  audit_copy_bytes=$(as_root stat -c %s "$database") || fail "cannot size OpenClaw SQLite database for $lane lane"
  [[ "$audit_copy_bytes" =~ ^[0-9]+$ ]] || fail "invalid OpenClaw SQLite database size for $lane lane"
  for sidecar in "$database-wal" "$database-shm"; do
    if as_root test -f "$sidecar"; then
      local sidecar_bytes
      sidecar_bytes=$(as_root stat -c %s "$sidecar") || fail "cannot size OpenClaw SQLite sidecar for $lane lane"
      [[ "$sidecar_bytes" =~ ^[0-9]+$ ]] || fail "invalid OpenClaw SQLite sidecar size for $lane lane"
      audit_copy_bytes=$((audit_copy_bytes + sidecar_bytes))
    fi
  done
  if [ "$audit_copy_bytes" -gt "$audit_copy_max_bytes" ]; then
    printf 'unavailable\n' > "$META/$lane-audit-status"
    return
  fi
  local audit_available_bytes
  audit_available_bytes=$(as_root stat -f -c %a:%S "$OUT/runtime") || fail "cannot inspect audit scratch capacity for $lane lane"
  [[ "$audit_available_bytes" =~ ^[0-9]+:[0-9]+$ ]] || fail "invalid audit scratch capacity for $lane lane"
  local audit_available_blocks=${audit_available_bytes%%:*}
  local audit_block_bytes=${audit_available_bytes##*:}
  audit_available_bytes=$((audit_available_blocks * audit_block_bytes))
  if [ "$audit_available_bytes" -lt $((audit_copy_bytes + 8388608)) ]; then
    printf 'unavailable\n' > "$META/$lane-audit-status"
    return
  fi
  if as_root test -e "$audit_dir" || as_root test -L "$audit_dir"; then
    fail "audit export path already exists for $lane lane"
  fi
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
      --property=MemorySwapMax=0 \
      --property=CPUQuota=50% \
      --property=TasksMax=16 \
      --property=LimitNOFILE=64 \
      --property="LimitFSIZE=$audit_copy_max_bytes" \
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
      --property="InaccessiblePaths=$REPO_ROOT $other_root $root/workspace $root/home $root/tmp $root/var-tmp -$root/target -$root/plugin" \
      --property="ReadOnlyPaths=$root" \
      --property="ReadWritePaths=$audit_output" \
      --property=IPAddressDeny=any \
      --property=SocketBindDeny=any \
      --property=StandardOutput=null \
      --property=StandardError=null \
      --property=SystemCallArchitectures=native \
      --property="SystemCallFilter=~bind listen accept accept4 io_uring_setup io_uring_register io_uring_enter" \
      --property=SystemCallErrorNumber=EPERM \
      --property=UMask=0077 \
      --property="WorkingDirectory=$audit_output" \
      /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
        node "$audit_dir/export-tool-audit.mjs" "$root" "$audit_output/audit.json" "$AGENT_ID" "4096"; then
    fail "contained OpenClaw tool-audit export failed for $lane lane"
  fi
  if as_root test -L "$audit_output/audit.json" || ! as_root test -f "$audit_output/audit.json"; then
    fail "contained tool-audit export produced no regular receipt for $lane lane"
  fi
  [ "$(as_root stat -c %s "$audit_output/audit.json")" -le 8388608 ] || fail "contained tool-audit export exceeded its receipt cap for $lane lane"
  local recorder_observed
  recorder_observed=$(as_root node -e 'const fs=require("fs");const value=JSON.parse(fs.readFileSync(process.argv[1],"utf8")).recorderObserved;if(typeof value!=="boolean")throw new Error("missing recorder observation");process.stdout.write(value?"1":"0")' "$audit_output/audit.json") \
    || fail "contained tool-audit export produced an invalid recorder receipt for $lane lane"
  if [ "$recorder_observed" != "1" ]; then
    printf 'unavailable\n' > "$META/$lane-audit-status"
    return
  fi
  as_root install -m 0600 "$audit_output/audit.json" "$trace_dir/audit.json"
  printf 'captured\n' > "$META/$lane-audit-status"
}

run_lane_and_capture baseline "$BASELINE"
capture_tool_audit baseline "$BASELINE"
run_lane_and_capture exercise "$EXERCISE"
capture_tool_audit exercise "$EXERCISE"
date -u +%Y-%m-%dT%H:%M:%S.%NZ > "$META/completed-at"

as_root tar -C "$OUT" -czf "$OUT/raw.tar.gz" meta baseline exercise
as_root chown "$(id -u):$(id -g)" "$OUT/raw.tar.gz"
as_root chmod 0600 "$OUT/raw.tar.gz"
install -d -m 0700 "$DOWNLOAD_OUT"
install -m 0600 "$OUT/raw.tar.gz" "$DOWNLOAD_OUT/raw.tar.gz"
exit 0
`
