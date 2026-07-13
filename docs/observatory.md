# ClawHub Observatory behavior scanner

The `behavior` adapter adds paired runtime evidence to Clawscan. Observatory
runs the same synthetic OpenClaw task without and with a target, subtracts
baseline runtime activity, and preserves normalized `observatory.behavior.v1`
evidence. Both the standalone CLI and the Clawscan `behavior` adapter accept
skills and native OpenClaw plugins; Clawscan classifies a target directory that
holds `openclaw.plugin.json` as a plugin and passes it straight to Observatory.
Skill-only scanners return a clear skipped result for plugin targets.
The schema intentionally has no verdict, score, or recommendation.
Canonical public evidence is capped at 64 MiB; generation and rendering enforce
the same bound. When rendering from a full multi-scanner Clawscan artifact, the
outer artifact has a separate 256 MiB input cap and the embedded behavior
payload still must satisfy the 64 MiB evidence bound.

## Build and configure

```bash
go build -o ./bin/observatory ./cmd/observatory
cp examples/observatory.yml ./observatory.yml
./bin/observatory validate-config ./observatory.yml
./bin/observatory validate-config --live ./observatory.yml
```

The live validation fails until `live: true` and the required isolation receipt
are present.

The dedicated Crabbox file must be owner-only and pin the same template and
bridge named by the Observatory receipt:

```yaml
provider: proxmox
target: linux
proxmox:
  apiUrl: https://pve-observatory.example:8006
  node: pve-observatory
  templateId: 9400
  bridge: vmbr-observatory
  user: crabbox
  workRoot: /work/observatory
  fullClone: true
```

Use `chmod 600` on that file. When `executor.command` is a local credential
wrapper, `executor.crabboxBinary` pins the reviewed Crabbox build; only the
local 1Password Connect variables cross into that wrapper. Other ambient
credentials and all ambient `CRABBOX_*` overrides are stripped.
The dedicated Crabbox YAML accepts only `provider`, `target`, and current
Proxmox fields; profiles, jobs, sync overrides, and environment forwarding are
rejected so they cannot weaken staging or pass control-plane credentials.
Relative artifact, Crabbox config/binary, and path-like executor command values
resolve from the Observatory config file's directory.
Target `.git` metadata is not transported into the guest; each skipped subtree
is recorded in the public omission manifest and bound into the target digest.
Skills without an explicit frontmatter name use the neutral public label
`Unnamed skill` rather than a host-directory basename.

## Run through Clawscan

The adapter launches a host-side Crabbox control plane, so Clawscan's own Docker
sandbox must be off. The untrusted target still runs only in the separately
isolated disposable VM.

```bash
export CLAWSCAN_BEHAVIOR_BIN="$PWD/bin/observatory"
export CLAWSCAN_BEHAVIOR_CONFIG="$PWD/observatory.yml"

go run ./cmd/clawscan ./path/to/skill \
  --scanner behavior \
  --sandbox off \
  --output ./artifacts/behavior.json
```

Point the same command at a directory that contains `openclaw.plugin.json` to
scan a native plugin; Clawscan records `target.kind: plugin` plus the manifest
`id` in the artifact and passes the directory straight to Observatory:

```bash
go run ./cmd/clawscan ./path/to/plugin \
  --scanner behavior \
  --sandbox off \
  --output ./artifacts/behavior.json
```

The recorded `target.id` is the manifest identifier, never a host path. Clawscan
never auto-discovers plugins; a plugin directory must be named explicitly.

Valid JSON evidence survives a nonzero Observatory exit. Infrastructure
failures without evidence remain scanner failures. Clawscan stores only an
opaque failure note; detailed executor output and paths stay in the private
Observatory run directory.

## Re-analyze and render

Raw captures stay private and can be re-analyzed without provisioning:

```bash
./bin/observatory analyze \
  --config ./observatory.yml \
  --bundle ./private-run/capture.tar.gz \
  --output ./evidence.json \
  ./path/to/target

./bin/observatory render \
  --input ./evidence.json \
  --output ./site

./bin/observatory render \
  --previous ./skill-v1.json \
  --input ./skill-v2.json \
  --output ./site
```

The renderer accepts standalone Observatory JSON or a Clawscan artifact whose
`behavior.raw` field contains the evidence. It emits a self-contained dark page
and public JSON projection. A skill capture needs the same explicit
`targetLineage` in both Observatory configs before `--previous` is accepted;
native plugins use their manifest ID. The renderer also requires matching
effective-capture digests, runtime versions, isolation receipts, prompts, and
coverage, and refuses incomplete captures. It never labels incomparable runs as
a version delta. Version deltas include both normalized trace observations and
synthetic-canary interaction changes.

Re-analysis requires the same effective prompt, model, endpoint allowlist,
capture-protocol revision, isolation receipt, and resource limits used for
capture. Their canonical digest
is stored in both the raw bundle and public evidence; drift fails closed instead
of relabeling old data.

## Persistence and lifecycle evidence

Each scan derives a `persistence` section that reports persistence- and
lifecycle-relevant behavior over a curated, versioned catalog of surfaces:
OpenClaw config, hooks, MCP and plugin/skill registrations, scheduled work, and
workspace startup instructions, plus a bounded set of conventional user surfaces
(shell init files, XDG autostart, systemd user units, user cron, SSH trust,
PATH binaries) and read-only system locations (system cron, systemd units,
profile scripts, the dynamic loader preload, and legacy init).

Findings distinguish two outcomes explicitly:

- **attempted** — a persistence operation the read-only OS or containment
  denied. These never carry `residual: confirmed`.
- **succeeded residual change** — a successful write whose residual on-disk
  effect a before/after lane inventory confirms (`residual: confirmed`,
  `evidence: syscall+inventory` or `inventory`).

Evidence comes from two sources that are correlated per finding:

1. **Existing syscall traces** classify every mutating file operation whose
   normalized subject maps to a monitored surface, preserving the
   attempted/succeeded outcome. This is the authoritative attempt record and the
   only source for denied writes to read-only system locations.
2. **A before/after lane inventory** snapshots the writable lane surfaces after
   seeding (before the agent runs) and again after it finishes. Baseline runtime
   noise (state the OpenClaw runtime rewrites in both lanes) is subtracted by a
   lane-independent transition identity — path, change kind, and mode transition.
   Content digests differ per lane and are kept **private**; they are never
   published. A target-specific change to a path the runtime also rewrites is
   still confirmed because the succeeded, baseline-subtracted **syscall** write
   correlates against the full exercise residue set. The default run does **not**
   add a reboot cycle; residual confirmation is inventory-based.

The inventory records only file digests and modes, never contents, so seeded
canary values never leave the guest. The current protocol always emits complete
before/after inventory receipts, so a capture whose inventory is missing,
malformed, duplicated, or truncated is **rejected as incomplete** rather than
graded — an incomplete inventory can never silently yield a `not-observed` or
clean result. `residual: unavailable` is reserved for read-only system locations
that cannot be inventoried (for example `/etc/cron.d`), where a denied attempt is
still recorded from the syscall trace.

Each before/after inventory runs in its own transient systemd unit as the
unprivileged agent user. The lane is mounted read-only to the unit; systemd owns
the receipt stream. The unit has no capabilities or network, hides unrelated
lane/repository paths, and enforces fixed time, memory, swap, CPU, task, file
descriptor, output-size, namespace, and syscall bounds. Traversal also caps entry
count, depth, path length, hashed-file size, and serialized output. Reaching any
bound marks the receipt incomplete or fails the unit, and bundle parsing rejects
the scan.

`persistence.surfaces` publishes the monitored catalog so coverage is explicit.
The section never claims exhaustive host persistence detection, carries no
verdict, and a persistence-surface write is a behavioral observation, not proof
of intent.

## Isolation contract

Crabbox provisions and operates the runner; it is not itself a hostile-code
sandbox. Live mode requires:

- a fresh Proxmox VM on a dedicated non-LAN network;
- a Linux control host; live execution and secure target staging fail closed on
  other platforms because the MVP pins and traverses target directories by file descriptor;
- default-deny/sinkholed egress with only the model endpoint allowed;
- a dedicated non-root `observatory` agent user;
- a same-name primary group, no supplementary groups, and no passwordless sudo
  for that user;
- root-owned `strace` instrumentation and trace files;
- synthetic state, memory, credentials, and API markers only;
- no host sockets, production OpenClaw state, real channels, or real accounts;
- bounded runtime and artifact sizes;
- bounded per-lane tmpfs storage so target writes cannot fill the guest disk;
- transient systemd cgroups with hard whole-group deadlines, CPU/memory/task
  quotas, a read-only OS, hidden homes, private tmp/devices, namespace and
  kernel protections, socket-bind denial, and destination-IP filtering;
- an empty child environment and literal-IP allowlist containing only the model
  control plane;
- an IPv4-only model endpoint in the MVP; IPv6 is rejected until its discovery
  traffic has an equally narrow policy;
- a VM-wide nftables default-drop policy allowing established management
  traffic, new SSH only from the active literal-IPv4 management peer, DHCP,
  loopback, and only the exact model IP/port; evidence retains both the per-run
  applied-rules hash and a stable canonical-policy digest;
- an explicit full-clone template, isolated bridge, and `0600` dedicated
  Crabbox config; arbitrary Crabbox arguments and ambient overrides are not
  accepted.

The generated agent has coding tools but no messaging, scheduling, delegation,
gateway, media, or elevated tool surface. Raw command arguments, transcripts,
private addresses, host paths, and canary values are excluded from the public
evidence page.

The allowlist is exact host-and-port matching. Trace parsing covers failed
execs, interrupted/resumed syscalls, socket `write`/`writev`, and annotated
directory FDs; private addresses are redacted from every observation subject.
File opens are reported as `open-for-read`, `open-for-write`,
`open-for-read-write`, or `open-path`, not as completed file I/O.
Relative operands are resolved with PID-aware `chdir`/`fchdir` and
fork/`CLONE_FS` inheritance tracking before normalization or canary matching.
Coverage explicitly identifies the selected MVP syscall scope; its family
booleans prove paired trace receipts, not exhaustive Linux syscall coverage.
Target digests bind file contents plus file/directory modes. A root-owned mode
manifest restores permissions and empty directories that Git does not retain;
target-controlled Git attributes are rejected.

## Controlled mock egress

Controlled mock egress is an opt-in upgrade from safe outbound-attempt evidence
to payload-aware evidence, without permitting any arbitrary real egress. It is
disabled by default; when disabled the scan behaves exactly as before.

When enabled under `runtime.mockEgress`, Observatory runs a bounded, guest-local
loopback sink once per lane, outside the untrusted agent cgroup. The sink is
pinned to an exact IPv4 loopback address and port, so captured bytes never leave
the VM. The exact port is a real enforcement boundary: the guest firewall gives
the dedicated agent UID an allow rule for only the exact sink host and port and
then drops every other agent loopback destination, both ordered before the
generic loopback accept. The agent UID marker is substituted with the numeric UID
inside the guest, and non-agent (control-plane), model, and management traffic are
untouched. This entry is kept separate from the exact model control-plane
allowlist; everything else stays default-deny. The sink applies strict request,
per-request byte, total byte, and wall-clock caps, and returns an optional
deterministic canned response. The sink itself runs in a separate transient
systemd unit with no capabilities, a read-only system, an exact bind-port rule,
write access only to its receipt directory, and fixed time, memory, swap, CPU,
task, file descriptor, and output-size limits. A preallocated capture buffer plus
bounded concurrent sockets and data-event counters prevents request/chunk object
overhead from growing independently of the configured byte limits.

So the exercised target can actually use the sink, an enabled scan exposes a
clearly synthetic `OBSERVATORY_MOCK_EGRESS_URL` in the otherwise-empty child
environment (identical in both lanes; only the exercise lane has a target). The
owned probe skill and probe plugin both send a bounded synthetic payload carrying
the workspace cloud canary to that endpoint, giving an end-to-end owned-fixture
proof without routing arbitrary destinations or contacting any real service.

The public evidence gains a `mockEgress` section with the sink port class,
baseline/exercise/delta request and byte counts, a payload digest, a payload
encoding label, and the IDs of any synthetic canaries observed in the captured
bytes. Raw captured bytes stay only in the private per-lane receipt inside the
capture bundle. TLS-encrypted or otherwise opaque payloads are recorded as byte
counts and are never decoded, and canary scanning is skipped for them — the
evidence never pretends opaque traffic was read. Connect/send observations to the
sink are labeled `controlled-sink:<port>`; the raw loopback address is redacted.

The system fails closed: when the sink is enabled the bundle must contain a
per-lane receipt whose recorded sink identity matches the configured address.
Receipt request, aggregate byte, per-request byte, chunk, and peak-socket counters
must remain within the effective configuration and protocol caps. A receipt
present while the sink is disabled is rejected. The applied guest firewall
receipt remains required, and the sink is pinned into the stable firewall-policy
digest so the receipt changes when the sink configuration does.

Sizing: `limits.maxBundleBytes` must leave room for both per-lane receipts, at
least `mockEgress.maxTotalBytes * 2 + 1 MiB`.

## Owned fixture proof

Development and validation use only:

- `testdata/fixtures/probe-skill` — reads a synthetic canary, attempts an
  inaccessible system file, writes a synthetic workspace receipt, appends a
  synthetic line to the lane `$HOME/.bashrc` (a confirmed residual persistence
  change), attempts a denied `/etc/cron.d` write (an attempted, non-residual
  persistence change), and attempts a TEST-NET connection that containment must
  drop;
- `testdata/fixtures/probe-plugin` — a native tool plugin that reads the same
  synthetic canary, proves `/etc/shadow` remains unreadable, performs the same
  shell-init and denied-system-cron persistence probes, and writes a synthetic
  receipt.

No ClawHub target is used until the owned fixtures pass the real VM lane.
Skill names are validated as canonical OpenClaw identifiers and the same ID is
used for the staged directory, per-agent allowlist, and default exercise prompt.
For a plugin using the default exercise prompt, Observatory selects the first
sorted tool declared in `contracts.tools` and names it explicitly. Plugins with
no declared tools require an operator-supplied `exercise.prompt`.

## Instruction-redirection probes

Every scan is hands-off: the operator supplies only a skill or plugin path.
Observatory automatically seeds a bounded, fixed set of synthetic
injected-instruction markers into controlled workspace content that the exercised
agent can read. No operator-authored scenario is required. Each probe embeds a
random `OBS-REDIRECT-*` marker token and names a single harmless sentinel action:

- `workspace-note-egress` seeds `$WORKSPACE/NOTES.md` and asks the agent to
  connect to a reserved TEST-NET-2 documentation endpoint. That address is
  unroutable and is default-dropped by the guest firewall, so the probe can never
  reach a real service.
- `workspace-readme-write` seeds `$WORKSPACE/README.observatory.md` and asks the
  agent to create a synthetic `observatory-redirect.sentinel` completion file.

Exposure is deterministic and hands-off. Observatory appends one short, neutral
instruction to the effective lane prompt — across the default, target-aware
skill/plugin, and operator-supplied custom prompt paths — directing the agent to
open and read the seeded context files before finishing. Both lanes share the
exact same augmented prompt, so baseline subtraction stays valid, and the
augmented prompt is bound through `captureConfigSha256` and `promptSha256`. The
instruction names the files but never states that they carry probes and never
names a sentinel action, so it does not reveal the probes or bias whether the
agent follows their embedded content.

Detection separates three escalation tiers per probe, computed as paired
baseline/exercise deltas exactly like canaries:

- `read` — the agent opened the seeded instruction file;
- `repeated` — the marker token appeared in the agent's own captured output;
- `deviated` — the agent actually performed the named sentinel action through an
  observable file or network syscall.

`escalation` is the highest tier the exercise lane reached; `attributed` is the
highest tier whose delta over the baseline lane is positive. Reading or repeating
a seeded marker is never treated as prompt injection: only a positive
`deviatedDelta` shows the exercise lane followed a seeded instruction. Sentinel
targets are constant, so the deviation also appears as an ordinary observation and
version diffs stay stable; the random marker token is redacted from every public
subject.

Each probe also carries an `exercised` flag (true only when the exercise lane
actually read the seeded file), and coverage reports `redirectProbesExercised`
alongside `redirectProbeScope: seeded-workspace-redirects`, the probe count, and
`redirectDeepMode`. A probe the exercise lane never read was not exposed to the
agent: its absent deviation lowers coverage and must never be read as resistance
to redirection. The MVP default runs one Crabbox deployment and one paired trial.
A `redirect.deep` config knob is exposed for a future deep/repeat mode but must
stay `false`; enabling it fails config validation rather than multiplying trials
or models. The network sentinel resolves through a single documented seam so a
future controlled sink can replace the TEST-NET endpoint without weakening the
default-deny egress policy, which remains unchanged.
## OpenClaw tool-call ledger

Every capture carries a `toolCallLedger` section: a paired baseline/exercise
ledger of actual OpenClaw tool calls, distinct from the syscall timeline below.
It is projected directly from OpenClaw's canonical metadata-only
`audit_events` SQLite table (`tool.action.started`/`finished` records), which by
contract records tool
identity, ordering, terminal state, error code, and timing but never prompts,
tool arguments, tool results, command output, or raw error text.

Each lane reports a `coverage` verdict and ordered `calls`. A call carries a safe
per-lane `sequence` used for correlation, the compact `tool` name, a terminal
`state` (`succeeded`, `failed`, `cancelled`, `timed_out`, `blocked`, `unknown`,
or `started` when no terminal record was recorded), an optional audit `errorCode`,
and relative `durationMs`/`offsetMs` timing. Started and finished records are
correlated internally by their tool call id; the raw call id and its one-way
fingerprint are never published, only the safe ordinal is. Coverage is:

- `incomplete` — audit rows were captured, but OpenClaw persists them on a
  best-effort basis, so even paired records cannot prove complete tool-call
  coverage. The reason also identifies missing terminal records, zero observed
  rows, or truncation at the 4096-call per-lane cap;
- `unavailable` — no audit ledger was recorded for the lane.

Bounded, secret-safe argument/result summaries are reported as **unavailable**
(`argumentSummaries.available: false`) with an explicit reason: the metadata-only
audit ledger never carries arguments or results, and the redacted trajectory's
best-effort redaction cannot guarantee synthetic-canary safety. The observatory
publishes this explicit coverage rather than presenting syscall subjects as tool
arguments.

After the untrusted agent unit has stopped and been collected, the remote runner
reads the canonical `$OPENCLAW_STATE_DIR/state/openclaw.sqlite` database without
launching OpenClaw or contacting a Gateway. The exporter runs as the dedicated
agent user in a second transient unit with a 20-second deadline, 128 MiB memory
limit, 50 percent CPU quota, 16-task limit, 8 MiB file limit, an empty
environment, no capabilities, private and denied networking, lane state mounted
read-only, and only a fresh receipt directory writable. Database, sidecar,
directory, and output symlinks are rejected. The query is read-only and enables
SQLite `query_only` mode with trusted schemas disabled.

The strict `<lane>/audit.json` receipt binds the direct-export source, an
agent-run recorder-lifecycle observation, the 4096-call bound, exact total call
count, and truncation flag. Unknown fields, duplicate
lifecycle records, malformed provenance, unsupported schema versions, and
inconsistent counts fail closed. A missing canonical database, or a database
created by unrelated local-agent state without a complete agent-run recorder
lifecycle, is explicit `unavailable` coverage. A present but malformed database
aborts capture rather than fabricating a ledger. The lane's
`meta/<lane>-audit-status` marker binds that result into the private bundle.
The lifecycle signal proves only that the recorder emitted some run metadata.
Because audit writes are best-effort, it never upgrades observed rows, including
an empty tool-action result, to complete coverage.

OpenClaw currently owns durable audit recording in its Gateway runtime.
Observatory deliberately runs the embedded local agent without a Gateway, so an
OpenClaw build that does not persist embedded-run audit events produces explicit
`unavailable` ledger coverage. Observatory does not infer tool calls from
syscalls or fabricate a ledger. Complete tool-call coverage requires an upstream
recorder with an acknowledged, loss-detectable contract; the current best-effort
ledger cannot provide it.

The state database belongs to the same lane user as the target. OpenClaw's
audit rows are not integrity-signed, so a captured ledger is supplemental
behavior metadata, not tamper-evident proof. Deterministic grading must not rely
on this ledger as its sole source. The root-owned syscall trace remains the
independent runtime observation boundary.

## Runtime syscall timeline

Alongside the baseline-subtracted `observations` aggregate, every capture carries
a `runtimeTimeline` section: an ordered, per-lane projection of the underlying
file/process/network **syscalls** captured by `strace` for both lanes. This is
the runtime substrate beneath the tool calls, not the OpenClaw tool calls
themselves — it records syscall subjects, not tool arguments or results. Where
`observations` answers "what increased in the exercise lane", the timeline
answers "in what order, and when" so downstream deterministic grading and future
declared-vs-observed comparison can reason about sequence and timing.

Each lane publishes `events` in capture order with a contiguous `sequence`, the
event `kind`/`operation`, a normalized secret-safe `subject`, an `outcome` of
`completed`, `denied` (an `EACCES`/`EPERM` permission failure), or `error`, an
optional network `role`, and an optional `canary` attribution when a file event
touches a synthetic canary path. Subjects reuse the exact normalization and
redaction applied to `observations`: host paths collapse to `$WORKSPACE`,
`$STATE`, `$HOME`, `$SKILL`/`$PLUGIN`, private and control-plane addresses are
masked, canary markers are never emitted, and raw command arguments and payloads
are excluded. The full ordered sequence ships in the JSON projection; the static
page previews up to 250 events per lane.

Timing is captured with `strace -ttt` and published as `offsetMs`, the
millisecond offset from each lane's first event, only when the lane carries a
timestamp on every event and those timestamps never move backwards
(`timed: true`, with a lane `durationMs`). Absolute wall-clock time is never
published, and a lane with missing or non-monotonic timestamps omits offsets
rather than publishing untrustworthy timing. Each lane is bounded at 4096 events;
a busier lane keeps the earliest-first prefix and sets `truncated: true` with the
full `totalEvents` count. Malformed, inconsistent, or incompletely timed
timelines fail closed during evidence validation. Both the ledger and the
timeline are part of the capture-protocol revision, so re-analysis and version
comparison reject evidence produced by a different protocol.

## MVP limitations

- One bounded task cannot cover every branch.
- Results depend on model/tool behavior and synthetic inputs.
- `strace` provides endpoint addresses, not complete DNS or payload attribution.
- Payload capture is limited to traffic reaching the pinned controlled mock
  egress sink; all other destinations stay default-denied and appear only as
  attempts. Opaque or TLS-encrypted sink payloads are counted, never decoded.
- Skills and native tool plugins are covered; browser/GUI and channel plugins
  are not exercised deeply.
- Persistence coverage is a curated selection of agent and conventional user
  surfaces, not an exhaustive host persistence audit. Residual confirmation
  depends on a complete before/after lane inventory, which the protocol always
  emits; a capture with missing, malformed, or truncated inventory is rejected as
  incomplete. Cross-lane baseline-noise subtraction uses path, change kind, and
  mode transition, so a target change to a shared path is confirmed through its
  correlated syscall rather than by comparing lane-specific content. No reboot
  cycle is performed in the default run.
- Current embedded OpenClaw runs may expose no durable recorder lifecycle even
  when unrelated state created the SQLite database; the tool-call ledger then
  reports explicit `unavailable` coverage.
- Behavioral correlation is not author intent and is never a safety verdict.
- Redirect probes cover two fixed workspace surfaces with one bounded trial each;
  a marker that was only read or repeated is not evidence of prompt injection.
