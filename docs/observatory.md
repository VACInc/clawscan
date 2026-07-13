# ClawHub Observatory behavior scanner

The `behavior` adapter adds paired runtime evidence to Clawscan. Observatory
runs the same synthetic OpenClaw task without and with a target, subtracts
baseline runtime activity, and preserves normalized `observatory.behavior.v1`
evidence. The standalone CLI accepts skills and native OpenClaw plugins; the
Clawscan adapter remains skill-facing.
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

## Owned fixture proof

Development and validation use only:

- `testdata/fixtures/probe-skill` — reads a synthetic canary, attempts an
  inaccessible system file, writes a synthetic workspace receipt, and attempts
  a TEST-NET connection that containment must drop;
- `testdata/fixtures/probe-plugin` — a native tool plugin that reads the same
  synthetic canary, proves `/etc/shadow` remains unreadable, and writes a
  synthetic receipt.

No ClawHub target is used until the owned fixtures pass the real VM lane.
Skill names are validated as canonical OpenClaw identifiers and the same ID is
used for the staged directory, per-agent allowlist, and default exercise prompt.
For a plugin using the default exercise prompt, Observatory selects the first
sorted tool declared in `contracts.tools` and names it explicitly. Plugins with
no declared tools require an operator-supplied `exercise.prompt`.

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
fingerprint are never published — only the safe ordinal is. Coverage is:

- `complete` — a claimed-complete ledger where every call has both a started and
  a terminal record (a lane with no tool calls is complete with zero calls);
- `incomplete` — a claimed-complete ledger missing a terminal record for a call,
  or truncated at the 4096-call per-lane cap;
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

The strict `<lane>/audit.json` receipt binds the direct-export source, 4096-call
bound, exact total call count, and truncation flag. Unknown fields, duplicate
lifecycle records, malformed provenance, unsupported schema versions, and
inconsistent counts fail closed. A missing canonical database is explicit
`unavailable` coverage; a present but malformed database aborts capture rather
than fabricating a ledger. The lane's `meta/<lane>-audit-status` marker binds
that result into the private bundle.

OpenClaw currently owns durable audit recording in its Gateway runtime.
Observatory deliberately runs the embedded local agent without a Gateway, so an
OpenClaw build that does not persist embedded-run audit events produces explicit
`unavailable` ledger coverage. Observatory does not infer tool calls from
syscalls or fabricate a ledger. Complete tool-call coverage for that runtime
requires an upstream-supported embedded recorder or a separately reviewed
Gateway execution topology.

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
- Skills and native tool plugins are covered; browser/GUI and channel plugins
  are not exercised deeply.
- Current embedded OpenClaw runs may expose no durable tool audit database; the
  tool-call ledger then reports explicit `unavailable` coverage.
- Behavioral correlation is not author intent and is never a safety verdict.
