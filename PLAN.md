# ClawHub Observatory — MVP Plan

Continuous behavioral evidence for the ClawHub skill ecosystem. Evidence, never verdicts.

The design incorporates the supplied research synthesis and prior-art analysis.

## Product decision

Build the missing dynamic scanner lane for `openclaw/clawscan`, plus the smallest public artifact that proves why the lane matters:

1. `clawscan --scanner behavior` invokes the Observatory CLI and preserves its JSON evidence.
2. The Observatory runs the same synthetic task twice in a disposable OpenClaw environment: once without the target (baseline), then with the skill or plugin installed (exercise).
3. `strace` captures successful and attempted file, process, and network activity across the agent process tree.
4. The analyzer subtracts baseline runtime noise, normalizes private paths/endpoints, correlates synthetic honeytoken interactions across read, write, execute, outbound, and agent-output stages without publishing marker values, and emits `observatory.behavior.v2`. Tool-stage coverage remains explicitly limited because the current metadata ledger has no bounded arguments or results.
5. A zero-dependency dark static page renders the evidence and an optional previous-version diff.

The MVP is one owned skill fixture and one owned plugin fixture end to end, not a premature Hub watcher or top-100 batch service. No ClawHub package is executed during development.

## Positioning guardrails

- Extend Clawscan; do not build another static scanner or competing verdict engine.
- Report observations such as “opened `$HOME/.aws/credentials`” or “attempted a connection to a public endpoint.” Never label a skill safe, malicious, or approved.
- Support skills and native OpenClaw plugins as distinct target kinds. The Clawscan adapter remains skill-facing because that is Clawscan's current contract; plugin scans use the Observatory CLI directly.
- Treat live malicious-looking results as private until coordinated through the ClawHub moderation path.
- Keep raw traces private. The public projection contains normalized observations, counts, hashes, coverage, and limitations—not transcripts, secrets, usernames, private IPs, or raw command arguments.
- Bound the canonical public evidence projection consistently at 64 MiB; full multi-scanner Clawscan render inputs have a separate 256 MiB outer-artifact cap.

## Why baseline and exercise are paired

OpenClaw itself reads workspace/state files, starts helper processes, and calls the configured model endpoint. A single trace would falsely attribute that activity to the skill. Paired runs make the useful unit of evidence the behavioral delta:

- baseline: identical runtime, canaries, task, and model; target absent;
- exercise: identical setup; target present;
- published observation: activity introduced or increased in the exercise run.

This is the MVP’s main technical claim and the foundation for declared-vs-observed capability work later.

## Components

### Clawscan adapter

- Scanner ID: `behavior`.
- Adapter contract follows `internal/runner/socket_scanner.go` and registry registration.
- Requires `CLAWSCAN_BEHAVIOR_CONFIG`; optional `CLAWSCAN_BEHAVIOR_BIN` selects the CLI binary.
- Must run with Clawscan’s `--sandbox off`: the adapter launches a host-side remote executor, while the untrusted target runs only in the remote isolated VM.
- Valid JSON is retained even when the Observatory process exits nonzero, matching other evidence-preserving adapters.

### Observatory CLI

- `observatory scan --config <path> <target>`: stage a skill or native plugin, execute, analyze, emit JSON.
- `observatory analyze ...`: turn fixture or captured traces into the same evidence schema without provisioning.
- `observatory render --input <json> --output <dir> [--previous <json>]`: create a self-contained dark evidence page and public JSON.

### Disposable runtime

- Crabbox provisions and executes on Proxmox; it is the control plane, not the security boundary.
- Live orchestration, descriptor-pinned no-follow target staging, and hardened site rendering require a Linux control host; other control-host platforms fail closed in the MVP.
- A dedicated unprivileged VM template supplies OpenClaw, Node, `strace`, systemd, and ordinary target dependencies.
- Each scan gets new OpenClaw state/workspace roots and synthetic credentials only.
- The generated OpenClaw config uses an Observatory-owned bounded loopback relay for the lab’s OpenAI-compatible local model endpoint and a narrow coding tool surface with messaging, scheduling, delegation, and external account integrations absent.
- The MVP requires a literal IPv4 model endpoint; IPv6 is rejected until neighbor/router discovery can be admitted without weakening default-deny rules.
- The exercise is bounded by wall-clock timeout, memory, CPU, process, output-file, and bundle limits and a single representative synthetic task.
- Before either lane starts, the disposable VM receives a unique nftables default-drop policy allowing established management traffic, new SSH only from the active literal-IPv4 management peer, DHCP, the exact relay/sink loopback ports for the hostile UID, and the exact model IP/port only for the relay control UID. Each lane adds a transient systemd cgroup with a hard whole-cgroup kill deadline, read-only host OS, private home/tmp/devices/IPC, no AF_UNIX sockets, zero swap, bounded file descriptors, namespace and privilege restrictions, bind denial, and cgroup IP allowlisting for relay/sink loopback addresses only.
- The child environment is rebuilt from an empty environment. The target never inherits Crabbox, host, channel, or operator credentials.

### Evidence analyzer

- Captures `open/openat`, create/write/link/delete/rename, successful and failed `execve`, connect/send attempts, and ordinary TCP/UDP `write`/`writev` traffic identified through annotated socket descriptors.
- Publishes executable names but not raw argv.
- Normalizes run paths to `$WORKSPACE`, `$STATE`, `$HOME`, and `$SKILL`.
- Resolves relative path operations against a PID-aware current-directory model,
  including fork inheritance and `CLONE_FS` sharing.
- Replaces private-network addresses in every published observation subject with a marker; separately labels the configured model endpoint as control-plane traffic.
- Suppresses dynamic-loader/locale noise and reports parser blind spots explicitly.
- Records target SHA-256, copied/omitted file manifest, runtime versions, exit codes, duration, observation counts, canary class and stage interactions, coverage limitations, the per-run applied firewall hash, and a stable firewall-policy digest.
- Binds every capture to a canonical digest of the effective prompt, model, endpoint allowlist, isolation receipt, resource limits, and runtime configuration; offline re-analysis rejects configuration drift.

## Security boundary

Crabbox’s own trust model says it is a developer execution tool, not hostile multi-tenant isolation. Therefore live mode fails closed unless the operator config explicitly attests all of the following:

- disposable Proxmox VM, not a reused host;
- dedicated non-LAN network;
- default-deny or sinkholed egress with only the model endpoint allowed;
- unprivileged guest user whose only group is a same-name dedicated primary group, with no `sudo` and no mounted host/runtime sockets;
- no real credentials, channels, user memory, SSH keys, or production OpenClaw state in the guest;
- bounded runtime and artifact-size limits.
- per-lane bounded tmpfs storage, preventing target writes from exhausting the guest disk.

Live validation also requires an explicit full-clone template ID, a dedicated PVE `vmbr0` through `vmbr9999` bridge, six affirmative isolation controls, a `0600` Crabbox config pinned to Proxmox/Linux/full-clone with insecure TLS explicitly disabled, a bounded validated PEM CA bundle used as the exclusive trust anchor, and a non-root `/work/...` provisioner root. The exact CA digest is bound into the capture and isolation receipts. User-supplied Crabbox arguments and ambient TLS or `CRABBOX_*` overrides are rejected or stripped.

The example config leaves live mode disabled. This build will not run a real VM until those controls are independently verified.

## Evidence schema: `observatory.behavior.v2`

Top-level sections:

- `captureConfigSha256`: public digest binding the effective capture conditions
  and versioned capture/isolation/trace-analysis protocol revision;
- `target`: public lineage (when configured), source label, content digest, file/byte counts, omissions;
- `run`: ID, status, timestamps, executor/runtime metadata, lane exit codes;
- `exercise`: prompt digest and bounded scenario metadata (not transcript content);
- `observations`: kind, operation, normalized subject, baseline/exercise/delta
  counts, outcome; file descriptor acquisition is labeled `open-for-*` and is
  never presented as a completed read or write;
- `canaries`: canary ID, synthetic class (`identity`, `memory`, or `credential`), surface, aggregate counts, and ordered per-stage baseline/exercise/delta counts, never marker values;
- `persistence`: a curated `selected-persistence-surfaces` catalog plus findings
  that distinguish attempted-but-denied persistence operations from successful
  residual changes confirmed by a before/after lane inventory; no reboot cycle,
  no verdict, and no claim of exhaustive host persistence detection;
- `redirectProbes`: per-probe instruction-redirection escalation. Observatory
  seeds a bounded, fixed set of synthetic injected-instruction markers into
  workspace content and deterministically exposes them by augmenting every
  effective lane prompt (shared by both lanes) with a neutral read instruction. It
  reports paired baseline/exercise counts for three tiers — `read`, `repeated`,
  and `deviated` — plus the highest tier reached (`escalation`), the highest tier
  attributable over baseline (`attributed`), and an `exercised` flag that is true
  only when the exercise lane actually read the seeded file. Sentinel actions are
  harmless (a reserved TEST-NET endpoint or a synthetic sentinel file) and cannot
  reach a real service. A read or repeat is never treated as prompt injection; only
  a positive `deviatedDelta` is;
- `coverage`: captured syscall families, ordered canary-stage coverage and source receipts (with tool coverage always limited), an explicit `selected-mvp-syscalls`
  scope (never an exhaustive Linux-audit claim), the redirect probe scope/count,
  the count of probes actually exercised (`redirectProbesExercised`; a missing
  read lowers coverage rather than implying resistance), the redirect deep-mode
  flag, and concrete limitations;
- `toolCallLedger`: a paired baseline/exercise ledger of actual OpenClaw tool
  calls, projected after each lane exits by a contained, read-only query of
  OpenClaw's canonical `audit_events` SQLite table
  (`tool.action.started`/`finished`). The exporter has no network, sees lane
  state read-only, and can write only its bounded receipt. Each lane reports a coverage verdict
  (`incomplete`/`unavailable`) and ordered calls with a safe ordinal,
  compact tool name, terminal state, error code, and relative timing. Raw tool
  call ids are never published; argument/result summaries are explicitly
  unavailable because the metadata-only ledger carries no arguments and the
  redacted trajectory cannot guarantee canary safety. Because the lane owns its
  OpenClaw state database and audit rows are not integrity-signed, this ledger
  is supplemental metadata rather than sole-source grading evidence. OpenClaw
  audit persistence is best-effort, so captured rows never claim complete
  coverage. An empty audit table plus an observed recorder lifecycle means only
  that zero tool-call rows were observed, not that zero calls occurred;
- `runtimeTimeline`: an ordered, per-lane runtime **syscall** timeline (not tool
  calls) for both lanes, with contiguous sequence numbers, normalized secret-safe
  subjects, completion/denial/error outcomes, path-based canary attribution, and
  relative `offsetMs` timing published only when the capture provides monotonic
  per-event timestamps. Each lane is bounded and flags truncation; the timeline
  never carries raw arguments, canary values, private addresses, or host paths.

The schema deliberately has no verdict, severity, score, or recommendation field.
Redirect escalation tiers are observed-behavior labels, not a safety verdict.

## MVP acceptance criteria

- Clawscan lists and dispatches `behavior` through the registry.
- Adapter errors are secret-redacted; valid evidence survives nonzero scanner exit.
- Trace parser proves baseline subtraction for file, process, network, failed-attempt, and canary-stage cases. Owned typed sink receipts and agent stdout exercise their separate bounded private seams, while tool metadata remains non-authoritative.
- Target staging rejects symlinks/Git attribute controls, records and digest-binds skipped `.git` metadata, bounds files plus directories plus omissions, and restores exact source permission modes and empty directories after Git transport.
- Network evidence includes filesystem and Linux abstract Unix-domain sockets, and site rendering pins a no-follow output directory and refuses symlinked or hard-linked fixed output files.
- Skill frontmatter names are validated as canonical OpenClaw allowlist IDs and used consistently for staging, prompting, and agent visibility; batched network evidence preserves repeated destinations and partial-send outcomes.
- Live scan refuses to start when isolation attestation or required runtime configuration is absent.
- Renderer produces a self-contained dark page with current evidence and coverage limits; previous-version trace and canary deltas require matching stable lineage, effective-capture digest, runtime/isolation receipts, prompt, and coverage.
- Owned skill and plugin fixtures both traverse staging, capture parsing, target-digest binding, normalization, evidence generation, and rendering; generated plugin config is accepted by the installed OpenClaw CLI.
- Focused tests, full `go test -count=1 ./...`, `go vet ./...`, CLI smoke tests, docs build, and repository autoreview pass.

## Explicitly outside the MVP

- ClawHub catalog watcher, queue, retries, or top-100 scheduling;
- public hosting, RSS, moderation alerts, and RFC integration;
- browser/GUI automation;
- packet payload publication or full DNS attribution;
- malware verdicts, risk scores, automatic blocking, or publisher reputation;
- live Proxmox validation before the isolation boundary is verified.

## After the MVP

1. After explicit VM-teardown approval, validate the owned probe skill and probe plugin in the real isolated Proxmox lane.
2. Add declared-capability input and observed-capability diffs for ClawHub RFC #2944.
3. Add version-keyed storage and update diffs.
4. Add catalog watching, bounded concurrency, retry policy, and private moderation routing.
5. Publish a small pilot, then propose the adapter upstream with copied real-behavior proof.
