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

## Hands-off version-diff history

Every scan of a completed capture records its public evidence in a bounded
local history keyed by the stable lineage (skills) or manifest ID (plugins).
On the next release, `observatory scan` selects the latest strictly comparable
prior evidence for that identity and renders or emits an evidence-based version
delta — no version, target, or history is ever fetched from the network.

```bash
# Record this scan and render a site that auto-includes the latest comparable
# predecessor delta. Also write the structured delta document.
./bin/observatory scan --config ./observatory.yml \
  --site ./site --delta ./version-delta.json ./path/to/skill

# Render a delta later from stored history instead of a hand-picked file.
./bin/observatory render --input ./skill-v2.json --output ./site \
  --auto-previous --config ./observatory.yml
```

The evidence JSON on stdout is unchanged; delta selection is a side channel and
never pollutes the Clawscan adapter contract. The current run is recorded before
selection and is excluded from its own predecessor search. Selection reuses the
same comparability gate as `--previous`: a mismatched capture protocol,
isolation receipt, prompt, model, resource limits, or target kind/identity is
skipped rather than diffed, and a completed run with no comparable predecessor
simply renders current evidence only. Corrupt history (an unparseable index or a
damaged snapshot) fails closed: `scan` omits the delta with a diagnostic, and an
explicit `render --auto-previous` returns an error. The structured
`observatory.version-delta.v1` document carries the behavioral `changes` plus a
reserved, nil-by-default `grade` field so a future external grade signal can be
integrated alongside — never in place of — the evidence-based delta.

History is configured under `history` in the Observatory YAML:

```yaml
history:
  enabled: true   # default; set false to disable recording and diffs
  retain: 10      # bounded snapshots kept per stable lineage/plugin ID (1..1000)
```

Retention prunes only the private history snapshots; canonical per-run artifact
directories and raw capture bundles are never removed. History snapshots live
under `<artifactsDir>/history` with owner-only permissions and contain only the
public evidence projection, preserving the private/public artifact boundary.
Use `--no-history` to skip recording and diffing for a single run.

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

## MVP limitations

- One bounded task cannot cover every branch.
- Results depend on model/tool behavior and synthetic inputs.
- `strace` provides endpoint addresses, not complete DNS or payload attribution.
- Skills and native tool plugins are covered; browser/GUI and channel plugins
  are not exercised deeply.
- Behavioral correlation is not author intent and is never a safety verdict.
