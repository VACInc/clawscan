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

## Model/runtime comparison matrix

The default scan runs exactly one model and one paired capture. An optional,
opt-in matrix compares how the same target behaves under a bounded list of
model/runtime variants. The matrix never changes the default: a plain
`observatory scan` always uses the single `runtime.model`, even when a `matrix`
block is present. Only the `matrix` subcommand reads the variants.

Define variants as sparse overrides of the base model/runtime; unset fields
inherit. Between 2 and 8 variants are allowed. Each variant needs a unique,
stable `id` and a distinct effective configuration — two ids for the same
effective config, or two variants that resolve to the same capture digest, are
rejected as ambiguous rather than silently merged.

```yaml
matrix:
  variants:
    - id: baseline-model
      model: { id: local-tool-model }
    - id: alternate-endpoint
      model: { id: local-tool-model-b, baseUrl: http://10.0.0.21:8000/v1 }
      controlPlaneAddresses: [10.0.0.21:8000]
```

Because a matrix multiplies resource use, the resource multiplier is always
shown before any VM is provisioned, and `--dry-run` prints the plan (multiplier,
fresh-VM count, worst-case wall clock, and per-variant model/endpoint class and
capture digest) without provisioning anything:

```bash
./bin/observatory matrix --config ./observatory.yml --dry-run ./path/to/target
```

A real matrix run executes each variant as its own fresh-VM paired scan,
sequentially (never concurrently), reusing the shared executor, isolation,
target staging, exercise prompt, and limits so that captures differ only on the
model/runtime axis. Each variant fully re-validates the live isolation contract
before it starts. Use `--fail-fast` to stop at the first failing variant;
otherwise the whole matrix runs and per-variant status is reported.

```bash
./bin/observatory matrix --config ./observatory.yml --output ./matrix ./path/to/target
```

The output is `observatory.matrix.v1`: a structured, side-by-side comparison of
grade-ready behavioral signals. Each variant carries its bound
`captureConfigSha256`, model receipt (provider, id, endpoint class), firewall
policy digest, and per-kind signal totals. Each observed behavior appears once
with its per-variant delta counts and a `uniform` flag. The comparison only
covers variants whose captures are genuinely comparable — same target digest,
prompt, coverage, isolation profile, and runtime versions. It refuses to compare
captures that differ in anything other than the model/runtime axis, and lists
incomplete or failed variants under `excluded` with a reason category. It never
labels an incomparable capture as a behavioral difference, and it carries no
verdict, score, or recommendation.

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
