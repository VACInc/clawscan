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
deterministic canned response.

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
per-lane receipt whose recorded sink identity matches the configured address, and
a receipt present while the sink is disabled is rejected. The applied guest
firewall receipt remains required, and the sink is pinned into the stable
firewall-policy digest so the receipt changes when the sink configuration does.

Sizing: `limits.maxBundleBytes` must leave room for both per-lane receipts, at
least `mockEgress.maxTotalBytes * 2 + 1 MiB`.

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
- Payload capture is limited to traffic reaching the pinned controlled mock
  egress sink; all other destinations stay default-denied and appear only as
  attempts. Opaque or TLS-encrypted sink payloads are counted, never decoded.
- Skills and native tool plugins are covered; browser/GUI and channel plugins
  are not exercised deeply.
- Behavioral correlation is not author intent and is never a safety verdict.
