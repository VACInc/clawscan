# Proxmox runner template

This directory builds the site-local, secret-free VM template used by both:

- a ClawScan `local-free` pass inside ClawScan's Docker sandbox; and
- Observatory's separate paired behavior pass inside its hardened systemd lane.

Do not combine `behavior` with the free scanners in one ClawScan invocation.
The behavior adapter requires global `--sandbox off`; combining them would also
disable Docker for the command-backed scanners.

## Immutable inputs

`template.lock` pins the dated Ubuntu image, Node archive, OpenClaw release, and
the multi-architecture ClawScan runtime image digest. The build also records
the resolved npm lock and complete installed Debian package manifest. Apt
packages are recorded, not reproducibly pinned to an Ubuntu snapshot, so the
guest release receipt is mandatory build evidence. The template contains no
model credential, Proxmox token, scanner API key, target, repository checkout,
or OpenClaw state.

The runtime image is stored as a digest-preserving OCI archive. Every clone
verifies the archive manifest, imports it through Docker's `moby` containerd
namespace under the site-local `observatory-pinned` tag, and verifies the
loaded manifest digest before ClawScan can use it.

The Proxmox VMID is a site-local generation identifier, not a cryptographic
content identity. Use a new VMID/name for every rebuild and never replace an
existing template. Bind the checked-in lock digest and resulting guest release
receipt into Observatory evidence before claiming cryptographic image lineage.

## Build contract

Run `build-observatory-template.sh` on the Proxmox node as root. Its defaults
create VMID `9403`, name `clawscan-observatory-runner-v1`, 4 vCPUs, 8 GiB RAM,
and a 64 GiB disk on `local-lvm`. It refuses an existing VMID and never destroys
one. Public dependencies are baked by `virt-customize` through the build host;
the resulting VM NIC is attached only to the dedicated `vmbr2` quarantine
bridge. The builder refuses `vmbr0` and `vmbr1`.

`vmbr2` is local to the selected Proxmox node, has no physical or cluster
uplink, and is not an SDN/VNet shared across nodes. Its host firewall permits
only controller-to-guest SSH, DHCP, established replies, and the guest control
UID's exact model-relay destination. Guest access to the Proxmox host, LAN,
Internet, other Proxmox nodes, and other quarantine guests is denied.

Clones use DHCP (`ip=dhcp`); addresses are intentionally dynamic. The build
seals cloud-init, seeds `/etc/machine-id` as `uninitialized`, and disables
first-boot package upgrades. Each clone therefore generates a unique
machine/DHCP identity without trying to reach Ubuntu mirrors from quarantine.
The template is intentionally not Proxmox-protected because that flag is
inherited by full clones and would prevent Crabbox's mandatory teardown.

The build requires `qm`, `pvesm`, `qemu-img`, `guestfish`, `virt-customize`, and
`curl`. The builder expands the pinned cloud image's root filesystem in place
before installing runtime payloads. That preserves the source partition numbers
and both of its BIOS/UEFI boot paths.
After creation, copy `crabbox-observatory.example.yml` outside the repository,
set the real site-local values, and keep that config mode 0600. Its reviewed
shape is:

```yaml
provider: proxmox
target: linux
proxmox:
  node: pve-node
  templateId: 9403
  storage: local-lvm
  pool: crabbox
  bridge: vmbr2
  fullClone: true
  user: crabbox
  workRoot: /work/crabbox
  insecureTLS: false
```

Supply Proxmox credentials only through the audited local credential wrapper.
Pin a CA file in Observatory; never enable insecure TLS. The Proxmox user and
separated token both need the same narrow `SDN.Use` grant for `vmbr2`.

## Fail-closed security gate

`run-gated-observatory.sh` first submits the staged target to VirusTotal, then
runs `run-security-gate.sh` while that external analysis is pending. The local
gate runs ClawScan Static,
SkillSpector without an LLM, Cisco's base analyzers, and AgentVerus inside the
pinned Docker runtime. It removes optional provider credentials before launch
and applies `evaluate-local-free-scan.jq` to the complete artifact.
The controller stages the payload as `artifact/`; `target/` is deliberately not
used because Crabbox excludes that common build-directory name during sync.

Any scanner error, unexpected skip, incomplete/omitted evidence, changed output
contract, or material finding returns exit `42` with:

```json
{"status":"failed","stage":"security-scan","reason":"failed due to security scan"}
```

After the local gate passes, the controller reuses its exact Static and
SkillSpector evidence, polls the original VirusTotal submission without
re-uploading, and runs the `clawhub-oauth` Codex judge. An unresolved
VirusTotal report or non-benign/failed judge blocks the behavioral phase. The
model relay must not be started and the behavior VM must not be provisioned
until all of those gates pass.

On success, `result.json` embeds the deterministic `behaviorGrade` and points
to the complete `behaviorEvidence` artifact in the same output directory.

VirusTotal hash misses upload the staged archive and are not a private analysis
channel. The operator is responsible for target-upload authorization and API
plan/terms suitability; the pipeline never silently substitutes a private
guarantee.

## MiniMax secret relay

The disposable VM never receives the MiniMax key. Observatory's existing
guest-local bounded relay forwards only to `minimax-secret-relay.mjs` on the
controller. That outer relay accepts only `POST /v1/chat/completions`, the exact
`MiniMax-M3` model, `Authorization: Bearer local`, bounded bodies/concurrency,
normalizes the upstream request to a bounded non-streaming response, and injects
the real key only for `https://api.minimax.io`. The Proxmox host
firewall is the outer allowlist: the quarantine subnet can reach only the
controller's one relay IP and port.

## Validation

In a fresh full clone, run:

```sh
sudo /opt/observatory-template/validate-observatory-template.sh
```

Sync a current ClawScan binary plus this repository and run the owned fixtures:

```sh
infra/proxmox/run-owned-fixture-smoke.sh /work/results
```

Expected behavior:

- owned skill: all four free scanners complete;
- owned plugin: Static and SkillSpector complete; Cisco and AgentVerus explicitly skip;
- behavior: run separately through Observatory with `--sandbox off`;
- no ClawHub download or external scanner/model credential is used.

The smoke script explicitly forces Docker mode, scrubs optional provider
credentials, pins the baked local runtime tag, and checks that the artifacts
record that sandbox. It is the free-scanner half of the E2E, not proof of the
separate Observatory behavior lane by itself.

Final E2E must export the artifacts, verify the pinned runtime digest and guest
release receipt, release only the newly created disposable clones, and prove
that retained Field Fleet VMID 116 was never touched.
