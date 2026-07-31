# Observatory MVP release-gate ledger

Status: living document for the tagless MVP release candidate.
Owner: repository maintainer of this fork.
Scope: the exact code path that is exercised by the owned-fixture behavior lane
plus the CI and release paths that can publish or execute it.

## 1. Exact revisions

| Item | Value |
| --- | --- |
| Candidate branch | `feat/observatory-mvp` |
| Candidate base | `0fcbd44fa34f2794b47a198298424ff68d7c7bcf` (`observatory-enhancements-integration`) |
| Cached canonical upstream | `origin/main` `e63bacb73e8ede8a166dd0d61267bdb07596972a` (fetched 2026-07-31) |
| Merge base | `e3aa8bc0e0ccf03b3bd591fbe6569a658a18e2dd` |
| Divergence at base | 49 ahead / 29 behind `origin/main` |
| Fork publication state | `fork/main` (`VACInc/clawscan-observatory`) is at `0fcbd44`, i.e. the integration line is already published to the fork |

`HANDOFF.md` (untracked in the integration checkout) claims head `731a441` and
"nothing from this branch has been pushed". Both statements are stale: the
integration head is `0fcbd44` and that commit is the current `fork/main`. Treat
the handoff as historical narrative only.

## 2. Local artifact classification

The integration checkout carried uncommitted state. Each item is classified
before it can enter the candidate branch.

| Path | State | Classification | Reason |
| --- | --- | --- | --- |
| `internal/profiles/clawhub/clawscan.yml` | modified (2 deletions) | **exclude** | Upstream already removed VirusTotal from the bundled ClawHub profile in `origin/main` (`#19`). The local edit is a duplicate of upstream work and must come from reconciliation, not from a dirty tree. |
| `HANDOFF.md` | untracked | **exclude** | Stale narrative, superseded by this ledger. |
| `bin/clawscan`, `bin/observatory` | untracked binaries | **regenerate** | Build outputs must be produced from the candidate SHA by the release path, never copied from a developer tree. |
| `testdata/fixtures/clean-skill/`, `testdata/fixtures/clean-plugin/` | untracked | **regenerate/keep-out-of-MVP** | Not referenced by any tracked test in the candidate tree. Owned fixtures that the MVP relies on are the tracked `pipeline-safe-skill` and `pipeline-safe-plugin` trees. |

No user-owned dirty artifact is incorporated into the candidate branch. The
branch was created from the committed integration SHA in an isolated worktree.

## 3. Trust graph: untrusted to trusted transitions

Untrusted inputs are anything an unreviewed pull-request author or an unowned
scan target controls.

| # | Untrusted input | Boundary before | Boundary after |
| --- | --- | --- | --- |
| T1 | PR branch contents selected by `pr_number` | `skilltrustbench-profile-gate.yml` checked out the PR branch and then called `run-clawscan-benchmark.yml` with `secrets: inherit`, which built and ran that checkout with scanner and model credentials | Proposal validation runs with `contents: read`, no secrets. The benchmark lane accepts only a `commit_sha` proven to be an ancestor of the trusted branch, and receives named secrets only. |
| T2 | PR-authored `proposals/<GHSA-ID>/clawscan.yml` (`config_path`) | Passed straight into `clawscan --config` in the secret-bearing job, where profile fields can name executable commands | Validated as data by `cmd/validate-profile-proposal` (parse, shape, scope, executable-field rejection). Execution requires a trusted commit. |
| T3 | PR-authored workflow definitions | Reusable workflow was resolved from the PR checkout context | Benchmark lane is dispatched against the trusted default branch definition and refuses non-ancestor SHAs. |
| T4 | Automated commits pushed back into the PR branch | `update-baseline` held `contents: write` and ran `git push` onto the PR branch | Baseline update is produced as an artifact plus a step summary. Publication is a separate maintainer action. |
| T5 | Mutable third-party action tags | `actions/checkout@v4`, `actions/setup-go@v5`, `actions/upload-artifact@v4`, `actions/download-artifact@v4` in the benchmark and gate paths | All actions in the retained MVP workflow set are pinned to full commit SHAs and enforced by a test. |
| T6 | Scan target contents (owned fixture, and any future third-party target) | Capture reader accepted duplicate tar member names, last writer winning | Duplicate normalized member names fail closed. |

## 4. Findings triage against current source

Source: `docs/source-review-2026-07-25-findings.md`, section
`proj-clawhub-observatory`. Only concrete, reachable items are retained for the
MVP gate.

| ID | Title | Reachable in MVP path | Disposition |
| --- | --- | --- | --- |
| S-01 | Profile gate exposes inherited secrets to PR-selected executable profile fields | Yes | Fixed: two-lane split, trusted-commit gate, hostile-profile regression. |
| S-06 | Mutable dependencies execute in privileged workflows | Yes | Fixed: SHA pinning plus enforcement test over the retained MVP workflow set. |
| S-07 / C-06 | Capture parser accepts duplicate tar member names | Yes | Fixed: duplicate normalized member names are rejected before insertion. |
| S-09 | Observatory does not pin Crabbox config and binary snapshots | Yes, live lane | Tracked for the live phase; see `docs/observatory.md` runner contract. |
| S-08 | Output writers follow symlinks and publish partial files | Yes, publication path | Reviewed in this pass; see `internal/observatory` writer tests. |
| S-02 | Target readers have regular-file-to-symlink TOCTOU races | Partially, staging path | Descriptor-pinned staging retained; no new MVP surface. |
| S-03 | Default Docker sandbox lacks strong containment | No, documented limitation | Documentation correction only. The behavior lane refuses ClawScan Docker mode. |
| S-04, S-05, S-10, R-02, C-01..C-08 | Remaining review items | Not on the owned-fixture behavior path | Deferred with rationale; not release blockers for a tagless RC. |

## 5. Environment-blocked gates

These are the plan gates that cannot be closed from a repository-only session
and must not be reported as passed:

- Hours 6-13: live Proxmox owned-fixture proof. Requires an explicit
  operator-approved disposable VM lifecycle, VirusTotal, an OAuth judge, and a
  bounded model relay. Not attempted.
- Hour 17: demo bundle sourced from a real run. Depends on hours 6-13. A demo
  built from synthetic evidence would misrepresent the proof and is excluded.
- Hour 20: go/no-go. Remains **no-go** while the live proof packet is absent.

## 6. Baseline verification, candidate base

Recorded on the candidate base before any change (Go 1.26.1, Linux):

- `go build ./...`: pass
- `go vet ./...`: pass
- `go test -count=1 ./...`: **2 failures**, both in `internal/observatory`:
  - `TestGeneratedOpenClawConfigDiscoversOwnedSkillWhenCLIAvailable`
  - `TestGeneratedPluginConfigDiscoversOwnedFixtureWhenCLIAvailable`

  Cause: the generated guest OpenClaw configuration uses keys the installed
  OpenClaw (2026.7.2) rejects (`tools.exec.timeoutSec`, `plugins.bundledDiscovery`).
  This is live-path schema drift, not a test-only problem: a runner template on a
  current OpenClaw build would reject the generated config.
