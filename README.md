# ClawScan 📡

ClawScan is a composable security scanning harness for agent skills.

Run a suite of skill security scanners, pass the results to a judge harness, and compare against multiple skill security benchmarks.

[![CI](https://img.shields.io/badge/CI-passing-brightgreen)](https://github.com/openclaw/clawscan/actions/workflows/ci.yml?query=branch%3Amain)
[![Release](https://img.shields.io/badge/Release-passing-brightgreen)](https://github.com/openclaw/clawscan/actions/workflows/release.yml)
[![Latest release](https://img.shields.io/badge/latest%20release-unreleased-lightgrey)](https://github.com/openclaw/clawscan/releases)


## Quick Start

Install ClawScan:

```bash
npm install -g @openclaw/clawscan
```

Command-backed scanners and judges run in ClawScan's Docker runtime by default,
so keep Docker running for local scans.

Run NVIDIA SkillSpector and Cisco Skill Scanner against a local `skills/` folder:

```bash
clawscan --scanner skillspector --scanner cisco
```

## Observatory: behavior evidence, not verdicts

Static scanners report what code appears capable of doing. Observatory runs the
same synthetic OpenClaw task twice, once without the target and once with it,
subtracts baseline runtime activity, and publishes the observed difference.

```text
target ──▶ stage ──▶ static/free scanners ──▶ gate
                                              │
                        baseline lane ◀───────┴───────▶ exercise lane
                        (no target)                     (target loaded)
                              └──────── paired capture ────────┘
                                              │
                            observatory.behavior.v2 evidence
                                              │
                        observatory.grade.v2 (separate projection)
```

The evidence schema has no verdict, score, or recommendation. The grade is a
separate derived file. Both are reproducible offline from the retained capture.

Quick start on a Linux control host:

```bash
go build -o ./bin/clawscan ./cmd/clawscan
go build -o ./bin/observatory ./cmd/observatory

./bin/clawscan scanners behavior
./bin/observatory --help

# Stage an owned fixture, which never executes it.
./bin/observatory stage \
  --output /tmp/observatory-demo-stage \
  --metadata /tmp/observatory-demo-stage.json \
  ./testdata/fixtures/pipeline-safe-plugin

# Validate a live runner configuration before anything is provisioned.
./bin/observatory validate-config --live /secure/path/observatory.yml
```

Offline replay of a completed run, from the retained private capture:

```bash
./bin/observatory analyze --config ./observatory.yml \
  --bundle /secure/run/raw.tar.gz --json \
  --grade-output /secure/run/grade.json \
  /secure/run/target > /secure/run/evidence.json

./bin/observatory grade  --input /secure/run/evidence.json --output /tmp/grade.json
./bin/observatory render --input /secure/run/evidence.json --output /tmp/site
```

### Isolation prerequisites

The behavior lane executes the target, so it never runs on the ClawScan host and
it refuses ClawScan Docker sandbox mode. It requires a separately isolated
remote runner: a fresh full clone on a dedicated quarantine bridge, default-deny
networking, dedicated accounts, pinned TLS, bounded cgroups, and synthetic
identity material. The target never receives VirusTotal, Codex, model, Proxmox,
or Crabbox credentials. The runner contract is in
[`infra/proxmox/README.md`](infra/proxmox/README.md), and the full flow is
[`infra/proxmox/run-gated-observatory.sh`](infra/proxmox/run-gated-observatory.sh).

### What Observatory does not prove

- A clean grade is not a safety proof. One task exercises one path.
- Dormant branches, delayed triggers, and version-specific behavior can be
  missed.
- GUI and channel-plugin coverage is shallow, and tool-argument metadata can be
  incomplete. Both are reported in the evidence coverage fields.
- Deep or repeated redirect trials are rejected by configuration on purpose.
- Observatory does not host a public scanning service, scan the ClawHub catalog,
  or execute third-party targets on your behalf.

See [`docs/observatory.md`](docs/observatory.md) for the full contract. Release
archives also include [`LIMITATIONS.md`](LIMITATIONS.md) and
[`PROOF-PACKET.md`](PROOF-PACKET.md).

## Scan a known malicious skill

This example scans Trail of Bits' [`csv-summarizer`](https://github.com/trailofbits/overtly-malicious-skills/tree/4ffbf9461ef0505f9ce76a0d3694a18ec33ea531/skills/csv-summarizer) skill, which claims to summarize a CSV file but also prints every environment variable when run.

```bash
git clone https://github.com/trailofbits/overtly-malicious-skills.git /tmp/overtly-malicious-skills
cd /tmp/overtly-malicious-skills
git checkout 4ffbf9461ef0505f9ce76a0d3694a18ec33ea531
clawscan skills/csv-summarizer \
  --scanner skillspector \
  --scanner cisco \
  --output /tmp/clawscan-csv-summarizer.json
```

Sample findings:

```txt
targets: 1
scanner_completed: 2
scanner_failed: 0
scanner_skipped: 0
issues_found: 2
errors: 0
full_results: /tmp/clawscan-csv-summarizer.json
```

The results bundle keeps the top-level artifact plus per-scanner JSON reports.

<details>
<summary>Artifact excerpt</summary>

```json
{
  "schemaVersion": "clawscan-run-v1",
  "target": "skills/csv-summarizer",
  "scanners": {
    "cisco": {
      "status": "completed",
      "durationMs": 42,
      "outputPath": "clawscan-csv-summarizer/skills/csv-summarizer/cisco.json",
      "isSafe": true,
      "maxSeverity": "SAFE",
      "findingsCount": 0
    },
    "skillspector": {
      "status": "completed",
      "durationMs": 42,
      "outputPath": "clawscan-csv-summarizer/skills/csv-summarizer/skillspector.json",
      "severity": "MEDIUM",
      "score": 31,
      "recommendation": "CAUTION",
      "issues": [
        {
          "id": "LP3",
          "severity": "MEDIUM",
          "file": "SKILL.md"
        },
        {
          "id": "E2",
          "severity": "HIGH",
          "file": "scripts/summarize.py"
        }
      ]
    }
  }
}
```

</details>


## Motivation

Agent-skill security is new and fast-moving, with researchers and companies
exploring many promising scanners, datasets, and judge harnesses. In our
[ClawHub Security Signals paper](https://arxiv.org/html/2606.01494v1), we found
that combining multiple scanners with a configurable judge works better than
relying on any single scanner.

ClawScan turns that approach into a repeatable CLI. It includes a built-in `clawhub` profile, a saved scanner-and-judge configuration that matches what ClawHub runs in production, so researchers can reproduce results, test improvements, and help improve detection against the weekly refreshed ClawHub security-signals dataset.

## Commands

| Command family | Use |
| --- | --- |
| `clawscan <target> --scanner <id>` | Run one or more scanners against an explicit skill or native plugin target. Omit `<target>` to scan child skill directories under `./skills`; plugins are never auto-discovered. |
| `clawscan scanners [list\|<scanner-id>]` | Discover supported scanner IDs, required env vars, upstream links, descriptions, and install guidance. |
| `clawscan profiles [-v]` | Inspect built-in plus nearest project-local profiles; `-v` prints the resolved profile catalog as YAML. |
| `clawscan benchmark [list\|<benchmark-id>]` | Discover or run supported benchmarks through a selected scanner/profile/judge setup. |
| `clawscan install <scanner-id> [...]` | Install or verify local scanner dependencies where ClawScan has registry-backed install plans. |

## Scanners

`--scanner` selects a scanner adapter to run, writes its raw JSON evidence into
the results artifact, and can be repeated to compare multiple scanners in one
run:

```bash
clawscan ./my-skill \
  --scanner skillspector \
  --scanner cisco
```

Discover the scanner catalog from the CLI:

```bash
clawscan scanners
clawscan scanners skillspector
```

### Available scanners

> **Want to add your scanner to the list?** Follow the guide in [docs/scanners.md](docs/scanners.md#adding-a-built-in-scanner-adapter)

| ID | Name | Repo | Description | Required env vars | Local dependency setup |
| --- | --- | --- | --- | --- | --- |
| `agentverus` | AgentVerus | [repo](https://github.com/agentverus/agentverus-scanner) | Local file or directory scanner invoked through agentverus-scanner. | none | `npm install --save-dev agentverus-scanner` |
| `aig` | Tencent AI-Infra-Guard | [repo](https://github.com/Tencent/AI-Infra-Guard/tree/main/skill-scan) | Tencent Zhuque Lab's local directory scanner invoked through `aig-skill-scan`. Produces SARIF 2.1.0 with SkillTrustBench T01-T09 evidence. | `LLM_API_KEY` or `OPENAI_API_KEY`<br><details><summary>Optional config</summary><code>DEFAULT_MODEL</code>, <code>DEFAULT_BASE_URL</code>, <code>DEFAULT_MODEL_CONTEXT_WINDOW</code>, <code>LOG_LEVEL</code>.</details> | `pip install aig-skill-scan` |
| `behavior` | ClawHub Observatory Behavior | [docs](docs/observatory.md) | Paired baseline/exercise runtime evidence from a separately isolated disposable OpenClaw environment. Accepts skill and native plugin targets. | `CLAWSCAN_BEHAVIOR_CONFIG` | build `cmd/observatory`; run Clawscan with `--sandbox off` |
| `cisco` | Cisco AI Defense skill-scanner | [repo](https://github.com/cisco-ai-defense/skill-scanner) | Local file or directory scanner invoked through `skill-scanner` with JSON report output. Optional upstream env vars enable LLM, VirusTotal, and Cisco AI Defense analyzers. | none<br><details><summary>Optional config</summary><code>SKILL_SCANNER_LLM_API_KEY</code>, <code>SKILL_SCANNER_LLM_PROVIDER</code>, <code>SKILL_SCANNER_LLM_MODEL</code>, <code>SKILL_SCANNER_LLM_BASE_URL</code>, <code>SKILL_SCANNER_LLM_USER</code>, <code>SKILL_SCANNER_LLM_API_VERSION</code>, <code>SKILL_SCANNER_LLM_FORCE_JSON_OBJECT</code>, <code>SKILL_SCANNER_META_LLM_API_KEY</code>, <code>SKILL_SCANNER_META_LLM_MODEL</code>, <code>SKILL_SCANNER_META_LLM_BASE_URL</code>, <code>SKILL_SCANNER_META_LLM_API_VERSION</code>, <code>AWS_PROFILE</code>, <code>AWS_REGION</code>, <code>GOOGLE_APPLICATION_CREDENTIALS</code>, <code>VIRUSTOTAL_API_KEY</code>, <code>AI_DEFENSE_API_KEY</code>, <code>AI_DEFENSE_API_URL</code>.</details> | `uv pip install cisco-ai-skill-scanner` |
| `clawscan-static` | ClawScan Static | [repo](https://github.com/openclaw/clawscan) | Built-in deterministic text scanner for high-signal risky skill and OpenClaw plugin patterns. | none | skipped; built in |
| `skillspector` | NVIDIA SkillSpector | [repo](https://github.com/NVIDIA/skillspector) | Local skill or OpenClaw plugin file/directory scanner. Uses LLM mode when provider env vars are set; otherwise runs with `--no-llm`. | none<br><details><summary>Optional config</summary><code>SKILLSPECTOR_PROVIDER</code>, <code>SKILLSPECTOR_MODEL</code>, <code>SKILLSPECTOR_MODEL_REGISTRY</code>, <code>SKILLSPECTOR_LOG_LEVEL</code>, <code>SKILLSPECTOR_SSL_VERIFY</code>, <code>NVIDIA_INFERENCE_KEY</code>, <code>OPENAI_API_KEY</code>, <code>OPENAI_BASE_URL</code>, <code>ANTHROPIC_API_KEY</code>, <code>ANTHROPIC_PROXY_ENDPOINT_URL</code>, <code>ANTHROPIC_PROXY_API_KEY</code>, <code>ANTHROPIC_PROXY_API_VERSION</code>.</details> | `uv tool install git+https://github.com/NVIDIA/skillspector.git` |
| `snyk` | Snyk Agent Scan | [repo](https://github.com/snyk/agent-scan) | Local skill scanner invoked through `uvx snyk-agent-scan`. | `SNYK_TOKEN` | verifies `uvx` launcher |
| `socket` | Socket CLI | [repo](https://github.com/SocketDev/socket-cli) | Local file or directory scanner using Socket's public CLI full-scan path. | `SOCKET_CLI_API_TOKEN` | `npm install -g socket` |
| `virustotal` | VirusTotal API | [docs](https://docs.virustotal.com/reference/file) | API-backed local file hash lookup. Skill and OpenClaw plugin directories are scanned as deterministic ZIP archives. | `VIRUSTOTAL_API_KEY` | skipped; API-backed |

Starting in `v0.1.2`, the built-in `aig` scanner uses Tencent's local
`aig-skill-scan` package instead of the legacy A.I.G Docker/API service.
Replace `AIG_MODEL` with `DEFAULT_MODEL`, `AIG_MODEL_BASE_URL` with
`DEFAULT_BASE_URL`, and `AIG_MODEL_API_KEY` with `LLM_API_KEY` (or
`OPENAI_API_KEY`). `AIG_BASE_URL` and `AIG_API_KEY` are no longer used.
The local scanner accepts directory targets only; materialize URL or file inputs
as a skill directory before scanning them with `aig`.

## Profiles

`--profile` runs a saved scanner and judge configuration, such as the built-in
`clawhub` profile that matches ClawHub's production scanner suite and Codex
judge harness:

```bash
clawscan ./my-skill --profile clawhub
```

The same profile accepts an explicit OpenClaw plugin directory (or its
`openclaw.plugin.json` manifest), runs all three scanners, and renders the
bundled judge prompt with `packageRelease` target context.

Inspect the resolved profile catalog, including the nearest project
`.clawscan.yml` / `.clawscan.yaml` when present:

```bash
clawscan profiles
clawscan profiles -v
```

### Available profiles

| Profile | Scanners | Judge |
| --- | --- | --- |
| `clawhub` | `skillspector`, `virustotal`, `clawscan-static` | Codex `gpt-5.5`, high reasoning, bundled ClawHub prompt/schema |

### Build a custom profile with `.clawscan.yml`

Custom profiles can be created in `.clawscan.yml`.

This is useful for version controlling iterations on your profile, creating multiple profiles to run over the same skills, etc

```yaml
version: 1
profiles:
  review:
    scanners:
      - skillspector
      - snyk
    sandbox:
      env:
        - OPENAI_API_KEY
        - CODEX_API_KEY
    judge:
      command: >
        codex exec --cd {{ workspace }}
        --model gpt-5.5
        --output-last-message {{ output }}
        - < {{ prompt:./prompt.md }}
```

## Judge Harness

`--judge` hands scanner evidence to an external agent command so it can inspect
the skill, do its own research in the scan workspace, and write a final JSON
verdict:

```bash
clawscan ./my-skill \
  --scanner skillspector \
  --judge 'codex exec --cd {{ workspace }} --output-last-message {{ output }} - < {{ prompt:./prompt.md }}'
```

Supported `--judge` placeholders:

| Placeholder | Meaning |
| --- | --- |
| `{{ workspace }}` | Temporary directory containing the copied skill, scanner JSON, and metadata. |
| `{{ prompt }}` | Render `./prompt.md` and pass the rendered prompt file path. |
| `{{ prompt:<path> }}` | Render a specific prompt template and pass that file path. |
| `{{ output_schema }}` | Copy `./schema.json` into the workspace and pass that file path. |
| `{{ output_schema:<path> }}` | Copy a specific schema file and pass that file path. |
| `{{ output }}` | File path where the judge should write its final JSON object. |

For a host Codex CLI already authenticated with ChatGPT OAuth, use the built-in
`clawhub-oauth` profile. Scanners remain in Docker; the host judge is ephemeral,
can only read its staged workspace, and has network, web, apps, hooks, and
subagents disabled. This profile starts VirusTotal first and, if an upload is
still pending after the local scanners finish, polls it for up to 10 minutes
before Codex is allowed to run:

```bash
VIRUSTOTAL_API_KEY=... clawscan ./my-skill --profile clawhub-oauth
```

## Sandbox

ClawScan runs command-backed scanners and judges in
`ghcr.io/openclaw/clawscan-runtime:latest` by default:

```bash
clawscan ./my-skill --scanner skillspector
```

Use `--sandbox off` only in an already-isolated environment, or when you have
installed scanner dependencies on the host with `clawscan install`. Use
`--sandbox-env <NAME>` or a profile `sandbox.env` list to pass judge-specific
environment variables into the container.

## Benchmarks

`clawscan benchmark <benchmark-id>` runs a supported benchmark through the
selected scanners and optional judge harness:

```bash
clawscan benchmark list

clawscan benchmark SkillTrustBench \
  --profile clawhub \
  --output ./artifacts/skilltrustbench-clawhub.json
```

Use `--ids <path-or-url>` with SkillTrustBench to run a fixed subset from a
plain text ID list or JSONL rows with an `id` field. JSONL rows that include
`judgment` are authoritative for labels and metadata, so verify the source
digest with `--ids-sha256 <sha256>` before using them for a published score.
The digest is required for remote sources.

### Available benchmarks

| Benchmark | ID | Source |
| --- | --- | --- |
| ClawHub Security Signals | `clawhub-security-signals` | [Hugging Face](https://huggingface.co/datasets/OpenClaw/clawhub-security-signals) |
| SkillTrustBench | `SkillTrustBench` | [Hugging Face](https://huggingface.co/datasets/cuhk-zhuque/SkillTrustBench) |

### Submitting a patch to the `clawhub` profile

If you are a security researcher who found malicious skills live on ClawHub and
want to improve the production scanner so it catches them, use GitHub private
vulnerability reporting for the sensitive details and open a PR containing only
a candidate `proposals/<GHSA-ID>/clawscan.yml` config. For a guided walkthrough,
ask Codex:

```text
Use $report-clawhub-malicious-skill to walk me through reporting a malicious ClawHub skill.
```

### Profile proposal trust boundary

Profile proposals are reviewed in two separate lanes because a profile can name
the judge command:

- **Proposal validation** (`Profile Proposal Validation`) runs on the pull
  request with read-only permissions and no secrets. It builds the validator
  from the trusted base commit, extracts the proposed file from the pull-request
  head without checking that tree out, and validates it strictly as data.
- **Benchmarking** (`SkillTrustBench Benchmark`) is a maintainer dispatch. It
  accepts an exact commit SHA, refuses any commit that is not already an
  ancestor of `main` or a `trusted/*` branch, and only then runs the benchmark
  with named credentials. It publishes the dated baseline as an artifact and
  pushes no commits.

No pull-request-selected ref, config, or artifact reaches a job that holds
credentials.

### ClawHub Profile Baseline

Maintainers validate accepted `clawhub` profile proposals against the public
SkillTrustBench leaderboard subset. The maintainer gate writes compact dated
baselines under `benchmarks/skilltrustbench-leaderboard-10pct/`; the latest
`YYYY-MM-DD.json` file is the current accepted baseline.
