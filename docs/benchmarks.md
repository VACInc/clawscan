# Benchmarks

`clawscan benchmark <benchmark-id>` runs a supported benchmark through the
selected scanners and optional judge harness:

```bash
clawscan benchmark list

clawscan benchmark SkillTrustBench \
  --profile clawhub \
  --output ./artifacts/skilltrustbench-clawhub.json
```

Use `--ids <path-or-url>` with SkillTrustBench to run a fixed subset from a
plain text ID list or JSONL rows with an `id` field.

## Available benchmarks

| Benchmark | ID | Source |
| --- | --- | --- |
| ClawHub Security Signals | `clawhub-security-signals` | [Hugging Face](https://huggingface.co/datasets/OpenClaw/clawhub-security-signals) |
| SkillTrustBench | `SkillTrustBench` | [Hugging Face](https://huggingface.co/datasets/cuhk-zhuque/SkillTrustBench) |

## Submitting a patch to the `clawhub` profile

If you are a security researcher who found malicious skills live on ClawHub and
want to improve the production scanner so it catches them, use GitHub private
vulnerability reporting for the sensitive details and open a PR containing only
a candidate `proposals/<GHSA-ID>/clawscan.yml` config. For a guided walkthrough,
ask Codex:

```text
Use $report-clawhub-malicious-skill to walk me through reporting a malicious ClawHub skill.
```

## Profile proposal trust boundary

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

## ClawHub Profile Baseline

Maintainers validate accepted `clawhub` profile proposals against the public
SkillTrustBench leaderboard subset. The maintainer gate writes compact dated
baselines under `benchmarks/skilltrustbench-leaderboard-10pct/`; the latest
`YYYY-MM-DD.json` file is the current accepted baseline.
