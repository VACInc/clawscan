# Profiles

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

## Available profiles

| Profile | Scanners | Judge |
| --- | --- | --- |
| `clawhub` | `skillspector`, `virustotal`, `clawscan-static` | Codex `gpt-5.5`, high reasoning, bundled ClawHub prompt/schema; API-key judge in Docker |
| `clawhub-oauth` | `virustotal`, `skillspector`, `clawscan-static` | Codex `gpt-5.5`, high reasoning, bundled ClawHub prompt/schema; host OAuth judge confined to the staged workspace |

Use `clawhub-oauth` when the host Codex CLI is already logged in with ChatGPT:

```bash
VIRUSTOTAL_API_KEY=... clawscan ./my-skill --profile clawhub-oauth
```

Scanners still run in Docker. Only the Codex judge runs on the host, where it
reuses the CLI's saved OAuth login. Scanner/API secrets are removed from the
judge process environment. Its shell can only read the staged judge workspace;
network, web search, apps, hooks, subagents, and session persistence are
disabled. VirusTotal is submitted first; after the local scans, the profile
polls a pending report every 30 seconds for at most 10 minutes. Codex is blocked
if VirusTotal fails or remains pending. Never mount or copy `~/.codex/auth.json`
into the scanner container.

## Build a custom profile with `.clawscan.yml`

Custom profiles can be created in `.clawscan.yml`.

This is useful for version controlling iterations on your profile, creating multiple profiles to run over the same skills, etc

```yaml
version: 1
profiles:
  review:
    scanners:
      - virustotal
      - skillspector
      - snyk
    sandbox:
      env:
        - OPENAI_API_KEY
        - CODEX_API_KEY
        - VIRUSTOTAL_API_KEY
    judge:
      execution: sandbox
      waitForScanners:
        - virustotal
      waitTimeout: 10m
      waitInterval: 30s
      command: >
        codex exec --cd {{ workspace }}
        --model gpt-5.5
        --output-last-message {{ output }}
        - < {{ prompt:./prompt.md }}
```

`judge.execution` accepts `sandbox` (default) or `host`. Treat `host` profile
configuration as trusted code: ClawScan executes its command using the host
shell. Use it only for a tightly constrained judge such as `clawhub-oauth`.
`waitForScanners` currently supports `virustotal`; a pending result is polled
without re-uploading the artifact, and an unresolved result blocks the judge.

VirusTotal is not a private sandbox. A hash miss causes the staged archive to be
uploaded and it may enter VirusTotal's shared corpus. Operators must confirm
that upload is permitted for the target and that their API plan/terms cover the
workflow before enabling this profile.
