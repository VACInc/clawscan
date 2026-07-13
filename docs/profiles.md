# Profiles

`--profile` runs a saved scanner and judge configuration, such as the built-in
`clawhub` profile that matches ClawHub's production scanner suite and Codex
judge harness:

```bash
clawscan ./my-skill --profile clawhub
```

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
| `clawhub-oauth` | `skillspector`, `virustotal`, `clawscan-static` | Codex `gpt-5.5`, high reasoning, bundled ClawHub prompt/schema; host OAuth judge confined to the staged workspace |

Use `clawhub-oauth` when the host Codex CLI is already logged in with ChatGPT:

```bash
VIRUSTOTAL_API_KEY=... clawscan ./my-skill --profile clawhub-oauth
```

Scanners still run in Docker. Only the Codex judge runs on the host, where it
reuses the CLI's saved OAuth login. Scanner/API secrets are removed from the
judge process environment. Its shell can only read the staged judge workspace;
network, web search, apps, hooks, subagents, and session persistence are disabled. Never mount or copy
`~/.codex/auth.json` into the scanner container.

## Build a custom profile with `.clawscan.yml`

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
      execution: sandbox
      command: >
        codex exec --cd {{ workspace }}
        --model gpt-5.5
        --output-last-message {{ output }}
        - < {{ prompt:./prompt.md }}
```

`judge.execution` accepts `sandbox` (default) or `host`. Treat `host` profile
configuration as trusted code: ClawScan executes its command using the host
shell. Use it only for a tightly constrained judge such as `clawhub-oauth`.
