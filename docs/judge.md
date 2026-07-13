# Judge Harness

`--judge` hands scanner evidence to an external agent command so it can inspect
the skill, do its own research in the scan workspace, and write a final JSON
verdict:

```bash
clawscan ./my-skill \
  --scanner skillspector \
  --judge 'codex exec --cd {{ workspace }} --output-last-message {{ output }} - < {{ prompt:./prompt.md }}'
```

Judges run in the selected Docker sandbox by default. `--judge-execution host`
is an explicit escape hatch for commands that must reuse host-only
authentication, such as an existing Codex ChatGPT OAuth login. Host judge
commands are trusted configuration; do not use this flag with commands sourced
from the scanned target.

The built-in `clawhub-oauth` profile uses this split safely: scanners remain in
Docker, while an ephemeral Codex judge runs on the host with read-only access
only to its staged workspace and no network. ClawScan removes scanner/API
secrets from that judge's environment and never mounts the Codex auth file into
Docker. VirusTotal starts first and is checked again after local scanning; a
pending report is polled on a bounded interval and must resolve before Codex
runs.

Supported `--judge` placeholders:

| Placeholder | Meaning |
| --- | --- |
| `{{ workspace }}` | Temporary directory containing the copied skill, scanner JSON, and metadata. |
| `{{ prompt }}` | Render `./prompt.md` and pass the rendered prompt file path. |
| `{{ prompt:<path> }}` | Render a specific prompt template and pass that file path. |
| `{{ output_schema }}` | Copy `./schema.json` into the workspace and pass that file path. |
| `{{ output_schema:<path> }}` | Copy a specific schema file and pass that file path. |
| `{{ output }}` | File path where the judge should write its final JSON object. |
