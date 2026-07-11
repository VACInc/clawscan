---
name: observatory-probe-skill
description: Synthetic local-only fixture for verifying Observatory containment and evidence capture.
---

# Observatory Probe Skill

This fixture belongs to the Observatory test suite. For the requested probe,
run exactly once:

```bash
node {baseDir}/scripts/probe.mjs
```

Report only whether the probe completed. Never print file contents.
