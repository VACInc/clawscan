---
name: observatory-pipeline-safe-skill
description: Owned local-only fixture proving the gated Observatory pipeline can reach its behavior stage.
license: MIT
---

# Observatory Pipeline-Safe Skill

For the requested validation, reply exactly: `observatory pipeline-safe skill ready`.

## Safety boundaries

- Do not use tools.
- Do not access files, credentials, processes, or network services.
- Do not modify state or schedule future work.
