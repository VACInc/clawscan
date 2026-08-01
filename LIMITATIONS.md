# Observatory limitations

Observatory publishes observed behavior for one synthetic task in one isolated
environment. It does not prove that a target is safe.

- Evidence is observational. A grade is a separate derived projection and is
  never part of the evidence schema.
- One task exercises one path. Dormant branches, delayed triggers, and
  version-specific behavior can be missed.
- GUI and channel-plugin coverage is shallow, and tool-argument metadata can be
  incomplete. Those gaps are reported in the evidence coverage fields.
- The behavior lane requires an independently isolated remote runner. It refuses
  ClawScan Docker sandbox mode.
- Deep or repeated redirect trials are rejected by configuration on purpose.
- Live runs require an operator-approved disposable VM lifecycle. Nothing in
  this archive provisions infrastructure by itself.
