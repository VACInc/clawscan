# Grading integration for typed evidence channels

Production scan, analyze, render, and standalone grade paths use one adapter in
`internal/observatory`:

```go
GradeEvidenceWithSignals(evidence, gradeSignalsFromEvidence(evidence))
```

`GradeSignalsFromEvidence` performs this mapping. `GradeEvidence` remains the
legacy helper for `observatory.behavior.v1` fixtures that do not declare the
enhanced channels. The adapter never infers a channel from free-form
limitations or tool names.

## Exact field mapping

Persistence lifecycle:

- Set `Persistence.Status.Required` for capture protocols that declare the
  lifecycle inventory.
- Set `Available` when `Evidence.Persistence` passed evidence validation.
- Set `Complete` only when its scope is the supported persistence scope and
  `InventoryPaired` is true. Set `Authoritative` true.
- Copy each `PersistenceFinding` surface, operation, subject, outcome, residual,
  and `DeltaCount` into `GradePersistenceFinding`.
- Never translate `open-for-write` into `Residual: confirmed`. Only the typed
  post-exercise inventory may supply that value.

Instruction redirect probes:

- Mark the channel required for a protocol that declares
  `seeded-workspace-redirects`.
- `Available` requires a non-nil `Evidence.RedirectProbes`; `Complete` requires
  the supported scope plus exact coverage counts. Set `Authoritative` true.
- Copy ID, surface, vector, attributed, exercised, and `DeviatedDelta`.
- A complete channel with no exercised probes remains a valid capture, but the
  instruction dimension is `not-assessed`. It must not be reported as clean.

Controlled mock egress:

- Leave the status zero and optional when the captured config disabled the
  sink. When enabled, mark it required.
- `Available` requires non-nil `Evidence.MockEgress`; set `Truncated` from its
  typed field; set `Complete` only when the validated receipt is untruncated;
  set `Authoritative` true.
- Copy sink endpoint, request and byte deltas, and `CanariesObserved`. The source
  evidence validator already requires canary attribution to have cleartext
  payload classification.

Canary stages:

- Mark the channel required for protocols that declare the fixed stage coverage
  table. `Available` and `Complete` require the validated canonical table; set
  `Authoritative` true.
- For every canary stage, copy canary ID, stage name, declared coverage, and
  stage delta into `GradeCanaryStageInteraction`.
- Preserve `limited` coverage. A positive interaction remains real, while zero
  remains inconclusive.

Tool-call ledger:

- Set only `ToolLedger`. It is never required and
  `Authoritative` must remain false.
- `Available` means at least one lane is not `unavailable`. `Complete` requires
  both lanes to report `complete`; `Truncated` is the OR of both lane flags.
- Do not translate tool calls, tool names, argument guesses, or output text into
  behavioral findings. The ledger may lower confidence when incomplete, but it
  never changes severity or fires an escalator.

## Integration proof

The grader and owned-fixture validation must verify:

1. all protocol-declared required channels appear in `coverage.channels`;
2. the owned benign fixtures receive their expected A or B grade;
3. a confirmed hostile fixture receives F with typed observation references;
4. deleting, truncating, or corrupting each required receipt produces
   `graded: false` and `grade: ungraded`;
5. an `open-for-write` row without residual confirmation never fires
   `successful-persistence`;
6. a tool-ledger-only canary mention never fires propagation.
