package observatory

// GradeSignals is an integration boundary for typed evidence channels developed
// independently of the grading policy. Adapters copy durable, validated facts
// into this structure. They must never infer success from an open descriptor or
// from supplemental tool metadata.
type GradeSignals struct {
	Persistence  GradePersistenceSignals `json:"persistence"`
	Redirect     GradeRedirectSignals    `json:"redirect"`
	MockEgress   GradeMockEgressSignals  `json:"mockEgress"`
	CanaryStages GradeCanaryStageSignals `json:"canaryStages"`
	ToolLedger   GradeChannelStatus      `json:"toolLedger"`
}

type GradeChannelStatus struct {
	Required      bool   `json:"required"`
	Available     bool   `json:"available"`
	Complete      bool   `json:"complete"`
	Truncated     bool   `json:"truncated"`
	Authoritative bool   `json:"authoritative"`
	Reason        string `json:"reason,omitempty"`
}

type GradePersistenceSignals struct {
	Status   GradeChannelStatus        `json:"status"`
	Findings []GradePersistenceFinding `json:"findings"`
}

type GradePersistenceFinding struct {
	Surface   string `json:"surface"`
	Operation string `json:"operation"`
	Subject   string `json:"subject"`
	Outcome   string `json:"outcome"`
	Residual  string `json:"residual"`
	Delta     int    `json:"delta"`
}

type GradeRedirectSignals struct {
	Status GradeChannelStatus   `json:"status"`
	Probes []GradeRedirectProbe `json:"probes"`
}

type GradeRedirectProbe struct {
	ID             string `json:"id"`
	Surface        string `json:"surface"`
	Vector         string `json:"vector"`
	Attributed     string `json:"attributed"`
	Exercised      bool   `json:"exercised"`
	DeviationDelta int    `json:"deviationDelta"`
}

type GradeMockEgressSignals struct {
	Status           GradeChannelStatus `json:"status"`
	Endpoint         string             `json:"endpoint"`
	DeltaRequests    int                `json:"deltaRequests"`
	DeltaBytes       int64              `json:"deltaBytes"`
	CanariesObserved []string           `json:"canariesObserved"`
}

type GradeCanaryStageSignals struct {
	Status       GradeChannelStatus            `json:"status"`
	Interactions []GradeCanaryStageInteraction `json:"interactions"`
}

type GradeCanaryStageInteraction struct {
	CanaryID string `json:"canaryId"`
	Stage    string `json:"stage"`
	Coverage string `json:"coverage"`
	Delta    int    `json:"delta"`
}

// GradeSignalsFromEvidence is the single production adapter from validated
// behavior evidence into the grader's typed-channel boundary. It copies typed
// facts only; it never infers a residual, redirect, or propagation event from
// free-form observations or tool metadata.
func GradeSignalsFromEvidence(evidence Evidence) GradeSignals {
	signals := GradeSignals{}

	persistenceDeclared := evidence.SchemaVersion == EvidenceSchemaVersion || evidence.Persistence.Scope != ""
	if persistenceDeclared {
		available := validatePersistenceEvidence(evidence.Persistence) == nil
		signals.Persistence.Status = GradeChannelStatus{
			Required:      true,
			Available:     available,
			Complete:      available && evidence.Persistence.Scope == persistenceScope && evidence.Persistence.InventoryPaired,
			Authoritative: true,
		}
		if available {
			for _, finding := range evidence.Persistence.Findings {
				signals.Persistence.Findings = append(signals.Persistence.Findings, GradePersistenceFinding{
					Surface: finding.Surface, Operation: finding.Operation, Subject: finding.Subject,
					Outcome: finding.Outcome, Residual: finding.Residual, Delta: finding.DeltaCount,
				})
			}
		}
	}

	redirectDeclared := evidence.SchemaVersion == EvidenceSchemaVersion || evidence.Coverage.RedirectProbeScope != "" || evidence.RedirectProbes != nil
	if redirectDeclared {
		available := evidence.RedirectProbes != nil
		exercised := 0
		for _, probe := range evidence.RedirectProbes {
			if probe.Exercised {
				exercised++
			}
		}
		complete := available && evidence.Coverage.RedirectProbeScope == RedirectProbeScope &&
			evidence.Coverage.RedirectProbeCount == len(evidence.RedirectProbes) &&
			evidence.Coverage.RedirectProbesExercised == exercised
		signals.Redirect.Status = GradeChannelStatus{Required: true, Available: available, Complete: complete, Authoritative: true}
		if available {
			for _, probe := range evidence.RedirectProbes {
				signals.Redirect.Probes = append(signals.Redirect.Probes, GradeRedirectProbe{
					ID: probe.ID, Surface: probe.Surface, Vector: probe.Vector, Attributed: probe.Attributed,
					Exercised: probe.Exercised, DeviationDelta: probe.DeviatedDelta,
				})
			}
		}
	}

	if evidence.MockEgress != nil {
		mock := evidence.MockEgress
		signals.MockEgress.Status = GradeChannelStatus{
			Required: true, Available: true, Complete: mock.CaptureComplete && !mock.Truncated,
			Truncated: mock.Truncated, Authoritative: true,
		}
		signals.MockEgress.Endpoint = mock.SinkEndpoint
		signals.MockEgress.DeltaRequests = mock.DeltaRequests
		signals.MockEgress.DeltaBytes = mock.DeltaBytes
		signals.MockEgress.CanariesObserved = append([]string(nil), mock.CanariesObserved...)
	}

	if evidence.Coverage.CanaryStages != nil {
		pairedTrace := evidence.Coverage.BaselinePaired && evidence.Coverage.FileSyscalls &&
			evidence.Coverage.ProcessSyscalls && evidence.Coverage.NetworkSyscalls
		pairedSink := evidence.MockEgress != nil && (evidence.MockEgress.CaptureComplete || evidence.ModelRelay == nil)
		complete := validateCanaryStageCoverage(evidence.Coverage.CanaryStages, pairedTrace, pairedSink) == nil
		signals.CanaryStages.Status = GradeChannelStatus{Required: true, Available: complete, Complete: complete, Authoritative: true}
		coverage := make(map[string]string, len(evidence.Coverage.CanaryStages))
		for _, stage := range evidence.Coverage.CanaryStages {
			coverage[stage.Stage] = stage.Coverage
		}
		if complete {
			for _, canary := range evidence.Canaries {
				for _, stage := range canary.Stages {
					signals.CanaryStages.Interactions = append(signals.CanaryStages.Interactions, GradeCanaryStageInteraction{
						CanaryID: canary.ID, Stage: stage.Stage, Coverage: coverage[stage.Stage], Delta: stage.DeltaInteractions,
					})
				}
			}
		}
	}

	ledger := evidence.ToolCallLedger
	hasLedger := ledger.Source != "" || ledger.MaxCallsPerLane != 0 || ledger.Baseline.Calls != nil || ledger.Exercise.Calls != nil
	if hasLedger {
		signals.ToolLedger = GradeChannelStatus{
			Available: ledger.Baseline.Coverage != "unavailable" || ledger.Exercise.Coverage != "unavailable",
			Complete:  ledger.Baseline.Coverage == "complete" && ledger.Exercise.Coverage == "complete",
			Truncated: ledger.Baseline.Truncated || ledger.Exercise.Truncated,
		}
	}
	return signals
}
