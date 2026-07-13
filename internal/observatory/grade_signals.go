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
