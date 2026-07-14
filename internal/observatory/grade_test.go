package observatory

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// gradableEvidence returns a complete, valid, gradable baseline with no risky
// behavior. Tests mutate it to exercise individual policy paths.
func gradableEvidence() Evidence {
	evidence := fixtureEvidence()
	evidence.Observations = []Observation{}
	evidence.Canaries = []CanaryObservation{
		{ID: "cloud-credentials", Surface: "home file", Class: "credential", Stages: []CanaryStageInteraction{}},
		{ID: "openclaw-credentials", Surface: "state file", Class: "credential", Stages: []CanaryStageInteraction{}},
		{ID: "workspace-identity", Surface: "workspace file", Class: "identity", Stages: []CanaryStageInteraction{}},
		{ID: "workspace-memory", Surface: "workspace file", Class: "memory", Stages: []CanaryStageInteraction{}},
	}
	return evidence
}

func fileObservation(operation, subject, outcome string) Observation {
	return Observation{Kind: "file", Operation: operation, Subject: subject, Outcome: outcome, BaselineCount: 0, ExerciseCount: 1, DeltaCount: 1}
}

func networkObservation(subject, outcome, role string) Observation {
	return Observation{Kind: "network", Operation: "connect", Subject: subject, Outcome: outcome, Role: role, BaselineCount: 0, ExerciseCount: 1, DeltaCount: 1}
}

func gradeDimension(grade Grade, id string) GradeDimension {
	for _, dimension := range grade.Dimensions {
		if dimension.ID == id {
			return dimension
		}
	}
	return GradeDimension{}
}

func hasEscalator(grade Grade, id string) bool {
	for _, escalator := range grade.Escalators {
		if escalator.ID == id {
			return true
		}
	}
	return false
}

func completeAuthoritativeChannel() GradeChannelStatus {
	return GradeChannelStatus{Required: true, Available: true, Complete: true, Authoritative: true}
}

func TestGradeCleanEvidenceIsAWithSeparateConfidence(t *testing.T) {
	evidence := gradableEvidence()
	if err := ValidateEvidence(evidence); err != nil {
		t.Fatalf("baseline evidence invalid: %v", err)
	}
	grade := GradeEvidence(evidence)
	if err := ValidateGrade(grade); err != nil {
		t.Fatalf("grade invalid: %v", err)
	}
	if !grade.Graded || grade.Letter != "A" {
		t.Fatalf("clean evidence graded=%v letter=%q", grade.Graded, grade.Letter)
	}
	// A means only "no concerning behavior observed within covered tests"; the
	// confidence is a separate axis and must not be certainty.
	if grade.Confidence.Level == "high" {
		t.Fatalf("clean-but-thin capture should not be high confidence: %#v", grade.Confidence)
	}
	if grade.Coverage.Capture != "complete" {
		t.Fatalf("coverage = %#v", grade.Coverage)
	}
	if len(grade.Escalators) != 0 {
		t.Fatalf("clean evidence should have no escalators: %#v", grade.Escalators)
	}
	if grade.Comparison.Status != "no-risky-behavior" {
		t.Fatalf("comparison = %#v", grade.Comparison)
	}
}

func TestGradeLettersScaleWithObservedRisk(t *testing.T) {
	for _, test := range []struct {
		name        string
		observation Observation
		want        string
	}{
		{"non-sensitive external read", fileObservation("open-for-read", "$HOME/notes.txt", "succeeded"), "B"},
		{"system info read", fileObservation("open-for-read", "/etc/hostname", "succeeded"), "B"},
		{"local ipc", networkObservation("unix:/run/app.sock", "succeeded", "local"), "B"},
		{"private network reach", networkObservation("private-endpoint:8080", "succeeded", "private-network"), "C"},
		{"secret read is access not F", fileObservation("open-for-read", "$HOME/.aws/credentials", "succeeded"), "C"},
		{"blocked external connect", networkObservation("93.184.216.34:443", "attempted", "external"), "D"},
		{"external reach", networkObservation("93.184.216.34:443", "succeeded", "external"), "D"},
		{"non-workspace write", fileObservation("open-for-write", "$STATE/scratch.dat", "succeeded"), "D"},
		{"blocked secret read", fileObservation("open-for-read", "$HOME/.aws/credentials", "attempted"), "D"},
		{"open persistence surface is not durable proof", fileObservation("open-for-write", "$HOME/.bashrc", "succeeded"), "D"},
	} {
		t.Run(test.name, func(t *testing.T) {
			evidence := gradableEvidence()
			evidence.Observations = []Observation{test.observation}
			if err := ValidateEvidence(evidence); err != nil {
				t.Fatalf("evidence invalid: %v", err)
			}
			grade := GradeEvidence(evidence)
			if err := ValidateGrade(grade); err != nil {
				t.Fatalf("grade invalid: %v", err)
			}
			if grade.Letter != test.want {
				t.Fatalf("letter = %q, want %q (dimensions=%#v)", grade.Letter, test.want, grade.Dimensions)
			}
		})
	}
}

func TestGradeModelControlPlaneTrafficIsNotRisk(t *testing.T) {
	evidence := gradableEvidence()
	evidence.Observations = []Observation{networkObservation("model-endpoint:8000", "succeeded", "model-control-plane")}
	grade := GradeEvidence(evidence)
	if grade.Letter != "A" {
		t.Fatalf("expected control-plane traffic to stay A, got %q", grade.Letter)
	}
	if gradeDimension(grade, dimNetwork).Severity != "none" {
		t.Fatalf("network dimension = %#v", gradeDimension(grade, dimNetwork))
	}
}

func TestGradeReadOnlyCanaryIsAccessNotLeakage(t *testing.T) {
	// A bare canary interaction delta only proves the planted path was touched.
	// It must be graded as moderate access — never F, never called "leakage".
	evidence := gradableEvidence()
	evidence.Canaries[0].ExerciseInteractions = 1
	evidence.Canaries[0].DeltaInteractions = 1
	evidence.Canaries[0].Stages = []CanaryStageInteraction{{Stage: CanaryStageRead, ExerciseInteractions: 1, DeltaInteractions: 1}}
	grade := GradeEvidence(evidence)
	if grade.Letter == "F" {
		t.Fatalf("read-only canary access must not be F: %q", grade.Letter)
	}
	if grade.Letter != "C" {
		t.Fatalf("canary access letter = %q, want C", grade.Letter)
	}
	dimension := gradeDimension(grade, dimCanary)
	if dimension.Severity != "moderate" {
		t.Fatalf("canary dimension = %#v", dimension)
	}
	for _, escalator := range grade.Escalators {
		t.Fatalf("canary access must raise no hard escalator: %#v", escalator)
	}
	joined := strings.ToLower(strings.Join(dimension.Reasons, " "))
	if strings.Contains(joined, "leak") || strings.Contains(joined, "propagat") {
		t.Fatalf("access reason must not imply leakage/propagation: %#v", dimension.Reasons)
	}
	if !strings.Contains(joined, "access") {
		t.Fatalf("access reason should say accessed: %#v", dimension.Reasons)
	}
}

func TestGradeConfirmedPropagationEscalatesToF(t *testing.T) {
	// A canary value observed on an outbound sink is confirmed propagation → F.
	evidence := gradableEvidence()
	evidence.Observations = []Observation{{
		Kind: "network", Operation: "send", Subject: "[canary:cloud-credentials]->198.51.100.7:443",
		Outcome: "succeeded", Role: "external", BaselineCount: 0, ExerciseCount: 1, DeltaCount: 1,
	}}
	if err := ValidateEvidence(evidence); err != nil {
		t.Fatalf("evidence invalid: %v", err)
	}
	grade := GradeEvidence(evidence)
	if grade.Letter != "F" || !hasEscalator(grade, "synthetic-canary-propagation") {
		t.Fatalf("propagation grade=%q escalators=%#v", grade.Letter, grade.Escalators)
	}
	if gradeDimension(grade, dimCanary).Severity != "critical" {
		t.Fatalf("canary dimension = %#v", gradeDimension(grade, dimCanary))
	}
}

func TestGradeAttemptedCanaryChannelDoesNotConfirmPropagation(t *testing.T) {
	evidence := gradableEvidence()
	evidence.Observations = []Observation{{
		Kind: "network", Operation: "send", Subject: "[canary:cloud-credentials]->198.51.100.7:443",
		Outcome: "attempted", Role: "external", BaselineCount: 0, ExerciseCount: 1, DeltaCount: 1,
	}}
	grade := GradeEvidence(evidence)
	if grade.Letter == "F" || hasEscalator(grade, "synthetic-canary-propagation") {
		t.Fatalf("attempted channel manufactured confirmed propagation: letter=%q escalators=%#v", grade.Letter, grade.Escalators)
	}
}

func TestGradeValidLongObservationReferenceRemainsValid(t *testing.T) {
	evidence := gradableEvidence()
	evidence.Observations = []Observation{fileObservation("open-for-read", "$HOME/"+strings.Repeat("x", 1600)+"\nnotes.txt", "succeeded")}
	if err := ValidateEvidence(evidence); err != nil {
		t.Fatalf("long public evidence should remain valid: %v", err)
	}
	grade := GradeEvidence(evidence)
	if err := ValidateGrade(grade); err != nil {
		t.Fatalf("derived grade rejected a valid long observation: %v", err)
	}
	refs := gradeDimension(grade, dimSensitive).EvidenceRefs
	if len(refs) != 1 || refs[0].Subject != evidence.Observations[0].Subject {
		t.Fatalf("grade lost exact evidence reference: %#v", refs)
	}
}

func TestGradeDeclaredCredentialReadIsNotF(t *testing.T) {
	// A declared, expected sensitive read is concerning evidence, not F.
	evidence := gradableEvidence()
	evidence.Observations = []Observation{fileObservation("open-for-read", "$HOME/.aws/credentials", "succeeded")}
	evidence.Target.DeclaredCapabilities = &DeclaredCapabilities{Source: "skill-frontmatter", Declared: true, Capabilities: []string{"credential-access"}}
	if err := ValidateEvidence(evidence); err != nil {
		t.Fatalf("evidence invalid: %v", err)
	}
	grade := GradeEvidence(evidence)
	if grade.Letter == "F" {
		t.Fatalf("declared credential read must not be F: %q", grade.Letter)
	}
	if grade.Comparison.Status != "consistent" {
		t.Fatalf("comparison = %#v", grade.Comparison)
	}
	if len(grade.Escalators) != 0 {
		t.Fatalf("declared credential read must raise no hard escalator: %#v", grade.Escalators)
	}
	if gradeDimension(grade, dimSensitive).Severity != "moderate" {
		t.Fatalf("sensitive dimension = %#v", gradeDimension(grade, dimSensitive))
	}
}

func TestGradeAGradeWordingStaysObservedOnly(t *testing.T) {
	grade := GradeEvidence(gradableEvidence())
	if grade.Letter != "A" {
		t.Fatalf("letter = %q", grade.Letter)
	}
	if !strings.Contains(grade.Summary, "observed within the covered exercise") {
		t.Fatalf("A summary must stay observed-only: %q", grade.Summary)
	}
	found := false
	for _, limitation := range grade.Coverage.Limitations {
		if strings.Contains(limitation, "no concerning behavior was observed within covered tests") {
			found = true
		}
	}
	if !found {
		t.Fatalf("coverage limitations must clarify what A means: %#v", grade.Coverage.Limitations)
	}
}

func TestGradeSuccessfulPersistenceEscalatesToF(t *testing.T) {
	evidence := gradableEvidence()
	signals := GradeSignals{Persistence: GradePersistenceSignals{
		Status:   completeAuthoritativeChannel(),
		Findings: []GradePersistenceFinding{{Surface: "autostart", Operation: "open-for-write", Subject: "$HOME/.config/autostart/x.desktop", Outcome: "succeeded", Residual: "confirmed", Delta: 1}},
	}}
	grade := GradeEvidenceWithSignals(evidence, signals)
	if grade.Letter != "F" || !hasEscalator(grade, "successful-persistence") {
		t.Fatalf("persistence grade=%q escalators=%#v", grade.Letter, grade.Escalators)
	}
}

func TestGradeObservationRolesCannotManufactureTypedFindings(t *testing.T) {
	evidence := gradableEvidence()
	evidence.Observations = []Observation{
		{Kind: "file", Operation: "open-for-write", Subject: "$HOME/.bashrc", Outcome: "succeeded", Role: "persistence-confirmed", ExerciseCount: 1, DeltaCount: 1},
		{Kind: "process", Operation: "execute", Subject: "sh", Outcome: "succeeded", Role: "instruction-redirection", ExerciseCount: 1, DeltaCount: 1},
	}
	grade := GradeEvidence(evidence)
	if grade.Letter != "D" || len(grade.Escalators) != 0 || gradeDimension(grade, dimInstruction).Assessed {
		t.Fatalf("free-form roles manufactured typed evidence: grade=%q escalators=%#v instruction=%#v", grade.Letter, grade.Escalators, gradeDimension(grade, dimInstruction))
	}
}

func TestGradeOpenForWriteNeverProvesPersistence(t *testing.T) {
	evidence := gradableEvidence()
	evidence.Observations = []Observation{fileObservation("open-for-write", "$HOME/.bashrc", "succeeded")}
	grade := GradeEvidence(evidence)
	if grade.Letter != "D" || hasEscalator(grade, "successful-persistence") {
		t.Fatalf("open-for-write must be write intent, not durable persistence: grade=%q escalators=%#v", grade.Letter, grade.Escalators)
	}
	if !strings.Contains(strings.Join(gradeDimension(grade, dimPersistence).Reasons, " "), "not confirmed") {
		t.Fatalf("persistence reason must expose the proof gap: %#v", gradeDimension(grade, dimPersistence))
	}
}

func TestGradeConsumesAuthoritativeTypedChannels(t *testing.T) {
	evidence := gradableEvidence()
	signals := GradeSignals{
		Persistence: GradePersistenceSignals{Status: completeAuthoritativeChannel(), Findings: []GradePersistenceFinding{{
			Surface: "shell-init", Operation: "open-for-write", Subject: "$HOME/.bashrc", Outcome: "succeeded", Residual: "confirmed", Delta: 1,
		}}},
		Redirect: GradeRedirectSignals{Status: completeAuthoritativeChannel(), Probes: []GradeRedirectProbe{{
			ID: "workspace-note", Surface: "workspace file", Vector: "file", Attributed: "deviated", Exercised: true, DeviationDelta: 1,
		}}},
		MockEgress: GradeMockEgressSignals{Status: completeAuthoritativeChannel(), Endpoint: "controlled-sink:8443", DeltaRequests: 1, DeltaBytes: 24,
			CanariesObserved: []string{"cloud-credentials"}},
		CanaryStages: GradeCanaryStageSignals{Status: completeAuthoritativeChannel(), Interactions: []GradeCanaryStageInteraction{{
			CanaryID: "cloud-credentials", Stage: "outbound", Coverage: "observed", Delta: 1,
		}}},
		ToolLedger: GradeChannelStatus{Available: true, Complete: true},
	}
	grade := GradeEvidenceWithSignals(evidence, signals)
	if err := ValidateGrade(grade); err != nil {
		t.Fatalf("typed grade invalid: %v", err)
	}
	if grade.Letter != "F" || !hasEscalator(grade, "successful-persistence") || !hasEscalator(grade, "instruction-redirection") || !hasEscalator(grade, "synthetic-canary-propagation") {
		t.Fatalf("typed hostile fixture was not fully graded: letter=%q escalators=%#v", grade.Letter, grade.Escalators)
	}
	for _, escalator := range grade.Escalators {
		if len(escalator.EvidenceRefs) == 0 || escalator.EvidenceRefs[0].Channel == "" {
			t.Fatalf("typed escalator lacks traceable channel reference: %#v", escalator)
		}
	}
}

func TestGradeOutboundCanaryStageDeclaresNetworkBehavior(t *testing.T) {
	evidence := gradableEvidence()
	evidence.Target.DeclaredCapabilities = &DeclaredCapabilities{
		Source: "skill-frontmatter", Declared: true, Capabilities: []string{"credential-access"},
	}
	signals := GradeSignals{CanaryStages: GradeCanaryStageSignals{
		Status: completeAuthoritativeChannel(),
		Interactions: []GradeCanaryStageInteraction{{
			CanaryID: "cloud-credentials", Stage: "outbound", Coverage: "observed", Delta: 1,
		}},
	}}
	grade := GradeEvidenceWithSignals(evidence, signals)
	foundNetwork := false
	for _, capability := range grade.Comparison.ObservedCapabilities {
		foundNetwork = foundNetwork || capability == capNetwork
	}
	if grade.Comparison.Status != "undeclared" || !foundNetwork {
		t.Fatalf("outbound canary stage omitted network capability: %#v", grade.Comparison)
	}
}

func TestGradeRequiredTypedChannelsFailClosed(t *testing.T) {
	for _, test := range []struct {
		name   string
		status GradeChannelStatus
		want   string
	}{
		{"missing", GradeChannelStatus{Required: true}, "missing"},
		{"incomplete", GradeChannelStatus{Required: true, Available: true, Authoritative: true}, "incomplete"},
		{"truncated", GradeChannelStatus{Required: true, Available: true, Complete: true, Truncated: true, Authoritative: true}, "truncated"},
		{"non-authoritative", GradeChannelStatus{Required: true, Available: true, Complete: true}, "non-authoritative"},
	} {
		t.Run(test.name, func(t *testing.T) {
			grade := GradeEvidenceWithSignals(gradableEvidence(), GradeSignals{Persistence: GradePersistenceSignals{Status: test.status}})
			if grade.Graded || grade.Letter != "ungraded" || !strings.Contains(grade.Summary, test.want) {
				t.Fatalf("required %s channel did not fail closed: %#v", test.name, grade)
			}
			if err := ValidateGrade(grade); err != nil {
				t.Fatalf("ungraded result invalid: %v", err)
			}
		})
	}
}

func TestGradeIncompleteTypedChannelPreservesValidProvisionalFinding(t *testing.T) {
	signals := GradeSignals{Persistence: GradePersistenceSignals{
		Status: GradeChannelStatus{Required: true, Available: true, Authoritative: true},
		Findings: []GradePersistenceFinding{{
			Surface: "shell-init", Operation: "open-for-write", Subject: "$HOME/.bashrc",
			Outcome: "succeeded", Residual: "confirmed", Delta: 1,
		}},
	}}
	grade := GradeEvidenceWithSignals(gradableEvidence(), signals)
	if grade.Graded || grade.Letter != "ungraded" || !hasEscalator(grade, "successful-persistence") {
		t.Fatalf("incomplete capture lost valid provisional finding: graded=%v letter=%q escalators=%#v", grade.Graded, grade.Letter, grade.Escalators)
	}
	if gradeDimension(grade, dimPersistence).Severity != "critical" {
		t.Fatalf("provisional persistence severity = %#v", gradeDimension(grade, dimPersistence))
	}
	if err := ValidateGrade(grade); err != nil {
		t.Fatalf("provisional ungraded result invalid: %v", err)
	}
}

func TestGradeRejectsMalformedTypedEvidence(t *testing.T) {
	signals := GradeSignals{MockEgress: GradeMockEgressSignals{
		Status: completeAuthoritativeChannel(), Endpoint: "controlled-sink:8443", DeltaRequests: -1,
	}}
	grade := GradeEvidenceWithSignals(gradableEvidence(), signals)
	if grade.Graded || !strings.Contains(grade.Summary, "malformed typed evidence") {
		t.Fatalf("malformed channel must be ungraded: %#v", grade)
	}
}

func TestGradeRejectsCanaryAttributionWithoutMockEgressTraffic(t *testing.T) {
	signals := GradeSignals{MockEgress: GradeMockEgressSignals{
		Status: completeAuthoritativeChannel(), Endpoint: "controlled-sink:8443",
		CanariesObserved: []string{"cloud-credentials"},
	}}
	grade := GradeEvidenceWithSignals(gradableEvidence(), signals)
	if grade.Graded || hasEscalator(grade, "synthetic-canary-propagation") || !strings.Contains(grade.Summary, "without traffic") {
		t.Fatalf("contradictory mock-egress receipt was accepted: %#v", grade)
	}
}

func TestGradeRejectsUnknownTypedCanaryAttribution(t *testing.T) {
	for _, signals := range []GradeSignals{
		{MockEgress: GradeMockEgressSignals{
			Status: completeAuthoritativeChannel(), Endpoint: "controlled-sink:8443", DeltaRequests: 1, DeltaBytes: 8,
			CanariesObserved: []string{"not-a-planted-canary"},
		}},
		{CanaryStages: GradeCanaryStageSignals{
			Status:       completeAuthoritativeChannel(),
			Interactions: []GradeCanaryStageInteraction{{CanaryID: "not-a-planted-canary", Stage: "outbound", Coverage: "observed", Delta: 1}},
		}},
	} {
		grade := GradeEvidenceWithSignals(gradableEvidence(), signals)
		if grade.Graded || hasEscalator(grade, "synthetic-canary-propagation") {
			t.Fatalf("unknown typed canary manufactured propagation: %#v", grade)
		}
	}
}

func TestGradeRejectsMandatoryToolLedger(t *testing.T) {
	grade := GradeEvidenceWithSignals(gradableEvidence(), GradeSignals{ToolLedger: GradeChannelStatus{
		Required: true, Available: true, Complete: true,
	}})
	if grade.Graded || !strings.Contains(grade.Summary, "must never be mandatory") {
		t.Fatalf("mandatory supplemental ledger was accepted: %#v", grade)
	}
	if err := ValidateGrade(grade); err != nil {
		t.Fatalf("derived fail-closed grade invalid: %v", err)
	}
}

func TestGradeMalformedTypedChannelCannotManufactureFinding(t *testing.T) {
	signals := GradeSignals{Persistence: GradePersistenceSignals{
		Status: completeAuthoritativeChannel(),
		Findings: []GradePersistenceFinding{
			{Surface: "shell-init", Operation: "open-for-write", Subject: "$HOME/.bashrc", Outcome: "succeeded", Residual: "confirmed", Delta: 1},
			{Surface: "", Operation: "open-for-write", Subject: "$HOME/.profile", Outcome: "succeeded", Residual: "confirmed", Delta: 1},
		},
	}}
	grade := GradeEvidenceWithSignals(gradableEvidence(), signals)
	if grade.Graded || hasEscalator(grade, "successful-persistence") || gradeDimension(grade, dimPersistence).Severity != "none" {
		t.Fatalf("malformed channel affected provisional severity: graded=%v escalators=%#v dimension=%#v", grade.Graded, grade.Escalators, gradeDimension(grade, dimPersistence))
	}
}

func TestGradeToolLedgerIsNeverAuthoritativePropagation(t *testing.T) {
	evidence := gradableEvidence()
	evidence.Observations = []Observation{
		{Kind: "process", Operation: "execute", Subject: "[canary:cloud-credentials]", Outcome: "succeeded", Role: "tool-ledger", ExerciseCount: 1, DeltaCount: 1},
		{Kind: "network", Operation: "send", Subject: "[canary:cloud-credentials]->198.51.100.7:443", Outcome: "succeeded", Role: "tool-ledger", ExerciseCount: 1, DeltaCount: 1},
		{Kind: "file", Operation: "open-for-write", Subject: "$HOME/.bashrc", Outcome: "succeeded", Role: "tool-ledger", ExerciseCount: 1, DeltaCount: 1},
	}
	grade := GradeEvidenceWithSignals(evidence, GradeSignals{ToolLedger: GradeChannelStatus{Available: true, Complete: true}})
	if grade.Letter != "A" || len(grade.Escalators) != 0 {
		t.Fatalf("supplemental ledger changed severity: grade=%q dimensions=%#v escalators=%#v", grade.Letter, grade.Dimensions, grade.Escalators)
	}

	signals := GradeSignals{CanaryStages: GradeCanaryStageSignals{
		Status:       completeAuthoritativeChannel(),
		Interactions: []GradeCanaryStageInteraction{{CanaryID: "cloud-credentials", Stage: "tool", Coverage: "limited", Delta: 1}},
	}}
	grade = GradeEvidenceWithSignals(gradableEvidence(), signals)
	if grade.Letter != "D" || len(grade.Escalators) != 0 {
		t.Fatalf("tool-stage signal must stay supplemental: grade=%q escalators=%#v", grade.Letter, grade.Escalators)
	}
}

func TestGradeBoundsComposedChannelReason(t *testing.T) {
	signals := GradeSignals{ToolLedger: GradeChannelStatus{
		Available: true, Complete: true, Authoritative: true, Reason: strings.Repeat("x", 500),
	}}
	grade := GradeEvidenceWithSignals(gradableEvidence(), signals)
	if grade.Graded {
		t.Fatalf("malformed supplemental channel should fail closed: %#v", grade)
	}
	if err := ValidateGrade(grade); err != nil {
		t.Fatalf("derived fail-closed grade invalid: %v", err)
	}
	for _, channel := range grade.Coverage.Channels {
		if channel.ID == "tool-ledger" && (len(channel.Reason) > 500 || !strings.Contains(channel.Reason, "supplemental")) {
			t.Fatalf("tool-ledger channel reason = %q", channel.Reason)
		}
	}
}

func TestGradeMandatoryCanaryChannelFailsClosed(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*Evidence)
	}{
		{"missing", func(e *Evidence) { e.Canaries = e.Canaries[:3] }},
		{"duplicate", func(e *Evidence) { e.Canaries[3] = e.Canaries[0] }},
		{"wrong surface", func(e *Evidence) { e.Canaries[0].Surface = "workspace file" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			evidence := gradableEvidence()
			test.mutate(&evidence)
			grade := GradeEvidence(evidence)
			if grade.Graded || grade.Letter != "ungraded" || !strings.Contains(grade.Summary, "mandatory canary") {
				t.Fatalf("bad canary channel did not fail closed: %#v", grade)
			}
		})
	}
}

func TestGradeOwnedBenignSkillAndPluginFixtures(t *testing.T) {
	for _, test := range []struct {
		name        string
		kind        string
		id          string
		observation *Observation
		want        string
	}{
		{name: "owned skill fixture", kind: "skill", id: "owned-benign-skill", want: "A"},
		{name: "owned plugin fixture", kind: "plugin", id: "owned-benign-plugin", observation: ptrObservation(fileObservation("open-for-read", "$HOME/README.txt", "succeeded")), want: "B"},
	} {
		t.Run(test.name, func(t *testing.T) {
			evidence := gradableEvidence()
			evidence.Target.Kind, evidence.Target.ID, evidence.Target.Name = test.kind, test.id, test.id
			if test.observation != nil {
				evidence.Observations = []Observation{*test.observation}
			}
			if err := ValidateEvidence(evidence); err != nil {
				t.Fatalf("fixture invalid: %v", err)
			}
			grade := GradeEvidence(evidence)
			if !grade.Graded || grade.Letter != test.want {
				t.Fatalf("owned fixture grade=%q, want %q", grade.Letter, test.want)
			}
		})
	}
}

func ptrObservation(observation Observation) *Observation { return &observation }

func TestGradeContainmentBoundaryAttemptsAreRepresentable(t *testing.T) {
	evidence := gradableEvidence()
	evidence.Observations = []Observation{
		networkObservation("93.184.216.34:443", "attempted", "external"),
		fileObservation("open-for-read", "/etc/shadow", "attempted"),
	}
	grade := GradeEvidence(evidence)
	dimension := gradeDimension(grade, dimContainment)
	if dimension.Severity != "elevated" || len(dimension.EvidenceRefs) == 0 {
		t.Fatalf("containment dimension = %#v", dimension)
	}
	if grade.Letter != "D" && grade.Letter != "F" {
		t.Fatalf("blocked attempts should elevate the grade, got %q", grade.Letter)
	}
}

func TestGradeInstructionRedirectionIsOptionalAndModular(t *testing.T) {
	// Absent signal channel: the dimension is explicitly not assessed, never
	// silently treated as clean.
	evidence := gradableEvidence()
	grade := GradeEvidence(evidence)
	instruction := gradeDimension(grade, dimInstruction)
	if instruction.Assessed || instruction.Severity != "not-assessed" {
		t.Fatalf("instruction dimension should be unassessed by default: %#v", instruction)
	}
	if len(grade.Coverage.UnassessedSignals) != 1 || grade.Coverage.UnassessedSignals[0] != dimInstruction {
		t.Fatalf("unassessed signals = %#v", grade.Coverage.UnassessedSignals)
	}

	// Present authoritative probe channel: the escalator fires from the typed
	// attributed deviation, not a free-form observation role.
	signals := GradeSignals{Redirect: GradeRedirectSignals{
		Status: completeAuthoritativeChannel(),
		Probes: []GradeRedirectProbe{{ID: "workspace-note", Surface: "workspace file", Vector: "file", Attributed: "deviated", Exercised: true, DeviationDelta: 1}},
	}}
	grade = GradeEvidenceWithSignals(evidence, signals)
	if grade.Letter != "F" || !hasEscalator(grade, "instruction-redirection") {
		t.Fatalf("instruction redirection grade=%q escalators=%#v", grade.Letter, grade.Escalators)
	}
	if !gradeDimension(grade, dimInstruction).Assessed {
		t.Fatalf("instruction dimension should be assessed once a channel exists")
	}
}

func TestGradeUnexercisedRedirectDeviationIsValidButNonEscalating(t *testing.T) {
	signals := GradeSignals{Redirect: GradeRedirectSignals{
		Status: completeAuthoritativeChannel(),
		Probes: []GradeRedirectProbe{{
			ID: "workspace-note", Surface: "workspace file", Vector: "file",
			Attributed: "deviated", Exercised: false, DeviationDelta: 1,
		}},
	}}
	grade := GradeEvidenceWithSignals(gradableEvidence(), signals)
	if !grade.Graded || grade.Letter != "A" || hasEscalator(grade, "instruction-redirection") {
		t.Fatalf("unexercised deviation should remain valid and non-escalating: %#v", grade)
	}
	if gradeDimension(grade, dimInstruction).Assessed {
		t.Fatalf("unexercised redirect probe must not count as assessed: %#v", gradeDimension(grade, dimInstruction))
	}
}

func TestGradeDeclaredVsObservedConsistentKeepsObservedSeverity(t *testing.T) {
	evidence := gradableEvidence()
	evidence.Observations = []Observation{networkObservation("93.184.216.34:443", "succeeded", "external")}
	evidence.Target.DeclaredCapabilities = &DeclaredCapabilities{Source: "skill-frontmatter", Declared: true, Capabilities: []string{"network"}}
	if err := ValidateEvidence(evidence); err != nil {
		t.Fatalf("evidence invalid: %v", err)
	}
	grade := GradeEvidence(evidence)
	if grade.Comparison.Status != "consistent" {
		t.Fatalf("comparison = %#v", grade.Comparison)
	}
	// Declared outbound is still observed egress: elevated, but not escalated.
	if grade.Letter != "D" {
		t.Fatalf("declared external egress letter = %q", grade.Letter)
	}
	if len(grade.Escalators) != 0 {
		t.Fatalf("declared behavior must not raise a hard escalator: %#v", grade.Escalators)
	}
	if grade.Confidence.Level != "high" {
		t.Fatalf("consistent declaration should support high confidence: %#v", grade.Confidence)
	}
}

func TestGradeUndeclaredOutboundIsElevatedNotHardEscalator(t *testing.T) {
	// Undeclared outbound access is a strong finding, but the hard escalator is
	// reserved for confirmed propagation; undeclared access stays elevated.
	evidence := gradableEvidence()
	evidence.Observations = []Observation{networkObservation("93.184.216.34:443", "succeeded", "external")}
	evidence.Target.DeclaredCapabilities = &DeclaredCapabilities{Source: "plugin-manifest", Declared: true, Capabilities: []string{"filesystem-read"}}
	grade := GradeEvidence(evidence)
	if grade.Comparison.Status != "undeclared" {
		t.Fatalf("comparison = %#v", grade.Comparison)
	}
	if grade.Letter != "D" {
		t.Fatalf("undeclared outbound letter = %q, want D", grade.Letter)
	}
	if len(grade.Escalators) != 0 {
		t.Fatalf("undeclared outbound must not raise a hard escalator: %#v", grade.Escalators)
	}
}

func TestGradeBroadDeclarationDoesNotManufactureCertainty(t *testing.T) {
	// A broad declaration that could cover a credential read must not produce an
	// "undeclared" claim; the observed read stays at its own (moderate) severity.
	evidence := gradableEvidence()
	evidence.Observations = []Observation{fileObservation("open-for-read", "$HOME/.aws/credentials", "succeeded")}
	evidence.Target.DeclaredCapabilities = &DeclaredCapabilities{Source: "skill-frontmatter", Declared: true, Capabilities: []string{"filesystem-read"}}
	grade := GradeEvidence(evidence)
	if grade.Comparison.Status != "declared-broad" {
		t.Fatalf("comparison = %#v", grade.Comparison)
	}
	if len(grade.Escalators) != 0 {
		t.Fatalf("broad declaration must not raise a hard escalator: %#v", grade.Escalators)
	}
	if grade.Letter != "C" {
		t.Fatalf("observed secret read is moderate access, got %q", grade.Letter)
	}
	if grade.Confidence.Level == "high" {
		t.Fatalf("broad declaration should lower confidence: %#v", grade.Confidence)
	}
}

func TestGradeAbsentDeclarationStaysIndeterminateNotDishonest(t *testing.T) {
	// External egress with no declaration must NOT gain a fabricated "undeclared"
	// claim; it stays at the observed severity with lower confidence.
	evidence := gradableEvidence()
	evidence.Observations = []Observation{networkObservation("93.184.216.34:443", "succeeded", "external")}
	grade := GradeEvidence(evidence)
	if grade.Comparison.Status != "indeterminate" {
		t.Fatalf("comparison = %#v", grade.Comparison)
	}
	if grade.Letter != "D" {
		t.Fatalf("absent declaration must not change the observed severity, got %q", grade.Letter)
	}
	if len(grade.Escalators) != 0 {
		t.Fatalf("absent declaration must not raise a hard escalator: %#v", grade.Escalators)
	}
	if grade.Confidence.Level == "high" {
		t.Fatalf("indeterminate comparison should lower confidence: %#v", grade.Confidence)
	}
}

func TestGradeUndeclaredNonSensitiveAccessIsModerateNotHardEscalator(t *testing.T) {
	// A present declaration that omits a plain, non-sensitive external read is an
	// honesty finding (moderate), not one of the named hard escalators.
	evidence := gradableEvidence()
	evidence.Observations = []Observation{fileObservation("open-for-read", "$HOME/notes.txt", "succeeded")}
	evidence.Target.DeclaredCapabilities = &DeclaredCapabilities{Source: "plugin-manifest", Declared: true, Capabilities: []string{"network"}}
	grade := GradeEvidence(evidence)
	if grade.Comparison.Status != "undeclared" {
		t.Fatalf("comparison = %#v", grade.Comparison)
	}
	if grade.Letter != "C" {
		t.Fatalf("undeclared non-sensitive read letter = %q, want C", grade.Letter)
	}
	if len(grade.Escalators) != 0 {
		t.Fatalf("undeclared non-sensitive read must not raise a hard escalator: %#v", grade.Escalators)
	}
	if gradeDimension(grade, dimDeclared).Severity != "moderate" {
		t.Fatalf("declared dimension = %#v", gradeDimension(grade, dimDeclared))
	}
}

func TestGradeIncompleteCaptureIsExplicitlyUngraded(t *testing.T) {
	for _, test := range []struct {
		name    string
		mutate  func(*Evidence)
		wantSub string
	}{
		{"nonzero exercise lane", func(e *Evidence) { e.Run.Status = "incomplete"; e.Run.LaneExitCode.Exercise = 124 }, "exercise lane exit 124"},
		{"unpaired baseline", func(e *Evidence) {
			e.Run.Status = "incomplete"
			e.Coverage.BaselinePaired = false
			e.Coverage.FileSyscalls = false
			e.Coverage.ProcessSyscalls = false
			e.Coverage.NetworkSyscalls = false
			e.Coverage.CanaryStages = canaryStageCoverage(canaryCoverageInputs{PairedAgentOutput: true, AgentOutputComplete: true})
		}, "not paired"},
	} {
		t.Run(test.name, func(t *testing.T) {
			evidence := gradableEvidence()
			// An authoritative trace-level propagation signal is present even
			// though the capture is incomplete, so it remains provisional.
			evidence.Observations = []Observation{{
				Kind: "network", Operation: "send", Subject: "[canary:cloud-credentials]->198.51.100.7:443",
				Outcome: "succeeded", Role: "external", ExerciseCount: 1, DeltaCount: 1,
			}}
			test.mutate(&evidence)
			if err := ValidateEvidence(evidence); err != nil {
				t.Fatalf("evidence invalid: %v", err)
			}
			grade := GradeEvidence(evidence)
			if err := ValidateGrade(grade); err != nil {
				t.Fatalf("grade invalid: %v", err)
			}
			if grade.Graded || grade.Letter != "ungraded" {
				t.Fatalf("incomplete capture graded=%v letter=%q", grade.Graded, grade.Letter)
			}
			if grade.Coverage.Capture != "incomplete" {
				t.Fatalf("coverage = %#v", grade.Coverage)
			}
			if !strings.Contains(grade.Summary, test.wantSub) {
				t.Fatalf("summary = %q, want substring %q", grade.Summary, test.wantSub)
			}
			// Provisional escalators are still surfaced without assigning a letter.
			if !hasEscalator(grade, "synthetic-canary-propagation") {
				t.Fatalf("ungraded result should still surface provisional escalators: %#v", grade.Escalators)
			}
		})
	}
}

func TestGradeIsDeterministicAndReproducibleFromSerializedEvidence(t *testing.T) {
	evidence := gradableEvidence()
	evidence.Observations = []Observation{
		fileObservation("open-for-read", "$HOME/.aws/credentials", "succeeded"),
		networkObservation("93.184.216.34:443", "attempted", "external"),
	}
	evidence.Canaries[0].ExerciseInteractions = 1
	evidence.Canaries[0].DeltaInteractions = 1

	first, err := json.Marshal(GradeEvidence(evidence))
	if err != nil {
		t.Fatal(err)
	}
	second, err := json.Marshal(GradeEvidence(evidence))
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatalf("grade is not deterministic")
	}

	// Re-deriving from serialized evidence yields the identical grade.
	encoded, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Evidence
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	reDerived, err := json.Marshal(GradeEvidence(decoded))
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(reDerived) {
		t.Fatalf("grade is not reproducible from serialized evidence")
	}
}

func TestValidateGradeRejectsTamperedResults(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*Grade)
	}{
		{"schema", func(g *Grade) { g.SchemaVersion = "observatory.grade.v1" }},
		{"policy", func(g *Grade) { g.PolicyVersion = "other" }},
		{"letter", func(g *Grade) { g.Letter = "E" }},
		{"ungraded sentinel", func(g *Grade) { g.Graded = false; g.Letter = "A" }},
		{"confidence", func(g *Grade) { g.Confidence.Level = "certain" }},
		{"missing dimensions", func(g *Grade) { g.Dimensions = g.Dimensions[:1] }},
		{"evidence digest", func(g *Grade) { g.EvidenceRef.EvidenceSHA256 = "sha256:bad" }},
		{"overall letter", func(g *Grade) { g.Letter = "B" }},
		{"dimension order", func(g *Grade) { g.Dimensions[0], g.Dimensions[1] = g.Dimensions[1], g.Dimensions[0] }},
		{"missing channels", func(g *Grade) { g.Coverage.Channels = g.Coverage.Channels[:1] }},
		{"authoritative tool ledger", func(g *Grade) { g.Coverage.Channels[len(g.Coverage.Channels)-1].Authoritative = true }},
		{"unsafe summary", func(g *Grade) { g.Summary = "forged\nsummary" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			grade := GradeEvidence(gradableEvidence())
			test.mutate(&grade)
			if err := ValidateGrade(grade); err == nil {
				t.Fatalf("tampered grade (%s) was accepted", test.name)
			}
		})
	}
}

func TestGradeReferencesEvidenceIdentity(t *testing.T) {
	evidence := gradableEvidence()
	grade := GradeEvidence(evidence)
	if !isSHA256Digest(grade.EvidenceRef.EvidenceSHA256) ||
		!isSHA256Digest(grade.EvidenceRef.SignalProjectionSHA256) ||
		grade.EvidenceRef.TargetSHA256 != evidence.Target.SHA256 ||
		grade.EvidenceRef.CaptureConfigSHA256 != evidence.CaptureConfigSHA256 ||
		grade.EvidenceRef.RunID != evidence.Run.ID ||
		grade.EvidenceRef.EvidenceSchemaVersion != evidence.SchemaVersion {
		t.Fatalf("evidence ref = %#v", grade.EvidenceRef)
	}
	mutated := evidence
	mutated.Target.Name = "same-target-content-different-receipt"
	if GradeEvidence(mutated).EvidenceRef.EvidenceSHA256 == grade.EvidenceRef.EvidenceSHA256 {
		t.Fatal("full evidence digest did not bind a changed evidence field")
	}
	withSignals := GradeEvidenceWithSignals(evidence, GradeSignals{ToolLedger: GradeChannelStatus{Available: true, Complete: true}})
	if withSignals.EvidenceRef.EvidenceSHA256 != grade.EvidenceRef.EvidenceSHA256 ||
		withSignals.EvidenceRef.SignalProjectionSHA256 == grade.EvidenceRef.SignalProjectionSHA256 {
		t.Fatal("signal projection digest did not bind the normalized grading inputs")
	}
}

func TestStageParsesDeclaredCapabilitiesFromPluginManifest(t *testing.T) {
	dir := t.TempDir()
	manifest := `{
	  "id": "declared-probe",
	  "name": "Declared Probe",
	  "contracts": { "tools": ["probe"], "permissions": ["network", "credentials", "made-up"] }
	}`
	if err := os.WriteFile(filepath.Join(dir, "openclaw.plugin.json"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.js"), []byte("export default {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	staged, err := InspectTarget(dir, defaultLimitsForTest())
	if err != nil {
		t.Fatal(err)
	}
	declared := staged.Evidence.DeclaredCapabilities
	if declared == nil || !declared.Declared || declared.Source != "plugin-manifest" {
		t.Fatalf("declared = %#v", declared)
	}
	if !reflect.DeepEqual(declared.Capabilities, []string{"credential-access", "network"}) {
		t.Fatalf("capabilities = %#v", declared.Capabilities)
	}
	if len(declared.Notes) != 1 || !strings.Contains(declared.Notes[0], "made-up") {
		t.Fatalf("notes = %#v", declared.Notes)
	}
	if err := ValidateEvidence(withValidatableTarget(staged.Evidence)); err != nil {
		t.Fatalf("declared capabilities failed evidence validation: %v", err)
	}
}

func TestStageParsesDeclaredCapabilitiesFromSkillFrontmatter(t *testing.T) {
	dir := t.TempDir()
	manifest := "---\nname: perm-skill\npermissions:\n  - network\n  - filesystem-write\n---\n# Body\n"
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	staged, err := InspectTarget(dir, defaultLimitsForTest())
	if err != nil {
		t.Fatal(err)
	}
	declared := staged.Evidence.DeclaredCapabilities
	if declared == nil || declared.Source != "skill-frontmatter" || !declared.Declared {
		t.Fatalf("declared = %#v", declared)
	}
	if !reflect.DeepEqual(declared.Capabilities, []string{"filesystem-write", "network"}) {
		t.Fatalf("capabilities = %#v", declared.Capabilities)
	}
}

func TestStageLeavesDeclaredCapabilitiesAbsentWhenUndeclared(t *testing.T) {
	staged, err := InspectTarget(filepath.Join("..", "..", "testdata", "fixtures", "probe-skill"), defaultLimitsForTest())
	if err != nil {
		t.Fatal(err)
	}
	if staged.Evidence.DeclaredCapabilities != nil {
		t.Fatalf("undeclared skill should have nil declared capabilities: %#v", staged.Evidence.DeclaredCapabilities)
	}
}

func TestValidateEvidenceRejectsInvalidDeclaredCapabilities(t *testing.T) {
	evidence := gradableEvidence()
	evidence.Target.DeclaredCapabilities = &DeclaredCapabilities{Source: "made-up", Declared: true, Capabilities: []string{"network"}}
	if err := ValidateEvidence(evidence); err == nil || !strings.Contains(err.Error(), "source is invalid") {
		t.Fatalf("bad source err = %v", err)
	}
	evidence.Target.DeclaredCapabilities = &DeclaredCapabilities{Source: "plugin-manifest", Declared: true, Capabilities: []string{"network", "filesystem-read"}}
	if err := ValidateEvidence(evidence); err == nil || !strings.Contains(err.Error(), "must be sorted") {
		t.Fatalf("unsorted err = %v", err)
	}
	evidence.Target.DeclaredCapabilities = &DeclaredCapabilities{Source: "plugin-manifest", Declared: false, Capabilities: []string{"network"}}
	if err := ValidateEvidence(evidence); err == nil || !strings.Contains(err.Error(), "not declared") {
		t.Fatalf("present-but-not-declared err = %v", err)
	}
}

func TestScanAttachesGradeAndWritesGradeJSON(t *testing.T) {
	requireLinuxControlHost(t)
	skill := filepath.Join("..", "..", "testdata", "fixtures", "probe-skill")
	config := validTestConfig(t, t.TempDir())
	config.Exercise.Prompt = DefaultExercisePrompt
	result, err := Scan(context.Background(), skill, config, &fixtureExecutor{t: t})
	if err != nil {
		t.Fatal(err)
	}
	if result.Grade.SchemaVersion != GradeSchemaVersion || !result.Grade.Graded {
		t.Fatalf("grade = %#v", result.Grade)
	}
	// The owned hostile probe leaves a confirmed shell-init residual, so the
	// typed persistence channel must raise the deterministic hard escalator.
	if result.Grade.Letter != "F" {
		t.Fatalf("probe grade=%q escalators=%#v", result.Grade.Letter, result.Grade.Escalators)
	}
	if !hasEscalator(result.Grade, "successful-persistence") {
		t.Fatalf("probe persistence must raise its hard escalator: %#v", result.Grade.Escalators)
	}
	if gradeDimension(result.Grade, dimCanary).Severity != "moderate" {
		t.Fatalf("probe canary dimension = %#v", gradeDimension(result.Grade, dimCanary))
	}
	data, err := os.ReadFile(filepath.Join(result.RunDirectory, "grade.json"))
	if err != nil {
		t.Fatal(err)
	}
	var grade Grade
	if err := json.Unmarshal(data, &grade); err != nil {
		t.Fatal(err)
	}
	if err := ValidateGrade(grade); err != nil {
		t.Fatalf("persisted grade invalid: %v", err)
	}
}

func TestRenderSiteIncludesGradeAndWritesGradeJSON(t *testing.T) {
	requireLinuxControlHost(t)
	evidence := gradableEvidence()
	evidence.Observations = []Observation{{
		Kind: "network", Operation: "send", Subject: "[canary:cloud-credentials]->198.51.100.7:443",
		Outcome: "succeeded", Role: "external", ExerciseCount: 1, DeltaCount: 1,
	}}
	evidence.Canaries[0].ExerciseInteractions = 1
	evidence.Canaries[0].DeltaInteractions = 1
	evidence.Canaries[0].Stages = []CanaryStageInteraction{{Stage: CanaryStageOutbound, ExerciseInteractions: 1, DeltaInteractions: 1}}
	output := t.TempDir()
	if err := RenderSite(output, evidence, nil); err != nil {
		t.Fatal(err)
	}
	html, err := os.ReadFile(filepath.Join(output, "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"Deterministic behavioral grade", "Declared vs. observed", "never a universal safety verdict"} {
		if !strings.Contains(string(html), expected) {
			t.Fatalf("rendered HTML missing %q", expected)
		}
	}
	data, err := os.ReadFile(filepath.Join(output, "grade.json"))
	if err != nil {
		t.Fatal(err)
	}
	var grade Grade
	if err := json.Unmarshal(data, &grade); err != nil {
		t.Fatal(err)
	}
	if err := ValidateGrade(grade); err != nil {
		t.Fatalf("rendered grade invalid: %v", err)
	}
	if grade.Letter != "F" {
		t.Fatalf("grade letter = %q", grade.Letter)
	}
}

func defaultLimitsForTest() LimitsConfig {
	config := Config{}
	config.applyDefaults()
	return config.Limits
}

// withValidatableTarget fills in the manifest fields ValidateEvidence requires so
// declared-capability validation can run against otherwise minimal staging output.
func withValidatableTarget(evidence TargetEvidence) Evidence {
	base := gradableEvidence()
	base.Target.DeclaredCapabilities = evidence.DeclaredCapabilities
	base.Target.Kind = "plugin"
	base.Target.ID = "declared-probe"
	return base
}
