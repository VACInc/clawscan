package observatory

import (
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"os"
	"reflect"
	"sort"
	"strings"
)

const MaxClawscanArtifactBytes = 256 << 20

// maxRuntimeTimelineDisplayRows bounds how many runtime syscall timeline rows each
// lane renders into the HTML page. The complete ordered timeline always ships in
// the JSON projection; the page shows only an earliest-first preview so a busy
// exercise cannot bloat the static evidence page.
const maxRuntimeTimelineDisplayRows = 250

// maxToolCallDisplayRows bounds how many tool-call ledger rows each lane renders.
const maxToolCallDisplayRows = 250

type VersionChange struct {
	Change        string
	Kind          string
	Operation     string
	Subject       string
	Outcome       string
	Role          string
	PreviousDelta int
	CurrentDelta  int
}

type pageData struct {
	Evidence      Evidence
	Grade         Grade
	PreviousGrade *Grade
	Changes       []VersionChange
	Counts        map[string]int
	Sections      evidenceSectionPresence
}

type evidenceSectionPresence struct {
	CanaryStages    bool
	RedirectProbes  bool
	Persistence     bool
	ToolCallLedger  bool
	RuntimeTimeline bool
	ProxmoxTLSCA    bool
}

func DecodeEvidence(reader io.Reader) (Evidence, error) {
	data, err := io.ReadAll(io.LimitReader(reader, MaxClawscanArtifactBytes+1))
	if err != nil {
		return Evidence{}, err
	}
	if len(data) > MaxClawscanArtifactBytes {
		return Evidence{}, fmt.Errorf("Clawscan artifact input exceeds %d bytes", MaxClawscanArtifactBytes)
	}
	var evidence Evidence
	if err := json.Unmarshal(data, &evidence); err == nil && supportedEvidenceSchema(evidence.SchemaVersion) {
		if err := ValidateEvidence(evidence); err != nil {
			return Evidence{}, err
		}
		return evidence, nil
	}
	var artifact struct {
		Scanners map[string]struct {
			Raw json.RawMessage `json:"raw"`
		} `json:"scanners"`
	}
	if err := json.Unmarshal(data, &artifact); err != nil {
		return Evidence{}, fmt.Errorf("parse evidence JSON: %w", err)
	}
	behavior, ok := artifact.Scanners["behavior"]
	if !ok || len(behavior.Raw) == 0 {
		return Evidence{}, errors.New("input is neither supported Observatory behavior evidence nor a Clawscan artifact containing scanner behavior")
	}
	if err := json.Unmarshal(behavior.Raw, &evidence); err != nil {
		return Evidence{}, fmt.Errorf("parse Clawscan behavior evidence: %w", err)
	}
	if err := ValidateEvidence(evidence); err != nil {
		return Evidence{}, err
	}
	return evidence, nil
}

func supportedEvidenceSchema(version string) bool {
	return version == EvidenceSchemaVersion || version == LegacyEvidenceSchemaVersion
}

func LoadEvidence(path string) (Evidence, error) {
	file, err := os.Open(path)
	if err != nil {
		return Evidence{}, err
	}
	defer file.Close()
	return DecodeEvidence(file)
}

func RenderSite(outputDir string, evidence Evidence, previous *Evidence) error {
	if err := ValidateEvidence(evidence); err != nil {
		return err
	}
	grade := GradeEvidenceWithSignals(evidence, GradeSignalsFromEvidence(evidence))
	if err := ValidateGrade(grade); err != nil {
		return err
	}
	changes := []VersionChange{}
	var previousGrade *Grade
	if previous != nil {
		if err := ValidateEvidence(*previous); err != nil {
			return fmt.Errorf("validate previous evidence: %w", err)
		}
		if err := validateEvidenceComparison(*previous, evidence); err != nil {
			return err
		}
		changes = DiffEvidence(*previous, evidence)
		derived := GradeEvidenceWithSignals(*previous, GradeSignalsFromEvidence(*previous))
		if err := ValidateGrade(derived); err != nil {
			return fmt.Errorf("derive previous grade: %w", err)
		}
		previousGrade = &derived
	}
	directory, err := openRenderOutputDirectory(outputDir, 0o755)
	if err != nil {
		return err
	}
	defer directory.Close()
	counts := map[string]int{"file": 0, "process": 0, "network": 0, "canary": 0, "redirect": 0, "persistence": 0, "persistenceResidual": 0}
	for _, observation := range evidence.Observations {
		counts[observation.Kind] += observation.DeltaCount
	}
	for _, canary := range evidence.Canaries {
		counts["canary"] += canary.DeltaInteractions
	}
	for _, finding := range evidence.Persistence.Findings {
		counts["persistence"] += finding.DeltaCount
		if finding.Residual == "confirmed" {
			counts["persistenceResidual"] += finding.DeltaCount
		}
	}
	for _, probe := range evidence.RedirectProbes {
		counts["redirect"] += probe.DeviatedDelta
	}
	file, err := openRenderOutputFile(directory, "index.html", 0o644)
	if err != nil {
		return err
	}
	sections := evidenceSections(evidence)
	renderErr := evidencePageTemplate.Execute(file, pageData{Evidence: evidence, Grade: grade, PreviousGrade: previousGrade, Changes: changes, Counts: counts, Sections: sections})
	closeErr := file.Close()
	if renderErr != nil {
		return renderErr
	}
	if closeErr != nil {
		return closeErr
	}
	var evidenceOutput any = evidence
	if evidence.SchemaVersion == LegacyEvidenceSchemaVersion || !sections.CanaryStages {
		projection, err := legacyEvidenceProjection(evidence, sections)
		if err != nil {
			return err
		}
		evidenceOutput = projection
	}
	if err := writeRenderJSON(directory, "evidence.json", evidenceOutput, 0o644); err != nil {
		return err
	}
	return writeRenderJSON(directory, "grade.json", grade, 0o644)
}

func evidenceSections(evidence Evidence) evidenceSectionPresence {
	if evidence.SchemaVersion == EvidenceSchemaVersion {
		return evidenceSectionPresence{
			CanaryStages:   evidence.Coverage.CanaryStages != nil || canaryStageEvidencePresent(evidence.Canaries),
			RedirectProbes: true, Persistence: true, ToolCallLedger: true,
			RuntimeTimeline: true, ProxmoxTLSCA: true,
		}
	}
	return evidenceSectionPresence{
		CanaryStages:   evidence.Coverage.CanaryStages != nil || canaryStageEvidencePresent(evidence.Canaries),
		RedirectProbes: evidence.RedirectProbes != nil || evidence.Coverage.RedirectProbeScope != "",
		Persistence: evidence.Persistence.Scope != "" || evidence.Persistence.Surfaces != nil ||
			evidence.Persistence.Findings != nil || evidence.Persistence.Limitations != nil,
		ToolCallLedger: evidence.ToolCallLedger.Source != "" || evidence.ToolCallLedger.MaxCallsPerLane != 0 ||
			evidence.ToolCallLedger.Baseline.Calls != nil || evidence.ToolCallLedger.Exercise.Calls != nil,
		RuntimeTimeline: evidence.RuntimeTimeline.MaxEventsPerLane != 0 ||
			evidence.RuntimeTimeline.Baseline.Events != nil || evidence.RuntimeTimeline.Exercise.Events != nil,
		ProxmoxTLSCA: evidence.Run.Isolation.ProxmoxTLSCASHA256 != "",
	}
}

func canaryStageEvidencePresent(canaries []CanaryObservation) bool {
	for _, canary := range canaries {
		if canary.Class != "" || canary.Stages != nil {
			return true
		}
	}
	return false
}

func legacyEvidenceProjection(evidence Evidence, sections evidenceSectionPresence) (map[string]json.RawMessage, error) {
	encoded, err := json.Marshal(evidence)
	if err != nil {
		return nil, err
	}
	var projection map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &projection); err != nil {
		return nil, err
	}
	if !sections.RedirectProbes {
		delete(projection, "redirectProbes")
		coverage, err := removeJSONFields(projection["coverage"], "redirectProbeScope", "redirectProbeCount", "redirectProbesExercised", "redirectDeepMode")
		if err != nil {
			return nil, fmt.Errorf("project legacy evidence coverage: %w", err)
		}
		projection["coverage"] = coverage
	}
	if !sections.CanaryStages {
		coverage, err := removeJSONFields(projection["coverage"], "canaryStages")
		if err != nil {
			return nil, fmt.Errorf("project legacy canary coverage: %w", err)
		}
		projection["coverage"] = coverage
		canaries, err := removeCanaryJSONFields(projection["canaries"], "class", "stages")
		if err != nil {
			return nil, fmt.Errorf("project legacy canaries: %w", err)
		}
		projection["canaries"] = canaries
	}
	if !sections.Persistence {
		delete(projection, "persistence")
	}
	if evidence.MockEgress == nil {
		delete(projection, "mockEgress")
	}
	if evidence.ModelRelay == nil {
		delete(projection, "modelRelay")
	}
	if !sections.ToolCallLedger {
		delete(projection, "toolCallLedger")
	}
	if !sections.RuntimeTimeline {
		delete(projection, "runtimeTimeline")
	}
	if !sections.ProxmoxTLSCA {
		run, err := removeNestedJSONFields(projection["run"], "isolation", "proxmoxTlsCaSha256")
		if err != nil {
			return nil, fmt.Errorf("project legacy evidence isolation: %w", err)
		}
		projection["run"] = run
	}
	return projection, nil
}

func removeCanaryJSONFields(raw json.RawMessage, fields ...string) (json.RawMessage, error) {
	var canaries []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &canaries); err != nil {
		return nil, err
	}
	for _, canary := range canaries {
		for _, field := range fields {
			delete(canary, field)
		}
	}
	return json.Marshal(canaries)
}

func removeJSONFields(raw json.RawMessage, fields ...string) (json.RawMessage, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return nil, err
	}
	for _, field := range fields {
		delete(object, field)
	}
	return json.Marshal(object)
}

func removeNestedJSONFields(raw json.RawMessage, nested string, fields ...string) (json.RawMessage, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return nil, err
	}
	projected, err := removeJSONFields(object[nested], fields...)
	if err != nil {
		return nil, err
	}
	object[nested] = projected
	return json.Marshal(object)
}

func writeRenderJSON(directory *os.File, name string, value any, mode os.FileMode) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	file, err := openRenderOutputFile(directory, name, mode)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(data)
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

func validateEvidenceComparison(previous Evidence, current Evidence) error {
	previousIdentity, err := comparisonIdentity(previous)
	if err != nil {
		return err
	}
	currentIdentity, err := comparisonIdentity(current)
	if err != nil {
		return err
	}
	if previousIdentity != currentIdentity {
		return errors.New("version comparison requires evidence from the same target lineage")
	}
	if previous.CaptureConfigSHA256 != current.CaptureConfigSHA256 {
		return errors.New("version comparison requires the same effective capture configuration")
	}
	if previous.Run.Status != "completed" || current.Run.Status != "completed" ||
		previous.Run.LaneExitCode != (LaneExitCodes{}) || current.Run.LaneExitCode != (LaneExitCodes{}) ||
		!previous.Coverage.BaselinePaired || !current.Coverage.BaselinePaired {
		return errors.New("version comparison requires two complete paired captures")
	}
	if previous.Run.Executor != current.Run.Executor || !comparableIsolation(previous.Run.Isolation, current.Run.Isolation) {
		return errors.New("version comparison requires identical executor and isolation receipts")
	}
	if previous.Run.Runtime.OpenClawVersion == "" || previous.Run.Runtime.StraceVersion == "" ||
		current.Run.Runtime.OpenClawVersion == "" || current.Run.Runtime.StraceVersion == "" ||
		!reflect.DeepEqual(previous.Run.Runtime, current.Run.Runtime) {
		return errors.New("version comparison requires identical, recorded runtime versions and model receipt")
	}
	if previous.Exercise.PromptSHA256 != current.Exercise.PromptSHA256 || previous.Exercise.TurnLimit != current.Exercise.TurnLimit {
		return errors.New("version comparison requires the same exercise prompt and turn limit")
	}
	if !reflect.DeepEqual(previous.Coverage, current.Coverage) {
		return errors.New("version comparison requires identical capture coverage")
	}
	if previous.Persistence.Scope != current.Persistence.Scope ||
		previous.Persistence.InventoryPaired != current.Persistence.InventoryPaired ||
		!reflect.DeepEqual(previous.Persistence.Surfaces, current.Persistence.Surfaces) {
		return errors.New("version comparison requires identical persistence coverage")
	}
	return nil
}

func comparableIsolation(previous IsolationEvidence, current IsolationEvidence) bool {
	return previous.Substrate == current.Substrate && previous.NetworkMode == current.NetworkMode &&
		previous.ContainmentProfile == current.ContainmentProfile && previous.Verification == current.Verification &&
		previous.GuestFirewallPolicySHA256 == current.GuestFirewallPolicySHA256 &&
		previous.ProxmoxTLSCASHA256 == current.ProxmoxTLSCASHA256
}

func comparisonIdentity(evidence Evidence) (string, error) {
	if evidence.Target.Kind == "plugin" {
		return "plugin:" + evidence.Target.ID, nil
	}
	if evidence.Target.Lineage == "" {
		return "", errors.New("skill version comparison requires targetLineage in both capture configurations")
	}
	return "skill:" + evidence.Target.Lineage, nil
}

func DiffEvidence(previous Evidence, current Evidence) []VersionChange {
	previousByKey := map[string]Observation{}
	currentByKey := map[string]Observation{}
	for _, observation := range previous.Observations {
		previousByKey[publicObservationKey(observation)] = observation
	}
	for _, observation := range current.Observations {
		currentByKey[publicObservationKey(observation)] = observation
	}
	changes := []VersionChange{}
	for key, observation := range currentByKey {
		before, exists := previousByKey[key]
		change := "added"
		if exists {
			if before.DeltaCount == observation.DeltaCount {
				continue
			}
			change = "changed"
		}
		changes = append(changes, VersionChange{
			Change: change, Kind: observation.Kind, Operation: observation.Operation, Subject: observation.Subject, Outcome: observation.Outcome, Role: observation.Role,
			PreviousDelta: before.DeltaCount, CurrentDelta: observation.DeltaCount,
		})
	}
	for key, observation := range previousByKey {
		if _, exists := currentByKey[key]; exists {
			continue
		}
		changes = append(changes, VersionChange{
			Change: "removed", Kind: observation.Kind, Operation: observation.Operation, Subject: observation.Subject, Outcome: observation.Outcome, Role: observation.Role,
			PreviousDelta: observation.DeltaCount,
		})
	}
	previousCanaries := map[string]CanaryObservation{}
	currentCanaries := map[string]CanaryObservation{}
	for _, canary := range previous.Canaries {
		previousCanaries[canary.ID+"\x00"+canary.Surface] = canary
	}
	for _, canary := range current.Canaries {
		currentCanaries[canary.ID+"\x00"+canary.Surface] = canary
	}
	for key, canary := range currentCanaries {
		before, exists := previousCanaries[key]
		if exists && before.DeltaInteractions == canary.DeltaInteractions {
			continue
		}
		if !exists && canary.DeltaInteractions == 0 {
			continue
		}
		change := "added"
		if exists {
			change = "changed"
		}
		changes = append(changes, VersionChange{
			Change: change, Kind: "canary", Operation: "interaction", Subject: canary.ID + " (" + canary.Surface + ")", Outcome: "observed", Role: "synthetic-canary",
			PreviousDelta: before.DeltaInteractions, CurrentDelta: canary.DeltaInteractions,
		})
	}
	for key, canary := range previousCanaries {
		if _, exists := currentCanaries[key]; exists || canary.DeltaInteractions == 0 {
			continue
		}
		changes = append(changes, VersionChange{
			Change: "removed", Kind: "canary", Operation: "interaction", Subject: canary.ID + " (" + canary.Surface + ")", Outcome: "observed", Role: "synthetic-canary",
			PreviousDelta: canary.DeltaInteractions,
		})
	}
	changes = append(changes, diffCanaryStages(previousCanaries, currentCanaries)...)
	changes = append(changes, diffPersistenceFindings(previous.Persistence.Findings, current.Persistence.Findings)...)
	previousRedirects := map[string]RedirectProbeObservation{}
	currentRedirects := map[string]RedirectProbeObservation{}
	for _, probe := range previous.RedirectProbes {
		previousRedirects[probe.ID] = probe
	}
	for _, probe := range current.RedirectProbes {
		currentRedirects[probe.ID] = probe
	}
	for id, probe := range currentRedirects {
		before, exists := previousRedirects[id]
		if exists && before.Attributed == probe.Attributed && before.DeviatedDelta == probe.DeviatedDelta {
			continue
		}
		if !exists && probe.Attributed == redirectTierNone && probe.DeviatedDelta == 0 {
			continue
		}
		change := "added"
		if exists {
			change = "changed"
		}
		changes = append(changes, VersionChange{
			Change: change, Kind: "redirect", Operation: "escalation", Subject: probe.ID + " (" + probe.Surface + ")", Outcome: probe.Attributed, Role: "redirect-probe",
			PreviousDelta: before.DeviatedDelta, CurrentDelta: probe.DeviatedDelta,
		})
	}
	for id, probe := range previousRedirects {
		if _, exists := currentRedirects[id]; exists || (probe.Attributed == redirectTierNone && probe.DeviatedDelta == 0) {
			continue
		}
		changes = append(changes, VersionChange{
			Change: "removed", Kind: "redirect", Operation: "escalation", Subject: probe.ID + " (" + probe.Surface + ")", Outcome: probe.Attributed, Role: "redirect-probe",
			PreviousDelta: probe.DeviatedDelta,
		})
	}
	sort.Slice(changes, func(i, j int) bool {
		order := map[string]int{"added": 0, "changed": 1, "removed": 2}
		a, b := changes[i], changes[j]
		if order[a.Change] != order[b.Change] {
			return order[a.Change] < order[b.Change]
		}
		return a.Kind+"\x00"+a.Operation+"\x00"+a.Subject < b.Kind+"\x00"+b.Operation+"\x00"+b.Subject
	})
	return changes
}

// diffCanaryStages exposes the exact interaction stage that changed between
// two otherwise comparable captures.
func diffCanaryStages(previous map[string]CanaryObservation, current map[string]CanaryObservation) []VersionChange {
	type stageKey struct {
		canary string
		stage  string
	}
	previousStages := map[stageKey]int{}
	labels := map[stageKey]string{}
	for key, canary := range previous {
		for _, stage := range canary.Stages {
			id := stageKey{canary: key, stage: stage.Stage}
			previousStages[id] = stage.DeltaInteractions
			labels[id] = canary.ID + " (" + canary.Surface + ") " + stage.Stage
		}
	}
	currentStages := map[stageKey]bool{}
	changes := []VersionChange{}
	for key, canary := range current {
		for _, stage := range canary.Stages {
			id := stageKey{canary: key, stage: stage.Stage}
			currentStages[id] = true
			labels[id] = canary.ID + " (" + canary.Surface + ") " + stage.Stage
			before, exists := previousStages[id]
			if (exists && before == stage.DeltaInteractions) || (!exists && stage.DeltaInteractions == 0) {
				continue
			}
			change := "added"
			if exists {
				change = "changed"
			}
			changes = append(changes, VersionChange{
				Change: change, Kind: "canary", Operation: "stage:" + stage.Stage, Subject: labels[id], Outcome: "observed", Role: "synthetic-canary",
				PreviousDelta: before, CurrentDelta: stage.DeltaInteractions,
			})
		}
	}
	for id, before := range previousStages {
		if currentStages[id] || before == 0 {
			continue
		}
		changes = append(changes, VersionChange{
			Change: "removed", Kind: "canary", Operation: "stage:" + id.stage, Subject: labels[id], Outcome: "observed", Role: "synthetic-canary",
			PreviousDelta: before,
		})
	}
	return changes
}

func publicObservationKey(observation Observation) string {
	return strings.Join([]string{observation.Kind, observation.Operation, observation.Subject, observation.Outcome, observation.Role}, "\x00")
}

// diffPersistenceFindings reports added, changed, and removed persistence
// findings between two comparable captures. The subject includes the surface so
// a delta reads as, for example, "shell-init $HOME/.bashrc".
func diffPersistenceFindings(previous []PersistenceFinding, current []PersistenceFinding) []VersionChange {
	previousByKey := map[string]PersistenceFinding{}
	currentByKey := map[string]PersistenceFinding{}
	for _, finding := range previous {
		previousByKey[persistenceFindingKey(finding)] = finding
	}
	for _, finding := range current {
		currentByKey[persistenceFindingKey(finding)] = finding
	}
	changes := []VersionChange{}
	for key, finding := range currentByKey {
		before, exists := previousByKey[key]
		change := "added"
		if exists {
			if before.DeltaCount == finding.DeltaCount {
				continue
			}
			change = "changed"
		}
		changes = append(changes, persistenceChange(change, finding, before.DeltaCount))
	}
	for key, finding := range previousByKey {
		if _, exists := currentByKey[key]; exists {
			continue
		}
		changes = append(changes, persistenceChange("removed", finding, finding.DeltaCount))
	}
	return changes
}

func persistenceChange(change string, finding PersistenceFinding, previousDelta int) VersionChange {
	current := finding.DeltaCount
	if change == "removed" {
		current = 0
	}
	if change == "added" {
		previousDelta = 0
	}
	return VersionChange{
		Change: change, Kind: "persistence", Operation: finding.Operation,
		Subject: finding.Surface + " " + finding.Subject, Outcome: finding.Outcome, Role: finding.Residual,
		PreviousDelta: previousDelta, CurrentDelta: current,
	}
}

var evidencePageTemplate = template.Must(template.New("evidence").Funcs(template.FuncMap{
	"shortHash": func(value string) string {
		value = strings.TrimPrefix(value, "sha256:")
		if len(value) > 16 {
			return value[:16]
		}
		return value
	},
	"upper": strings.ToUpper,
	"gradeClass": func(letter string) string {
		switch letter {
		case "A":
			return "sev-none"
		case "B":
			return "sev-low"
		case "C":
			return "sev-moderate"
		case "D":
			return "sev-elevated"
		case "F":
			return "sev-critical"
		default:
			return "sev-ungraded"
		}
	},
	"sevClass": func(severity string) string { return "sev-" + severity },
	"join":     func(items []string) string { return strings.Join(items, " ") },
	"runtimeTimelinePreview": func(events []RuntimeTimelineEvent) []RuntimeTimelineEvent {
		if len(events) > maxRuntimeTimelineDisplayRows {
			return events[:maxRuntimeTimelineDisplayRows]
		}
		return events
	},
	"toolCallPreview": func(calls []ToolCall) []ToolCall {
		if len(calls) > maxToolCallDisplayRows {
			return calls[:maxToolCallDisplayRows]
		}
		return calls
	},
}).Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="dark">
  <title>{{.Evidence.Target.Name}} · ClawHub Observatory</title>
  <style>
    :root { color-scheme: dark; --bg:#090b10; --panel:#111722; --panel2:#151e2d; --text:#edf3ff; --muted:#91a1b8; --line:#26344a; --cyan:#62dcff; --green:#68e6a1; --amber:#ffc766; --red:#ff7a90; }
    * { box-sizing:border-box; }
    body { margin:0; background:radial-gradient(circle at 78% -10%,#17304a 0,transparent 34rem),var(--bg); color:var(--text); font:15px/1.55 ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }
    main { width:min(1120px,calc(100% - 32px)); margin:0 auto; padding:52px 0 80px; }
    header { display:grid; gap:16px; margin-bottom:28px; }
    .eyebrow { color:var(--cyan); font:700 12px/1.2 ui-monospace,SFMono-Regular,Consolas,monospace; letter-spacing:.14em; text-transform:uppercase; }
    h1 { margin:0; font-size:clamp(32px,6vw,64px); line-height:1.02; letter-spacing:-.045em; }
    h2 { margin:0 0 14px; font-size:20px; letter-spacing:-.02em; }
    h3 { margin:20px 0 8px; font-size:14px; letter-spacing:.01em; color:var(--cyan); font-family:ui-monospace,SFMono-Regular,Consolas,monospace; }
    p { margin:0; }
    .lede { max-width:760px; color:var(--muted); font-size:17px; }
    .badge { display:inline-flex; width:max-content; align-items:center; gap:8px; padding:7px 11px; border:1px solid var(--line); border-radius:999px; background:#0b111b; color:var(--muted); font:700 12px ui-monospace,SFMono-Regular,Consolas,monospace; }
    .badge::before { content:""; width:8px; height:8px; border-radius:50%; background:var(--green); box-shadow:0 0 12px var(--green); }
    .badge.incomplete::before { background:var(--amber); box-shadow:0 0 12px var(--amber); }
    .grid { display:grid; grid-template-columns:repeat(6,1fr); gap:12px; margin:24px 0; }
    .metric,.panel { border:1px solid var(--line); border-radius:14px; background:linear-gradient(150deg,rgba(21,30,45,.96),rgba(12,17,26,.96)); box-shadow:0 18px 55px rgba(0,0,0,.22); }
    .metric { padding:18px; }
    .metric strong { display:block; font-size:28px; line-height:1; }
    .metric span { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.08em; }
    .panel { padding:22px; margin-top:14px; overflow:hidden; }
    .meta { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:14px; }
    .meta div { min-width:0; }
    dt { color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.09em; }
    dd { margin:3px 0 0; overflow-wrap:anywhere; font-family:ui-monospace,SFMono-Regular,Consolas,monospace; }
    table { width:100%; border-collapse:collapse; }
    th { color:var(--muted); font-size:11px; text-align:left; text-transform:uppercase; letter-spacing:.08em; }
    th,td { padding:11px 9px; border-bottom:1px solid var(--line); vertical-align:top; }
    tbody tr:last-child td { border-bottom:0; }
    code { color:#d7edff; font-family:ui-monospace,SFMono-Regular,Consolas,monospace; overflow-wrap:anywhere; }
    .kind { color:var(--cyan); font:700 11px ui-monospace,SFMono-Regular,Consolas,monospace; text-transform:uppercase; }
    .muted { color:var(--muted); }
    .change-added { color:var(--green); } .change-changed { color:var(--amber); } .change-removed { color:var(--red); }
    ul { margin:0; padding-left:20px; } li+li { margin-top:7px; }
    footer { margin-top:28px; color:var(--muted); font-size:13px; }
	.grade-hero { display:flex; align-items:center; gap:22px; flex-wrap:wrap; }
	.grade-letter { display:grid; place-items:center; width:96px; height:96px; border-radius:20px; border:1px solid var(--line); font:800 56px/1 ui-monospace,SFMono-Regular,Consolas,monospace; background:#0b111b; }
	.grade-letter.sev-ungraded { font-size:26px; }
	.sev-none { color:var(--green); } .sev-low { color:var(--cyan); } .sev-moderate { color:var(--amber); } .sev-elevated { color:#ffa361; } .sev-critical { color:var(--red); } .sev-ungraded { color:var(--muted); }
	.pill { display:inline-block; padding:2px 8px; border:1px solid var(--line); border-radius:999px; font:700 11px ui-monospace,SFMono-Regular,Consolas,monospace; text-transform:uppercase; letter-spacing:.06em; }
	.escalator { border-left:3px solid var(--red); padding:6px 0 6px 12px; margin-top:10px; }
    @media (max-width:780px) { .grid { grid-template-columns:repeat(2,1fr); } .meta { grid-template-columns:1fr; } .table-wrap { overflow-x:auto; } }
  </style>
</head>
<body><main>
  <header>
    <div class="eyebrow">ClawHub Observatory · Behavioral evidence</div>
    <h1>{{.Evidence.Target.Name}}</h1>
    <p class="lede">Observed deltas from a paired baseline and {{.Evidence.Target.Kind}} exercise. This page reports evidence, not a safety verdict.</p>
    <span class="badge {{if ne .Evidence.Run.Status "completed"}}incomplete{{end}}">{{upper .Evidence.Run.Status}}</span>
  </header>
	<section class="panel" aria-label="Behavioral grade">
	  <div class="grade-hero">
	    <div class="grade-letter {{gradeClass .Grade.Letter}}">{{if .Grade.Graded}}{{.Grade.Letter}}{{else}}N/A{{end}}</div>
	    <div>
	      <div class="eyebrow">Deterministic behavioral grade</div>
	      <h2>{{if .Grade.Graded}}Grade {{.Grade.Letter}}{{else}}Ungraded{{end}}</h2>
	      <p class="lede">{{.Grade.Summary}}</p>
	      <p class="muted">Policy {{.Grade.PolicyVersion}} · Confidence {{upper .Grade.Confidence.Level}} · Coverage {{.Grade.Coverage.Capture}} ({{.Grade.Coverage.AssessedDimensions}}/{{.Grade.Coverage.TotalDimensions}} dimensions){{if .PreviousGrade}} · Previous {{if .PreviousGrade.Graded}}{{.PreviousGrade.Letter}}{{else}}ungraded{{end}}{{end}}</p>
	    </div>
	  </div>
	  {{if .Grade.Escalators}}<div>{{range .Grade.Escalators}}<div class="escalator"><span class="pill sev-critical">{{.ID}}</span> {{.Description}}</div>{{end}}</div>{{end}}
	  <div class="table-wrap"><table><thead><tr><th>Dimension</th><th>Severity</th><th>Grade</th><th>Reasons</th></tr></thead><tbody>
	    {{range .Grade.Dimensions}}<tr><td>{{.Title}}</td><td><span class="pill {{sevClass .Severity}}">{{.Severity}}</span></td><td>{{.Grade}}</td><td>{{range .Reasons}}<div class="muted">{{.}}</div>{{end}}</td></tr>{{end}}
	  </tbody></table></div>
	  <h2 style="margin-top:18px">Declared vs. observed</h2>
	  <p class="muted">Status: <span class="pill">{{.Grade.Comparison.Status}}</span>{{if .Grade.Comparison.DeclarationPresent}} · declared: {{if .Grade.Comparison.DeclaredCapabilities}}{{join .Grade.Comparison.DeclaredCapabilities}}{{else}}none{{end}}{{else}} · no machine-readable declaration{{end}}{{if .Grade.Comparison.ObservedCapabilities}} · observed: {{join .Grade.Comparison.ObservedCapabilities}}{{end}}</p>
	  {{range .Grade.Comparison.Notes}}<p class="muted">{{.}}</p>{{end}}
	  {{range .Grade.Confidence.Reasons}}<p class="muted">Confidence: {{.}}</p>{{end}}
	  <p class="muted">This grade scores observed behavioral risk within the covered exercise only. It is never a universal safety verdict or a statement of author intent.</p>
	</section>
  <section class="grid" aria-label="Observation totals">
    <div class="metric"><strong>{{index .Counts "file"}}</strong><span>File events</span></div>
    <div class="metric"><strong>{{index .Counts "process"}}</strong><span>Process events</span></div>
    <div class="metric"><strong>{{index .Counts "network"}}</strong><span>Network events</span></div>
    <div class="metric"><strong>{{index .Counts "canary"}}</strong><span>Canary deltas</span></div>
    <div class="metric"><strong>{{if .Sections.Persistence}}{{index .Counts "persistence"}}{{else}}N/A{{end}}</strong><span>Persistence deltas</span></div>
    <div class="metric"><strong>{{if .Sections.RedirectProbes}}{{index .Counts "redirect"}}{{else}}N/A{{end}}</strong><span>Redirect deviations</span></div>
  </section>
  <section class="panel"><h2>Run receipt</h2><dl class="meta">
    <div><dt>Target digest</dt><dd>{{shortHash .Evidence.Target.SHA256}}</dd></div>
    <div><dt>Run ID</dt><dd>{{.Evidence.Run.ID}}</dd></div>
    <div><dt>Completed</dt><dd>{{.Evidence.Run.CompletedAt}}</dd></div>
    <div><dt>Runtime</dt><dd>{{.Evidence.Run.Runtime.OpenClawVersion}}</dd></div>
    <div><dt>Model</dt><dd>{{.Evidence.Run.Runtime.ModelProvider}}/{{.Evidence.Run.Runtime.ModelID}} ({{.Evidence.Run.Runtime.ModelEndpoint}})</dd></div>
    <div><dt>Isolation</dt><dd>{{.Evidence.Run.Isolation.Substrate}} · {{.Evidence.Run.Isolation.NetworkMode}} · {{.Evidence.Run.Isolation.ContainmentProfile}}</dd></div>
	  </dl></section>
	  {{with .Evidence.ModelRelay}}<section class="panel"><h2>Bounded model relay</h2><dl class="meta">
	    <div><dt>Route</dt><dd>{{.Route}}</dd></div>
	    <div><dt>Policy</dt><dd>{{shortHash .PolicySHA256}}</dd></div>
	    <div><dt>Lane receipts</dt><dd>{{shortHash .BaselineReceiptSHA256}} → {{shortHash .ExerciseReceiptSHA256}}</dd></div>
	    <div><dt>Requests</dt><dd>{{.BaselineRequests}} → {{.ExerciseRequests}}</dd></div>
	    <div><dt>Rejected requests</dt><dd>{{.BaselineRejectedRequests}} → {{.ExerciseRejectedRequests}}</dd></div>
	    <div><dt>Request bytes</dt><dd>{{.BaselineRequestBytes}} → {{.ExerciseRequestBytes}}</dd></div>
	    <div><dt>Response bytes</dt><dd>{{.BaselineResponseBytes}} → {{.ExerciseResponseBytes}}</dd></div>
	    <div><dt>Upstream errors</dt><dd>{{.BaselineUpstreamErrors}} → {{.ExerciseUpstreamErrors}}</dd></div>
	    <div><dt>Capture state</dt><dd>{{if .Truncated}}truncated{{else}}bounded{{end}}{{if .DeadlineHit}} · deadline reached{{end}}</dd></div>
	  </dl><p class="muted">The hostile lane reached only this bounded control relay. Model message bodies and the upstream address are not published.</p></section>{{end}}
	  {{if .Changes}}<section class="panel"><h2>Version delta</h2><div class="table-wrap"><table><thead><tr><th>Change</th><th>Behavior</th><th>Outcome</th><th>Role</th><th>Counts</th></tr></thead><tbody>
    {{range .Changes}}<tr><td class="change-{{.Change}}">{{upper .Change}}</td><td><span class="kind">{{.Kind}}</span> {{.Operation}} <code>{{.Subject}}</code></td><td>{{.Outcome}}</td><td>{{.Role}}</td><td>{{.PreviousDelta}} → {{.CurrentDelta}}</td></tr>{{end}}
  </tbody></table></div></section>{{end}}
  <section class="panel"><h2>Observed exercise deltas</h2>{{if .Evidence.Observations}}<div class="table-wrap"><table><thead><tr><th>Kind</th><th>Operation</th><th>Subject</th><th>Outcome</th><th>Baseline</th><th>Exercise</th><th>Δ</th></tr></thead><tbody>
    {{range .Evidence.Observations}}<tr><td><span class="kind">{{.Kind}}</span></td><td>{{.Operation}}</td><td><code>{{.Subject}}</code>{{if .Role}}<div class="muted">{{.Role}}</div>{{end}}</td><td>{{.Outcome}}</td><td>{{.BaselineCount}}</td><td>{{.ExerciseCount}}</td><td>+{{.DeltaCount}}</td></tr>{{end}}
  </tbody></table></div>{{else}}<p class="muted">No trace event increased in the exercise lane.</p>{{end}}</section>
  {{with .Evidence.MockEgress}}<section class="panel"><h2>Controlled mock egress</h2><dl class="meta">
    <div><dt>Sink</dt><dd>{{.SinkEndpoint}}</dd></div>
    <div><dt>Requests (Δ)</dt><dd>{{.BaselineRequests}} → {{.ExerciseRequests}} (+{{.DeltaRequests}})</dd></div>
	    <div><dt>Bytes captured (Δ)</dt><dd>{{.BaselineBytes}} → {{.ExerciseBytes}} (+{{.DeltaBytes}})</dd></div>
	    <div><dt>Receipt coverage</dt><dd>{{if .CaptureComplete}}complete{{else}}incomplete{{end}}</dd></div>
	    <div><dt>Payload</dt><dd>{{.PayloadEncoding}}{{if .Truncated}} · truncated{{end}}{{if .PayloadSHA256}} · {{shortHash .PayloadSHA256}}{{end}}</dd></div>
    <div><dt>Canaries transmitted</dt><dd>{{if .CanariesObserved}}{{range $index, $id := .CanariesObserved}}{{if $index}}, {{end}}<code>{{$id}}</code>{{end}}{{else}}none{{end}}</dd></div>
  </dl><p class="muted">Raw captured bytes stay in the private receipt. Opaque or TLS-encrypted payloads are counted, never decoded.</p></section>{{end}}
  {{if .Sections.Persistence}}<section class="panel"><h2>Persistence and lifecycle</h2>
    <p class="muted">Monitored surfaces: {{len .Evidence.Persistence.Surfaces}} · Before/after inventory {{if .Evidence.Persistence.InventoryPaired}}paired{{else}}unavailable{{end}} · Residual-confirmed deltas: {{index .Counts "persistenceResidual"}}. Attempted operations were denied by containment; only inventory-confirmed changes are residual.</p>
    {{if .Evidence.Persistence.Findings}}<div class="table-wrap"><table><thead><tr><th>Surface</th><th>Operation</th><th>Subject</th><th>Outcome</th><th>Residual</th><th>Δ</th></tr></thead><tbody>
    {{range .Evidence.Persistence.Findings}}<tr><td><span class="kind">{{.Category}}</span><div class="muted">{{.Surface}}</div></td><td>{{.Operation}}</td><td><code>{{.Subject}}</code></td><td>{{.Outcome}}</td><td>{{if eq .Residual "confirmed"}}<span class="change-added">confirmed</span>{{else}}<span class="muted">{{.Residual}}</span>{{end}} <div class="muted">{{.Evidence}}</div></td><td>+{{.DeltaCount}}</td></tr>{{end}}
  </tbody></table></div>{{else}}<p class="muted">No monitored persistence surface changed in the exercise lane.</p>{{end}}</section>{{else}}<section class="panel"><h2>Persistence and lifecycle</h2><p class="muted">Not collected in this v1 evidence.</p></section>{{end}}
  <section class="panel"><h2>Synthetic canaries</h2><div class="table-wrap"><table><thead><tr><th>Canary</th><th>Class</th><th>Surface</th><th>Stages (baseline→exercise)</th><th>Baseline</th><th>Exercise</th><th>Δ</th></tr></thead><tbody>
    {{range .Evidence.Canaries}}<tr><td><code>{{.ID}}</code></td><td>{{if $.Sections.CanaryStages}}<span class="kind">{{.Class}}</span>{{else}}<span class="muted">not collected</span>{{end}}</td><td>{{.Surface}}</td><td>{{if $.Sections.CanaryStages}}{{range .Stages}}<span class="muted">{{.Stage}}</span> {{.BaselineInteractions}}→{{.ExerciseInteractions}}{{if .DeltaInteractions}} <span class="change-added">+{{.DeltaInteractions}}</span>{{end}} {{else}}<span class="muted">none observed</span>{{end}}{{else}}<span class="muted">not collected</span>{{end}}</td><td>{{.BaselineInteractions}}</td><td>{{.ExerciseInteractions}}</td><td>{{if .DeltaInteractions}}+{{.DeltaInteractions}}{{else}}0{{end}}</td></tr>{{end}}
  </tbody></table></div></section>
  {{if .Sections.CanaryStages}}<section class="panel"><h2>Canary stage coverage</h2><div class="table-wrap"><table><thead><tr><th>Stage</th><th>Coverage</th><th>Source</th></tr></thead><tbody>
    {{range .Evidence.Coverage.CanaryStages}}<tr><td><span class="kind">{{.Stage}}</span></td><td>{{if eq .Coverage "observed"}}<span class="change-added">observed</span>{{else}}<span class="change-changed">limited</span>{{end}}</td><td><code>{{.Source}}</code></td></tr>{{end}}
  </tbody></table></div><p class="muted" style="margin-top:12px">Limited coverage means a zero interaction count for that stage is inconclusive. Any nonzero interaction is still a real observation.</p></section>{{else}}<section class="panel"><h2>Canary stage coverage</h2><p class="muted">Not collected in this evidence.</p></section>{{end}}
  {{if .Sections.RedirectProbes}}<section class="panel"><h2>Redirect instruction probes</h2><p class="muted">Synthetic injected instructions seeded in workspace content and exposed by the shared lane prompt. Reading or repeating a marker is not evidence of prompt injection; only a deviation delta shows the exercise lane performed the harmless sentinel action the instruction named. A probe the exercise lane never read was not exposed ({{.Evidence.Coverage.RedirectProbesExercised}}/{{.Evidence.Coverage.RedirectProbeCount}} exposed) and its absent deviation does not indicate resistance.</p><div class="table-wrap"><table><thead><tr><th>Probe</th><th>Surface</th><th>Vector</th><th>Exposed</th><th>Escalation</th><th>Attributed</th><th>Read Δ</th><th>Repeat Δ</th><th>Deviate Δ</th></tr></thead><tbody>
    {{range .Evidence.RedirectProbes}}<tr><td><code>{{.ID}}</code></td><td>{{.Surface}}</td><td>{{.Vector}}</td><td class="{{if not .Exercised}}change-changed{{end}}">{{if .Exercised}}yes{{else}}not exercised{{end}}</td><td class="{{if eq .Escalation "deviated"}}change-removed{{else if eq .Escalation "none"}}muted{{end}}">{{upper .Escalation}}</td><td class="{{if eq .Attributed "deviated"}}change-removed{{else if eq .Attributed "none"}}muted{{end}}">{{upper .Attributed}}</td><td>{{if .ReadDelta}}+{{.ReadDelta}}{{else}}0{{end}}</td><td>{{if .RepeatedDelta}}+{{.RepeatedDelta}}{{else}}0{{end}}</td><td>{{if .DeviatedDelta}}+{{.DeviatedDelta}}{{else}}0{{end}}</td></tr>{{end}}
  </tbody></table></div></section>{{else}}<section class="panel"><h2>Redirect instruction probes</h2><p class="muted">Not collected in this v1 evidence.</p></section>{{end}}
  {{if .Sections.ToolCallLedger}}<section class="panel"><h2>OpenClaw tool-call ledger</h2>
    <p class="muted">Paired baseline and exercise tool calls projected from OpenClaw's metadata-only audit ledger: tool name, ordering, terminal state, error code, and duration. Raw tool call ids, arguments, and results are never published. The lane owns this unsigned database, so the ledger is supplemental metadata, not tamper-evident grading proof.</p>
    <p class="muted">Argument and result summaries: {{if .Evidence.ToolCallLedger.ArgumentSummaries.Available}}available{{else}}<strong>unavailable</strong>{{end}} — {{.Evidence.ToolCallLedger.ArgumentSummaries.Reason}}</p>
    <h3>Baseline lane · {{.Evidence.ToolCallLedger.Baseline.Coverage}} · {{.Evidence.ToolCallLedger.Baseline.CallCount}} call(s){{if .Evidence.ToolCallLedger.Baseline.Truncated}} · {{.Evidence.ToolCallLedger.Baseline.TotalCalls}} before per-lane cap{{end}}{{if .Evidence.ToolCallLedger.Baseline.Reason}} · {{.Evidence.ToolCallLedger.Baseline.Reason}}{{end}}</h3>
    {{template "toolCallLane" .Evidence.ToolCallLedger.Baseline}}
    <h3>Exercise lane · {{.Evidence.ToolCallLedger.Exercise.Coverage}} · {{.Evidence.ToolCallLedger.Exercise.CallCount}} call(s){{if .Evidence.ToolCallLedger.Exercise.Truncated}} · {{.Evidence.ToolCallLedger.Exercise.TotalCalls}} before per-lane cap{{end}}{{if .Evidence.ToolCallLedger.Exercise.Reason}} · {{.Evidence.ToolCallLedger.Exercise.Reason}}{{end}}</h3>
    {{template "toolCallLane" .Evidence.ToolCallLedger.Exercise}}
  </section>{{else}}<section class="panel"><h2>OpenClaw tool-call ledger</h2><p class="muted">Not collected in this v1 evidence.</p></section>{{end}}
  {{if .Sections.RuntimeTimeline}}<section class="panel"><h2>Runtime syscall timeline</h2>
    <p class="muted">Ordered, normalized file/process/network syscalls for each lane — the runtime substrate beneath the tool calls above, not the tool calls themselves. Subjects are redacted and raw arguments are never shown; the complete ordered sequence ships in the JSON projection while this page previews up to 250 events per lane.</p>
    <h3>Baseline lane · {{.Evidence.RuntimeTimeline.Baseline.EventCount}} event(s){{if .Evidence.RuntimeTimeline.Baseline.Truncated}} · {{.Evidence.RuntimeTimeline.Baseline.TotalEvents}} captured before per-lane cap{{end}}{{if .Evidence.RuntimeTimeline.Baseline.Timed}} · {{.Evidence.RuntimeTimeline.Baseline.DurationMs}} ms span{{end}}</h3>
    {{template "runtimeTimelineLane" .Evidence.RuntimeTimeline.Baseline}}
    <h3>Exercise lane · {{.Evidence.RuntimeTimeline.Exercise.EventCount}} event(s){{if .Evidence.RuntimeTimeline.Exercise.Truncated}} · {{.Evidence.RuntimeTimeline.Exercise.TotalEvents}} captured before per-lane cap{{end}}{{if .Evidence.RuntimeTimeline.Exercise.Timed}} · {{.Evidence.RuntimeTimeline.Exercise.DurationMs}} ms span{{end}}</h3>
    {{template "runtimeTimelineLane" .Evidence.RuntimeTimeline.Exercise}}
  </section>{{else}}<section class="panel"><h2>Runtime syscall timeline</h2><p class="muted">Not collected in this v1 evidence.</p></section>{{end}}
  <section class="panel"><h2>Coverage and limits</h2><ul>{{range .Evidence.Coverage.Limitations}}<li>{{.}}</li>{{end}}</ul></section>
  <footer>Schema {{.Evidence.SchemaVersion}} · Prompt {{shortHash .Evidence.Exercise.PromptSHA256}} · Raw traces and transcripts are intentionally not published.</footer>
</main></body></html>
{{define "runtimeTimelineLane"}}{{if .Events}}<div class="table-wrap"><table><thead><tr><th>#</th><th>Kind</th><th>Operation</th><th>Subject</th><th>Outcome</th><th>Offset</th></tr></thead><tbody>
    {{range runtimeTimelinePreview .Events}}<tr><td>{{.Sequence}}</td><td><span class="kind">{{.Kind}}</span></td><td>{{.Operation}}</td><td><code>{{.Subject}}</code>{{if .Canary}}<div class="muted">canary · {{.Canary}}</div>{{else if .Role}}<div class="muted">{{.Role}}</div>{{end}}</td><td>{{.Outcome}}</td><td>{{if .OffsetMs}}{{.OffsetMs}} ms{{else}}—{{end}}</td></tr>{{end}}
  </tbody></table></div>{{else}}<p class="muted">No syscall events captured in this lane.</p>{{end}}{{end}}
{{define "toolCallLane"}}{{if .Calls}}<div class="table-wrap"><table><thead><tr><th>#</th><th>Tool</th><th>State</th><th>Error</th><th>Duration</th><th>Offset</th></tr></thead><tbody>
    {{range toolCallPreview .Calls}}<tr><td>{{.Sequence}}</td><td><code>{{.Tool}}</code></td><td>{{.State}}</td><td>{{if .ErrorCode}}{{.ErrorCode}}{{else}}—{{end}}</td><td>{{if .DurationMs}}{{.DurationMs}} ms{{else}}—{{end}}</td><td>{{if .OffsetMs}}{{.OffsetMs}} ms{{else}}—{{end}}</td></tr>{{end}}
  </tbody></table></div>{{else}}<p class="muted">No tool calls recorded in this lane.</p>{{end}}{{end}}`))
