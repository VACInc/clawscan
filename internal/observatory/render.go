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
	Evidence Evidence
	Changes  []VersionChange
	Counts   map[string]int
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
	if err := json.Unmarshal(data, &evidence); err == nil && evidence.SchemaVersion == EvidenceSchemaVersion {
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
		return Evidence{}, errors.New("input is neither observatory.behavior.v1 nor a Clawscan artifact containing scanner behavior")
	}
	if err := json.Unmarshal(behavior.Raw, &evidence); err != nil {
		return Evidence{}, fmt.Errorf("parse Clawscan behavior evidence: %w", err)
	}
	if err := ValidateEvidence(evidence); err != nil {
		return Evidence{}, err
	}
	return evidence, nil
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
	changes := []VersionChange{}
	if previous != nil {
		if err := ValidateEvidence(*previous); err != nil {
			return fmt.Errorf("validate previous evidence: %w", err)
		}
		if err := validateEvidenceComparison(*previous, evidence); err != nil {
			return err
		}
		changes = DiffEvidence(*previous, evidence)
	}
	directory, err := openRenderOutputDirectory(outputDir, 0o755)
	if err != nil {
		return err
	}
	defer directory.Close()
	counts := map[string]int{"file": 0, "process": 0, "network": 0, "canary": 0}
	for _, observation := range evidence.Observations {
		counts[observation.Kind] += observation.DeltaCount
	}
	for _, canary := range evidence.Canaries {
		counts["canary"] += canary.DeltaInteractions
	}
	file, err := openRenderOutputFile(directory, "index.html", 0o644)
	if err != nil {
		return err
	}
	renderErr := evidencePageTemplate.Execute(file, pageData{Evidence: evidence, Changes: changes, Counts: counts})
	closeErr := file.Close()
	if renderErr != nil {
		return renderErr
	}
	if closeErr != nil {
		return closeErr
	}
	return writeRenderJSON(directory, "evidence.json", evidence, 0o644)
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
	return nil
}

func comparableIsolation(previous IsolationEvidence, current IsolationEvidence) bool {
	return previous.Substrate == current.Substrate && previous.NetworkMode == current.NetworkMode &&
		previous.ContainmentProfile == current.ContainmentProfile && previous.Verification == current.Verification &&
		previous.GuestFirewallPolicySHA256 == current.GuestFirewallPolicySHA256
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

func publicObservationKey(observation Observation) string {
	return strings.Join([]string{observation.Kind, observation.Operation, observation.Subject, observation.Outcome, observation.Role}, "\x00")
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
    .grid { display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin:24px 0; }
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
  <section class="grid" aria-label="Observation totals">
    <div class="metric"><strong>{{index .Counts "file"}}</strong><span>File events</span></div>
    <div class="metric"><strong>{{index .Counts "process"}}</strong><span>Process events</span></div>
    <div class="metric"><strong>{{index .Counts "network"}}</strong><span>Network events</span></div>
    <div class="metric"><strong>{{index .Counts "canary"}}</strong><span>Canary deltas</span></div>
  </section>
  <section class="panel"><h2>Run receipt</h2><dl class="meta">
    <div><dt>Target digest</dt><dd>{{shortHash .Evidence.Target.SHA256}}</dd></div>
    <div><dt>Run ID</dt><dd>{{.Evidence.Run.ID}}</dd></div>
    <div><dt>Completed</dt><dd>{{.Evidence.Run.CompletedAt}}</dd></div>
    <div><dt>Runtime</dt><dd>{{.Evidence.Run.Runtime.OpenClawVersion}}</dd></div>
    <div><dt>Model</dt><dd>{{.Evidence.Run.Runtime.ModelProvider}}/{{.Evidence.Run.Runtime.ModelID}} ({{.Evidence.Run.Runtime.ModelEndpoint}})</dd></div>
    <div><dt>Isolation</dt><dd>{{.Evidence.Run.Isolation.Substrate}} · {{.Evidence.Run.Isolation.NetworkMode}} · {{.Evidence.Run.Isolation.ContainmentProfile}}</dd></div>
  </dl></section>
  {{if .Changes}}<section class="panel"><h2>Version delta</h2><div class="table-wrap"><table><thead><tr><th>Change</th><th>Behavior</th><th>Outcome</th><th>Role</th><th>Counts</th></tr></thead><tbody>
    {{range .Changes}}<tr><td class="change-{{.Change}}">{{upper .Change}}</td><td><span class="kind">{{.Kind}}</span> {{.Operation}} <code>{{.Subject}}</code></td><td>{{.Outcome}}</td><td>{{.Role}}</td><td>{{.PreviousDelta}} → {{.CurrentDelta}}</td></tr>{{end}}
  </tbody></table></div></section>{{end}}
  <section class="panel"><h2>Observed exercise deltas</h2>{{if .Evidence.Observations}}<div class="table-wrap"><table><thead><tr><th>Kind</th><th>Operation</th><th>Subject</th><th>Outcome</th><th>Baseline</th><th>Exercise</th><th>Δ</th></tr></thead><tbody>
    {{range .Evidence.Observations}}<tr><td><span class="kind">{{.Kind}}</span></td><td>{{.Operation}}</td><td><code>{{.Subject}}</code>{{if .Role}}<div class="muted">{{.Role}}</div>{{end}}</td><td>{{.Outcome}}</td><td>{{.BaselineCount}}</td><td>{{.ExerciseCount}}</td><td>+{{.DeltaCount}}</td></tr>{{end}}
  </tbody></table></div>{{else}}<p class="muted">No trace event increased in the exercise lane.</p>{{end}}</section>
  <section class="panel"><h2>Synthetic canaries</h2><div class="table-wrap"><table><thead><tr><th>Canary</th><th>Surface</th><th>Baseline</th><th>Exercise</th><th>Δ</th></tr></thead><tbody>
    {{range .Evidence.Canaries}}<tr><td><code>{{.ID}}</code></td><td>{{.Surface}}</td><td>{{.BaselineInteractions}}</td><td>{{.ExerciseInteractions}}</td><td>{{if .DeltaInteractions}}+{{.DeltaInteractions}}{{else}}0{{end}}</td></tr>{{end}}
  </tbody></table></div></section>
  <section class="panel"><h2>OpenClaw tool-call ledger</h2>
    <p class="muted">Paired baseline and exercise tool calls projected from OpenClaw's metadata-only audit ledger: tool name, ordering, terminal state, error code, and duration. Raw tool call ids, arguments, and results are never published.</p>
    <p class="muted">Argument and result summaries: {{if .Evidence.ToolCallLedger.ArgumentSummaries.Available}}available{{else}}<strong>unavailable</strong>{{end}} — {{.Evidence.ToolCallLedger.ArgumentSummaries.Reason}}</p>
    <h3>Baseline lane · {{.Evidence.ToolCallLedger.Baseline.Coverage}} · {{.Evidence.ToolCallLedger.Baseline.CallCount}} call(s){{if .Evidence.ToolCallLedger.Baseline.Truncated}} · {{.Evidence.ToolCallLedger.Baseline.TotalCalls}} before per-lane cap{{end}}{{if .Evidence.ToolCallLedger.Baseline.Reason}} · {{.Evidence.ToolCallLedger.Baseline.Reason}}{{end}}</h3>
    {{template "toolCallLane" .Evidence.ToolCallLedger.Baseline}}
    <h3>Exercise lane · {{.Evidence.ToolCallLedger.Exercise.Coverage}} · {{.Evidence.ToolCallLedger.Exercise.CallCount}} call(s){{if .Evidence.ToolCallLedger.Exercise.Truncated}} · {{.Evidence.ToolCallLedger.Exercise.TotalCalls}} before per-lane cap{{end}}{{if .Evidence.ToolCallLedger.Exercise.Reason}} · {{.Evidence.ToolCallLedger.Exercise.Reason}}{{end}}</h3>
    {{template "toolCallLane" .Evidence.ToolCallLedger.Exercise}}
  </section>
  <section class="panel"><h2>Runtime syscall timeline</h2>
    <p class="muted">Ordered, normalized file/process/network syscalls for each lane — the runtime substrate beneath the tool calls above, not the tool calls themselves. Subjects are redacted and raw arguments are never shown; the complete ordered sequence ships in the JSON projection while this page previews up to 250 events per lane.</p>
    <h3>Baseline lane · {{.Evidence.RuntimeTimeline.Baseline.EventCount}} event(s){{if .Evidence.RuntimeTimeline.Baseline.Truncated}} · {{.Evidence.RuntimeTimeline.Baseline.TotalEvents}} captured before per-lane cap{{end}}{{if .Evidence.RuntimeTimeline.Baseline.Timed}} · {{.Evidence.RuntimeTimeline.Baseline.DurationMs}} ms span{{end}}</h3>
    {{template "runtimeTimelineLane" .Evidence.RuntimeTimeline.Baseline}}
    <h3>Exercise lane · {{.Evidence.RuntimeTimeline.Exercise.EventCount}} event(s){{if .Evidence.RuntimeTimeline.Exercise.Truncated}} · {{.Evidence.RuntimeTimeline.Exercise.TotalEvents}} captured before per-lane cap{{end}}{{if .Evidence.RuntimeTimeline.Exercise.Timed}} · {{.Evidence.RuntimeTimeline.Exercise.DurationMs}} ms span{{end}}</h3>
    {{template "runtimeTimelineLane" .Evidence.RuntimeTimeline.Exercise}}
  </section>
  <section class="panel"><h2>Coverage and limits</h2><ul>{{range .Evidence.Coverage.Limitations}}<li>{{.}}</li>{{end}}</ul></section>
  <footer>Schema {{.Evidence.SchemaVersion}} · Prompt {{shortHash .Evidence.Exercise.PromptSHA256}} · Raw traces and transcripts are intentionally not published.</footer>
</main></body></html>
{{define "runtimeTimelineLane"}}{{if .Events}}<div class="table-wrap"><table><thead><tr><th>#</th><th>Kind</th><th>Operation</th><th>Subject</th><th>Outcome</th><th>Offset</th></tr></thead><tbody>
    {{range runtimeTimelinePreview .Events}}<tr><td>{{.Sequence}}</td><td><span class="kind">{{.Kind}}</span></td><td>{{.Operation}}</td><td><code>{{.Subject}}</code>{{if .Canary}}<div class="muted">canary · {{.Canary}}</div>{{else if .Role}}<div class="muted">{{.Role}}</div>{{end}}</td><td>{{.Outcome}}</td><td>{{if .OffsetMs}}{{.OffsetMs}} ms{{else}}—{{end}}</td></tr>{{end}}
  </tbody></table></div>{{else}}<p class="muted">No syscall events captured in this lane.</p>{{end}}{{end}}
{{define "toolCallLane"}}{{if .Calls}}<div class="table-wrap"><table><thead><tr><th>#</th><th>Tool</th><th>State</th><th>Error</th><th>Duration</th><th>Offset</th></tr></thead><tbody>
    {{range toolCallPreview .Calls}}<tr><td>{{.Sequence}}</td><td><code>{{.Tool}}</code></td><td>{{.State}}</td><td>{{if .ErrorCode}}{{.ErrorCode}}{{else}}—{{end}}</td><td>{{if .DurationMs}}{{.DurationMs}} ms{{else}}—{{end}}</td><td>{{if .OffsetMs}}{{.OffsetMs}} ms{{else}}—{{end}}</td></tr>{{end}}
  </tbody></table></div>{{else}}<p class="muted">No tool calls recorded in this lane.</p>{{end}}{{end}}`))
