package observatory

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
)

// auditLedgerDocument is the strict receipt emitted by the contained, read-only
// exporter for OpenClaw's canonical audit_events table. Raw tool call ids, run
// ids, actor provenance, and event ids are parsed only for validation and
// correlation, then discarded before public evidence is built.
type auditLedgerDocument struct {
	Source     string       `json:"source"`
	MaxCalls   *int         `json:"maxCalls"`
	Events     []auditEvent `json:"events"`
	TotalCalls *int         `json:"totalCalls"`
	Truncated  *bool        `json:"truncated"`
}

const (
	toolAuditCaptureSource = "openclaw-state-sqlite"
	toolAuditAgentID       = "observatory"
)

type toolAuditCapture struct {
	Events     []auditEvent
	TotalCalls int
	Truncated  bool
}

type auditActor struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type auditEvent struct {
	EventID        string     `json:"eventId"`
	Sequence       int64      `json:"sequence"`
	SourceSequence int64      `json:"sourceSequence"`
	OccurredAt     int64      `json:"occurredAt"`
	Kind           string     `json:"kind"`
	Action         string     `json:"action"`
	Status         string     `json:"status"`
	ErrorCode      string     `json:"errorCode"`
	Actor          auditActor `json:"actor"`
	AgentID        string     `json:"agentId"`
	RunID          string     `json:"runId"`
	ToolCallID     string     `json:"toolCallId"`
	ToolName       string     `json:"toolName"`
	Redaction      string     `json:"redaction"`
}

// argumentSummariesUnavailableReason is the explicit coverage the MVP publishes
// instead of pretending syscall subjects or best-effort trajectory fields are
// tool arguments. See ToolArgumentCoverage.
const argumentSummariesUnavailableReason = "OpenClaw's metadata-only audit ledger records tool identity, ordering, terminal state, error code, and timing but never tool arguments or results; the redacted trajectory's best-effort redaction cannot guarantee synthetic-canary safety, so bounded argument/result summaries are not published."

var toolAuditWhitespace = regexp.MustCompile(`\s+`)

// parseToolAuditLedger fails closed on a claimed-complete but malformed ledger.
// It requires the direct export source, exact bound and coverage counts, plus
// records satisfying the metadata contract (redaction marker, closed enums,
// unique provenance, and positive sequences).
func parseToolAuditLedger(data []byte) (toolAuditCapture, error) {
	var document auditLedgerDocument
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return toolAuditCapture{}, fmt.Errorf("not valid direct audit-export JSON: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("multiple JSON values")
		}
		return toolAuditCapture{}, fmt.Errorf("not valid direct audit-export JSON: %w", err)
	}
	if document.Source != toolAuditCaptureSource {
		return toolAuditCapture{}, errors.New("missing or unsupported audit export source")
	}
	if document.MaxCalls == nil || *document.MaxCalls != MaxToolCallsPerLane {
		return toolAuditCapture{}, errors.New("missing or unsupported audit export call bound")
	}
	if document.Events == nil {
		return toolAuditCapture{}, errors.New("missing events array")
	}
	if document.TotalCalls == nil || document.Truncated == nil {
		return toolAuditCapture{}, errors.New("missing audit export coverage counts")
	}
	if *document.TotalCalls < 0 {
		return toolAuditCapture{}, errors.New("invalid total tool-call count")
	}
	if len(document.Events) > MaxToolCallsPerLane*2 {
		return toolAuditCapture{}, errors.New("audit export exceeds the event bound")
	}
	eventIDs := make(map[string]bool, len(document.Events))
	sequences := make(map[int64]bool, len(document.Events))
	lifecycle := make(map[string]map[string]auditEvent)
	for _, event := range document.Events {
		if err := validateAuditEvent(event); err != nil {
			return toolAuditCapture{}, err
		}
		if eventIDs[event.EventID] || sequences[event.Sequence] {
			return toolAuditCapture{}, errors.New("audit export contains duplicate event provenance")
		}
		eventIDs[event.EventID] = true
		sequences[event.Sequence] = true
		key := event.RunID + "\x00" + event.ToolCallID
		if event.ToolCallID == "" {
			key = fmt.Sprintf("%s\x00sequence:%d", event.RunID, event.Sequence)
		}
		if lifecycle[key] == nil {
			lifecycle[key] = map[string]auditEvent{}
		}
		if _, exists := lifecycle[key][event.Action]; exists {
			return toolAuditCapture{}, errors.New("audit export contains duplicate tool lifecycle records")
		}
		lifecycle[key][event.Action] = event
	}
	for _, records := range lifecycle {
		started, hasStarted := records["tool.action.started"]
		finished, hasFinished := records["tool.action.finished"]
		if hasStarted && hasFinished {
			if started.Sequence >= finished.Sequence || started.OccurredAt > finished.OccurredAt {
				return toolAuditCapture{}, errors.New("audit export contains an inverted tool lifecycle")
			}
			if started.ToolName != "" && finished.ToolName != "" && started.ToolName != finished.ToolName {
				return toolAuditCapture{}, errors.New("audit export contains inconsistent tool identity")
			}
		}
	}
	observed := len(lifecycle)
	expected := *document.TotalCalls
	if expected > MaxToolCallsPerLane {
		expected = MaxToolCallsPerLane
	}
	if observed != expected || *document.Truncated != (*document.TotalCalls > MaxToolCallsPerLane) {
		return toolAuditCapture{}, errors.New("audit export coverage counts are inconsistent")
	}
	return toolAuditCapture{Events: document.Events, TotalCalls: *document.TotalCalls, Truncated: *document.Truncated}, nil
}

func validateAuditEvent(event auditEvent) error {
	if event.Redaction != "metadata_only" {
		return errors.New("record is not marked metadata_only")
	}
	if event.Kind != "tool_action" {
		return errors.New("record has an unsupported kind")
	}
	if event.Action != "tool.action.started" && event.Action != "tool.action.finished" {
		return errors.New("record has an unsupported action")
	}
	if !toolCallStates[event.Status] {
		return errors.New("record has an unsupported status")
	}
	if event.ErrorCode != "" && !toolCallErrorCodes[event.ErrorCode] {
		return errors.New("record has an unsupported error code")
	}
	if event.Sequence < 1 || event.SourceSequence < 1 || event.OccurredAt < 0 {
		return errors.New("record has an invalid sequence or timestamp")
	}
	if event.EventID == "" || event.AgentID != toolAuditAgentID || event.RunID == "" {
		return errors.New("record is missing required provenance")
	}
	if (event.Actor.Type != "agent" && event.Actor.Type != "system") || event.Actor.ID == "" {
		return errors.New("record has invalid actor provenance")
	}
	if event.Action == "tool.action.started" && (event.Status != "started" || event.ErrorCode != "") {
		return errors.New("tool start record has an invalid outcome")
	}
	if event.Action == "tool.action.finished" && event.Status == "started" {
		return errors.New("tool finish record has no terminal outcome")
	}
	if event.Action == "tool.action.finished" {
		expectedError := map[string]string{
			"succeeded": "", "failed": "tool_failed", "cancelled": "tool_cancelled",
			"timed_out": "tool_timed_out", "blocked": "tool_blocked", "unknown": "tool_outcome_unknown",
		}[event.Status]
		if event.ErrorCode != expectedError {
			return errors.New("tool finish record has an inconsistent error code")
		}
	}
	return nil
}

// BuildToolCallLedger projects the paired per-lane tool audits into the published
// ledger. It publishes only safe ordinals, compact tool names, terminal states,
// error codes, and relative timing; the raw tool call id and its fingerprint are
// used for internal correlation only and never leave this function.
func BuildToolCallLedger(bundle CaptureBundle) ToolCallLedger {
	return ToolCallLedger{
		Source:          ToolCallLedgerSource,
		MaxCallsPerLane: MaxToolCallsPerLane,
		ArgumentSummaries: ToolArgumentCoverage{
			Available: false,
			Reason:    argumentSummariesUnavailableReason,
		},
		Baseline: buildToolCallLane(bundle.Metadata.BaselineAuditStatus, bundle.BaselineToolAudit),
		Exercise: buildToolCallLane(bundle.Metadata.ExerciseAuditStatus, bundle.ExerciseToolAudit),
	}
}

type toolCallGroup struct {
	started  *auditEvent
	finished *auditEvent
	order    int64
}

func (group *toolCallGroup) repTime() (int64, bool) {
	if group.started != nil {
		return group.started.OccurredAt, true
	}
	if group.finished != nil {
		return group.finished.OccurredAt, true
	}
	return 0, false
}

func buildToolCallLane(status string, capture toolAuditCapture) ToolCallLane {
	lane := ToolCallLane{Coverage: "unavailable", Calls: []ToolCall{}}
	if status != "captured" {
		lane.Reason = "OpenClaw did not record a metadata-only audit ledger for this lane."
		return lane
	}
	ordered := correlateToolCalls(capture.Events)
	total := capture.TotalCalls
	published := ordered
	lane.Truncated = capture.Truncated

	timed := len(published) > 0
	reps := make([]int64, len(published))
	for index, group := range published {
		rep, ok := group.repTime()
		reps[index] = rep
		if !ok {
			timed = false
		}
	}
	if timed {
		for index := 1; index < len(reps); index++ {
			if reps[index] < reps[index-1] {
				timed = false
				break
			}
		}
	}
	base := int64(0)
	if timed && len(reps) > 0 {
		base = reps[0]
	}

	missing := 0
	var duration int64
	calls := make([]ToolCall, 0, len(published))
	for index, group := range published {
		if group.started == nil || group.finished == nil {
			missing++
		}
		call := ToolCall{Tool: toolCallName(group), State: "started"}
		if group.finished != nil {
			call.State = group.finished.Status
			call.ErrorCode = group.finished.ErrorCode
		}
		if group.started != nil && group.finished != nil {
			if elapsed := group.finished.OccurredAt - group.started.OccurredAt; elapsed >= 0 {
				value := elapsed
				call.DurationMs = &value
			}
		}
		if timed {
			offset := reps[index] - base
			if offset < 0 {
				offset = 0
			}
			if offset > duration {
				duration = offset
			}
			value := offset
			call.OffsetMs = &value
		}
		calls = append(calls, call)
	}
	for index := range calls {
		calls[index].Sequence = index + 1
	}
	lane.Calls = calls
	lane.CallCount = len(calls)
	lane.TotalCalls = total
	if timed {
		lane.Timed = true
		value := duration
		lane.DurationMs = &value
	}
	lane.Coverage, lane.Reason = toolCallCoverage(total, len(published), missing, lane.Truncated)
	return lane
}

// correlateToolCalls pairs tool.action.started and finished records by their raw
// tool call id and returns groups ordered by the authoritative ledger sequence.
// Records without a call id, or that cannot be paired, still surface as their own
// group so the lane coverage can report the gap.
func correlateToolCalls(events []auditEvent) []*toolCallGroup {
	groups := map[string]*toolCallGroup{}
	uncorrelated := 0
	for index := range events {
		event := events[index]
		if event.Kind != "tool_action" {
			continue
		}
		key := event.RunID + "\x00id:" + event.ToolCallID
		if event.ToolCallID == "" {
			uncorrelated++
			key = fmt.Sprintf("%s\x00nocall:%d", event.RunID, uncorrelated)
		}
		group := groups[key]
		if group == nil {
			group = &toolCallGroup{order: event.Sequence}
			groups[key] = group
		}
		if event.Sequence < group.order {
			group.order = event.Sequence
		}
		switch event.Action {
		case "tool.action.started":
			if group.started == nil || event.Sequence < group.started.Sequence {
				stored := event
				group.started = &stored
			}
		case "tool.action.finished":
			if group.finished == nil || event.Sequence < group.finished.Sequence {
				stored := event
				group.finished = &stored
			}
		}
	}
	ordered := make([]*toolCallGroup, 0, len(groups))
	for _, group := range groups {
		ordered = append(ordered, group)
	}
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].order < ordered[j].order })
	return ordered
}

func toolCallName(group *toolCallGroup) string {
	name := ""
	if group.started != nil {
		name = group.started.ToolName
	}
	if name == "" && group.finished != nil {
		name = group.finished.ToolName
	}
	name = strings.TrimSpace(toolAuditWhitespace.ReplaceAllString(name, " "))
	if !toolNamePattern.MatchString(name) {
		return "unknown"
	}
	return name
}

func toolCallCoverage(total int, published int, missing int, truncated bool) (string, string) {
	if total == 0 {
		return "complete", "No tool calls were recorded in this lane."
	}
	reasons := []string{}
	if missing > 0 {
		reasons = append(reasons, fmt.Sprintf("%d tool call(s) had no paired started and finished audit record.", missing))
	}
	if truncated {
		reasons = append(reasons, fmt.Sprintf("Recorded %d tool calls; retained the earliest %d.", total, published))
	}
	if len(reasons) == 0 {
		return "complete", ""
	}
	return "incomplete", strings.Join(reasons, " ")
}
