package observatory

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// auditLedgerDocument mirrors OpenClaw's AuditListResult: a bounded newest-first
// page of metadata-only audit records. Only the fields the observatory needs for
// correlation and validation are modeled; the raw tool call id, run/session ids,
// actor, and event id are parsed for internal use and never republished.
type auditLedgerDocument struct {
	Events []auditEvent `json:"events"`
}

type auditEvent struct {
	EventID        string `json:"eventId"`
	Sequence       int64  `json:"sequence"`
	SourceSequence int64  `json:"sourceSequence"`
	OccurredAt     int64  `json:"occurredAt"`
	Kind           string `json:"kind"`
	Action         string `json:"action"`
	Status         string `json:"status"`
	ErrorCode      string `json:"errorCode"`
	AgentID        string `json:"agentId"`
	RunID          string `json:"runId"`
	ToolCallID     string `json:"toolCallId"`
	ToolName       string `json:"toolName"`
	Redaction      string `json:"redaction"`
}

var auditActions = map[string]bool{
	"agent.run.started": true, "agent.run.finished": true,
	"tool.action.started": true, "tool.action.finished": true,
}

// argumentSummariesUnavailableReason is the explicit coverage the MVP publishes
// instead of pretending syscall subjects or best-effort trajectory fields are
// tool arguments. See ToolArgumentCoverage.
const argumentSummariesUnavailableReason = "OpenClaw's metadata-only audit ledger records tool identity, ordering, terminal state, error code, and timing but never tool arguments or results; the redacted trajectory's best-effort redaction cannot guarantee synthetic-canary safety, so bounded argument/result summaries are not published."

var toolAuditWhitespace = regexp.MustCompile(`\s+`)

// parseToolAuditLedger fails closed on a claimed-complete but malformed ledger.
// It requires a JSON AuditListResult whose every record satisfies the metadata
// contract (redaction marker, closed enums, positive sequences).
func parseToolAuditLedger(data []byte) ([]auditEvent, error) {
	var document auditLedgerDocument
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf("not valid AuditListResult JSON: %w", err)
	}
	if document.Events == nil {
		return nil, errors.New("missing events array")
	}
	for _, event := range document.Events {
		if err := validateAuditEvent(event); err != nil {
			return nil, err
		}
	}
	return document.Events, nil
}

func validateAuditEvent(event auditEvent) error {
	if event.Redaction != "metadata_only" {
		return errors.New("record is not marked metadata_only")
	}
	if event.Kind != "agent_run" && event.Kind != "tool_action" {
		return errors.New("record has an unsupported kind")
	}
	if !auditActions[event.Action] {
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
	if event.EventID == "" || event.AgentID == "" || event.RunID == "" {
		return errors.New("record is missing required provenance")
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

func buildToolCallLane(status string, events []auditEvent) ToolCallLane {
	lane := ToolCallLane{Coverage: "unavailable", Calls: []ToolCall{}}
	if status != "captured" {
		lane.Reason = "OpenClaw did not record a metadata-only audit ledger for this lane."
		return lane
	}
	ordered := correlateToolCalls(events)
	total := len(ordered)
	published := ordered
	if len(published) > MaxToolCallsPerLane {
		published = published[:MaxToolCallsPerLane]
		lane.Truncated = true
	}

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
		key := "id:" + event.ToolCallID
		if event.ToolCallID == "" {
			uncorrelated++
			key = fmt.Sprintf("nocall:%d", uncorrelated)
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
