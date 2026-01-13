package proto

import (
	"time"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	remediationv1 "github.com/picatz/deputy/gen/deputy/remediation/v1"
	"github.com/picatz/deputy/internal/ai"
	"github.com/picatz/deputy/internal/remediation"
)

// RemediationCommandToStep converts internal remediation.Command to proto Step.
func RemediationCommandToStep(c remediation.Command, id string) *remediationv1.Step {
	step := &remediationv1.Step{
		Id:           id,
		Kind:         detectStepKind(c),
		Title:        buildStepTitle(c),
		Description:  buildStepDescription(c),
		PackageName:  extractPackageName(c),
		Manager:      c.Manager,
		ManifestPath: c.Path,
		Command:      c.Command,
		Hint:         c.Hint,
		Executable:   c.Executable,
		RiskLevel:    detectRiskLevel(c),
	}
	return step
}

// RemediationStepFromProto converts proto Step to internal remediation.Command.
// Note: Some proto fields don't map back to Command (they're for execution tracking).
func RemediationStepFromProto(s *remediationv1.Step) remediation.Command {
	if s == nil {
		return remediation.Command{}
	}
	return remediation.Command{
		Manager:    s.Manager,
		Command:    s.Command,
		Path:       s.ManifestPath,
		Hint:       s.Hint,
		Executable: s.Executable,
	}
}

// RemediationCommandsToSteps converts a slice of internal Commands to proto Steps.
func RemediationCommandsToSteps(commands []remediation.Command) []*remediationv1.Step {
	if len(commands) == 0 {
		return nil
	}
	steps := make([]*remediationv1.Step, len(commands))
	for i, c := range commands {
		steps[i] = RemediationCommandToStep(c, stepID(i))
	}
	return steps
}

// RemediationStepsFromProto converts a slice of proto Steps to internal Commands.
func RemediationStepsFromProto(steps []*remediationv1.Step) []remediation.Command {
	if len(steps) == 0 {
		return nil
	}
	commands := make([]remediation.Command, len(steps))
	for i, s := range steps {
		commands[i] = RemediationStepFromProto(s)
	}
	return commands
}

// detectStepKind determines the StepKind based on command content.
func detectStepKind(c remediation.Command) remediationv1.StepKind {
	cmd := c.Command
	if len(cmd) > 0 {
		// Deputy internal commands
		if len(cmd) > 7 && cmd[:7] == "deputy:" {
			if len(cmd) > 21 && cmd[:21] == "deputy:action:update " {
				return remediationv1.StepKind_STEP_KIND_ACTION_UPDATE
			}
			if len(cmd) > 25 && cmd[:25] == "deputy:dockerfile:update " {
				return remediationv1.StepKind_STEP_KIND_DOCKERFILE_UPDATE
			}
		}
	}

	// Default to shell command for executable commands
	if c.Executable {
		return remediationv1.StepKind_STEP_KIND_SHELL_COMMAND
	}

	// File edits for non-executable commands
	return remediationv1.StepKind_STEP_KIND_FILE_EDIT
}

// buildStepTitle creates a human-readable title for the step.
func buildStepTitle(c remediation.Command) string {
	if c.Manager != "" {
		return "Update " + c.Manager + " dependency"
	}
	return "Apply remediation"
}

// buildStepDescription creates a description for the step.
func buildStepDescription(c remediation.Command) string {
	if c.Hint != "" {
		return c.Hint
	}
	return c.Command
}

// extractPackageName attempts to extract the package name from the command.
func extractPackageName(c remediation.Command) string {
	// This is a simplified extraction; real implementation would parse the command
	return ""
}

// detectRiskLevel determines the risk level based on command characteristics.
func detectRiskLevel(c remediation.Command) remediationv1.RiskLevel {
	// Non-executable commands are lower risk (manual review required)
	if !c.Executable {
		return remediationv1.RiskLevel_RISK_LEVEL_LOW
	}

	// Most package manager commands are medium risk
	return remediationv1.RiskLevel_RISK_LEVEL_MEDIUM
}

// stepID generates a step ID from an index.
func stepID(i int) string {
	return "step-" + itoa(i+1)
}

// itoa converts an integer to a string without importing strconv.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	neg := i < 0
	if neg {
		i = -i
	}
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		b[pos] = '-'
	}
	return string(b[pos:])
}

// AgentInfoToProto converts internal ai.Provider to proto AgentInfo.
func AgentInfoToProto(p ai.Provider) *remediationv1.AgentInfo {
	caps := p.Capabilities()
	return &remediationv1.AgentInfo{
		Name:        p.Name(),
		DisplayName: p.Name(), // Could be enhanced with a DisplayName() method
		Description: "",       // Could be enhanced with a Description() method
		Capabilities: &remediationv1.AgentCapabilities{
			Streaming:         caps.Streaming,
			ToolUse:           caps.ToolUse,
			Agentic:           caps.Agentic,
			SessionResumption: caps.SessionResumption,
		},
		IsAvailable: true,
	}
}

// AgentInfosToProto converts a slice of providers to proto AgentInfo slice.
func AgentInfosToProto(providers []ai.Provider) []*remediationv1.AgentInfo {
	if len(providers) == 0 {
		return nil
	}
	infos := make([]*remediationv1.AgentInfo, len(providers))
	for i, p := range providers {
		infos[i] = AgentInfoToProto(p)
	}
	return infos
}

// SandboxFromProto converts proto sandbox string to internal ai.Sandbox.
func SandboxFromProto(s string) ai.Sandbox {
	switch s {
	case "read-only":
		return ai.SandboxReadOnly
	case "workspace-write":
		return ai.SandboxWorkspaceWrite
	case "full-access":
		return ai.SandboxFullAccess
	default:
		return ai.SandboxReadOnly // Safe default
	}
}

// SandboxToProto converts internal ai.Sandbox to proto sandbox string.
func SandboxToProto(s ai.Sandbox) string {
	return string(s)
}

// StreamEventToAgentEvent converts internal ai.StreamEvent to proto AgentEvent.
func StreamEventToAgentEvent(e ai.StreamEvent, sessionID string, phase remediationv1.AgentPhase) *remediationv1.AgentEvent {
	event := &remediationv1.AgentEvent{
		Phase:     phase,
		SessionId: sessionID,
		Timestamp: timestamppb.Now(),
	}

	switch ev := e.(type) {
	case ai.TextEvent:
		event.Details = &remediationv1.AgentEvent_Text{
			Text: &remediationv1.AgentTextEvent{
				Text:      ev.Text,
				IsPartial: true,
			},
		}
	case ai.CommandEvent:
		var exitCode *int32
		if ev.ExitCode != nil {
			ec := int32(*ev.ExitCode)
			exitCode = &ec
		}
		event.Details = &remediationv1.AgentEvent_Command{
			Command: &remediationv1.AgentCommandEvent{
				Command:  ev.Command,
				Status:   ev.Status,
				ExitCode: exitCode,
				Output:   ev.Output,
			},
		}
	case ai.FileEvent:
		event.Details = &remediationv1.AgentEvent_File{
			File: &remediationv1.AgentFileEvent{
				Path:   ev.Path,
				Action: ev.Action,
				Status: ev.Status,
			},
		}
	case ai.ErrorEvent:
		event.Details = &remediationv1.AgentEvent_Error{
			Error: &remediationv1.AgentErrorEvent{
				Message: ev.Message,
				IsFatal: true,
			},
		}
	case ai.DoneEvent:
		event.Details = &remediationv1.AgentEvent_Summary{
			Summary: &remediationv1.AgentSummaryEvent{
				SessionId: ev.SessionID,
				Success:   ev.FinishReason == ai.FinishReasonStop,
				ModelUsed: ev.Model,
			},
		}
	case ai.StatusEvent:
		event.Details = &remediationv1.AgentEvent_Status{
			Status: &remediationv1.AgentStatusEvent{
				Status: ev.Status,
			},
		}
	case ai.UsageEvent:
		event.Details = &remediationv1.AgentEvent_Tokens{
			Tokens: &remediationv1.AgentTokensEvent{
				PromptTokens:     int32(ev.Usage.PromptTokens),
				CompletionTokens: int32(ev.Usage.CompletionTokens),
				TotalTokens:      int32(ev.Usage.TotalTokens),
			},
		}
	}

	return event
}

// UsageToTokensEvent converts internal ai.Usage to proto AgentTokensEvent.
func UsageToTokensEvent(u ai.Usage, runningTotal int) *remediationv1.AgentTokensEvent {
	return &remediationv1.AgentTokensEvent{
		PromptTokens:     int32(u.PromptTokens),
		CompletionTokens: int32(u.CompletionTokens),
		TotalTokens:      int32(u.TotalTokens),
		RunningTotal:     int32(runningTotal),
	}
}

// ApprovalModeFromProto converts proto ApprovalMode to a descriptive setting.
func ApprovalModeFromProto(m remediationv1.ApprovalMode) string {
	switch m {
	case remediationv1.ApprovalMode_APPROVAL_MODE_AUTO_APPROVE:
		return "auto"
	case remediationv1.ApprovalMode_APPROVAL_MODE_INTERACTIVE:
		return "interactive"
	case remediationv1.ApprovalMode_APPROVAL_MODE_ALL_STEPS:
		return "all"
	case remediationv1.ApprovalMode_APPROVAL_MODE_SKIP_HIGH_RISK:
		return "skip-high-risk"
	default:
		return "interactive"
	}
}

// RiskLevelToProto converts an internal risk string to proto RiskLevel.
func RiskLevelToProto(risk string) remediationv1.RiskLevel {
	switch risk {
	case "low":
		return remediationv1.RiskLevel_RISK_LEVEL_LOW
	case "medium":
		return remediationv1.RiskLevel_RISK_LEVEL_MEDIUM
	case "high":
		return remediationv1.RiskLevel_RISK_LEVEL_HIGH
	case "critical":
		return remediationv1.RiskLevel_RISK_LEVEL_CRITICAL
	default:
		return remediationv1.RiskLevel_RISK_LEVEL_UNSPECIFIED
	}
}

// RiskLevelFromProto converts proto RiskLevel to an internal risk string.
func RiskLevelFromProto(r remediationv1.RiskLevel) string {
	switch r {
	case remediationv1.RiskLevel_RISK_LEVEL_LOW:
		return "low"
	case remediationv1.RiskLevel_RISK_LEVEL_MEDIUM:
		return "medium"
	case remediationv1.RiskLevel_RISK_LEVEL_HIGH:
		return "high"
	case remediationv1.RiskLevel_RISK_LEVEL_CRITICAL:
		return "critical"
	default:
		return ""
	}
}

// DurationToProto converts a time.Duration to proto Duration.
func DurationToProto(d time.Duration) *durationpb.Duration {
	return durationpb.New(d)
}

// DurationFromProto converts proto Duration to time.Duration.
func DurationFromProto(d *durationpb.Duration) time.Duration {
	if d == nil {
		return 0
	}
	return d.AsDuration()
}
