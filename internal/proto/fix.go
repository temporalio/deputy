package proto

import (
	"google.golang.org/protobuf/types/known/timestamppb"

	fixv1 "github.com/temporalio/deputy/gen/deputy/fix/v1"
	targetv1 "github.com/temporalio/deputy/gen/deputy/target/v1"
	"github.com/temporalio/deputy/internal/remediation"
)

// BuildFixResponse creates a FixResponse from internal types.
func BuildFixResponse(
	displayPath, ref, commit string,
	stdlibUpgrade string,
	commands []remediation.Command,
) *fixv1.FixResponse {
	resp := &fixv1.FixResponse{
		Target: &targetv1.Target{
			DisplayPath: displayPath,
			CommitHash:  commit,
		},
		StdlibUpgrade: stdlibUpgrade,
		Commands:      RemediationCommandsToProto(commands),
		GeneratedAt:   timestamppb.Now(),
	}

	// Calculate stats
	resp.Stats = &fixv1.RemediationStats{
		TotalCommands:    int32(len(commands)),
		RunnableCommands: int32(countExecutable(commands)),
	}

	return resp
}

// RemediationCommandToProto converts an internal remediation.Command to proto.
func RemediationCommandToProto(c remediation.Command) *fixv1.RemediationCommand {
	return &fixv1.RemediationCommand{
		Manager:    c.Manager,
		Command:    c.Command,
		Path:       c.Path,
		Groups:     c.Groups,
		Hint:       c.Hint,
		FollowUp:   c.FollowUp,
		IsDirect:   c.IsDirect,
		Executable: c.Executable,
	}
}

// RemediationCommandsToProto converts a slice of internal commands to proto.
func RemediationCommandsToProto(commands []remediation.Command) []*fixv1.RemediationCommand {
	if len(commands) == 0 {
		return nil
	}
	out := make([]*fixv1.RemediationCommand, len(commands))
	for i, c := range commands {
		out[i] = RemediationCommandToProto(c)
	}
	return out
}

// RemediationCommandFromProto converts a proto RemediationCommand to internal type.
func RemediationCommandFromProto(pc *fixv1.RemediationCommand) remediation.Command {
	if pc == nil {
		return remediation.Command{}
	}
	return remediation.Command{
		Manager:    pc.Manager,
		Command:    pc.Command,
		Path:       pc.Path,
		Groups:     pc.Groups,
		Hint:       pc.Hint,
		FollowUp:   pc.FollowUp,
		IsDirect:   pc.IsDirect,
		Executable: pc.Executable,
	}
}

// RemediationCommandsFromProto converts proto commands to internal types.
func RemediationCommandsFromProto(commands []*fixv1.RemediationCommand) []remediation.Command {
	if len(commands) == 0 {
		return nil
	}
	out := make([]remediation.Command, len(commands))
	for i, c := range commands {
		out[i] = RemediationCommandFromProto(c)
	}
	return out
}

// countExecutable returns the number of executable commands.
func countExecutable(commands []remediation.Command) int {
	count := 0
	for _, cmd := range commands {
		if cmd.Executable {
			count++
		}
	}
	return count
}
