package agent

import (
	"context"
	"iter"

	agentv1 "github.com/temporalio/deputy/gen/deputy/agent/v1"
	"github.com/temporalio/deputy/gen/deputy/agent/v1/agentv1connect"
)

// Executor is an optional interface that agent handlers can implement
// to support in-process execution without requiring a connect.ServerStream.
type Executor interface {
	// ExecuteIter executes the agent and returns an iterator over events.
	ExecuteIter(ctx context.Context, req *agentv1.ExecuteRequest) iter.Seq2[*agentv1.ExecuteEvent, error]

	// ResumeIter resumes a session and returns an iterator over events.
	ResumeIter(ctx context.Context, req *agentv1.ResumeRequest) iter.Seq2[*agentv1.ExecuteEvent, error]
}

// AsExecutor attempts to cast an AgentPluginHandler to an Executor.
// Returns nil if the handler doesn't implement Executor.
func AsExecutor(handler agentv1connect.AgentPluginHandler) Executor {
	if exec, ok := handler.(Executor); ok {
		return exec
	}
	return nil
}

// ApprovalSupporter is an optional interface handlers implement to declare
// that their Approve RPC delivers real approval decisions to a running
// session. Every handler structurally has an Approve method: it is part of
// the plugin service contract, and embedding UnimplementedAgentPluginHandler
// stubs it with CodeUnimplemented, so method presence cannot distinguish real
// support; only an explicit declaration can. No builtin agent currently
// declares support: claude and codex acknowledge Approve calls but manage
// approvals inside their own CLIs and never emit approval-required events.
type ApprovalSupporter interface {
	// SupportsApprovals reports whether Approve delivers real decisions.
	SupportsApprovals() bool
}

// SupportsApprovals reports whether the handler explicitly declares working
// approval delivery via the ApprovalSupporter interface. Absent an explicit
// declaration it reports false: advertising an approval workflow a handler
// silently drops would be worse than not advertising one.
func SupportsApprovals(handler agentv1connect.AgentPluginHandler) bool {
	s, ok := handler.(ApprovalSupporter)
	return ok && s.SupportsApprovals()
}
