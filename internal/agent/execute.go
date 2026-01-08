package agent

import (
	"context"
	"iter"

	agentv1 "github.com/picatz/deputy/gen/deputy/agent/v1"
	"github.com/picatz/deputy/gen/deputy/agent/v1/agentv1connect"
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
