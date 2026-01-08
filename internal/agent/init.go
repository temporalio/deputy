package agent

func init() {
	// Register builtin agent plugins
	// These directly implement agentv1connect.AgentPluginHandler
	_ = DefaultRegistry.RegisterBuiltin("claude", NewClaudeHandler())
	_ = DefaultRegistry.RegisterBuiltin("codex", NewCodexHandler())
}
