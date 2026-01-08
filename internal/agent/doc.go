// Package agent provides the agent plugin system for Deputy.
//
// The agent plugin architecture supports three types of plugins:
//
//   - Builtin: Compiled into the Deputy binary (Claude, Codex)
//   - External: Separate processes discovered via PATH (deputy-agent-<name>)
//   - Remote: gRPC/Connect servers at configured endpoints
//
// # Plugin Interface
//
// All agent plugins implement the AgentPlugin gRPC service defined in
// api/deputy/agent/v1/agent.proto. This includes:
//
//   - GetInfo: Returns plugin metadata and capabilities
//   - Execute: Runs the agent with streaming events
//   - Resume: Continues a previous session
//   - Approve: Handles approval requests
//   - Cancel: Gracefully terminates execution
//
// # Registry
//
// The Registry manages plugin discovery and lifecycle:
//
//	registry := agent.NewRegistry()
//	registry.RegisterBuiltin(claude.NewPlugin())
//	registry.DiscoverExternal() // finds deputy-agent-* in PATH
//
// # Builtin Plugins
//
// Builtin plugins wrap existing ai.Provider implementations:
//
//	plugin := agent.WrapProvider(aiProvider)
//
// # External Plugins
//
// External plugins are discovered by searching PATH for executables
// matching the pattern "deputy-agent-<name>". When executed, they
// must serve the AgentPlugin gRPC service on a Unix socket or TCP port.
//
// # Sandboxed Execution
//
// Plugins can be run in sandboxed environments:
//
//	plugin := agent.NewSandboxedPlugin(plugin, agent.SandboxOptions{
//	    Runtime: agent.RuntimeDocker,
//	    Image:   "deputy-agent:latest",
//	})
package agent
