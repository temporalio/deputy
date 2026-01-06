// Package ai provides AI/LLM capabilities for Deputy.
//
// This package defines a provider-agnostic interface for integrating AI models
// into Deputy's workflows. It supports multiple use cases including remediation,
// triage, analysis, research, and conversational interactions.
//
// # Design Philosophy
//
// The AI subsystem is designed to be:
//
//   - Agnostic: Works with any LLM provider (OpenAI, Anthropic, local models, etc.)
//   - Configurable: Per-provider settings via .deputy.yaml and environment variables
//   - Composable: AI capabilities can be used throughout Deputy, not just in one command
//   - Deterministic by default: AI augments deterministic logic, doesn't replace it
//   - Safe: Sandboxing, approval workflows, and audit logging built-in
//
// # Architecture
//
// The package is organized around three core concepts:
//
// 1. [Provider] - An LLM backend that can complete prompts and stream responses.
//    Providers are stateless and handle the raw API communication.
//
// 2. [Session] - A stateful conversation with context, history, and tools.
//    Sessions enable multi-turn interactions and agentic workflows.
//
// 3. [Task] - A specific AI-powered operation like remediation or triage.
//    Tasks compose providers and sessions with domain-specific prompts.
//
// # Provider Interface
//
// Providers implement a minimal interface focused on text generation:
//
//	type Provider interface {
//	    Name() string
//	    Complete(ctx context.Context, req *CompletionRequest) (*CompletionResponse, error)
//	    Stream(ctx context.Context, req *CompletionRequest) iter.Seq2[StreamEvent, error]
//	}
//
// Built-in providers include:
//   - codex: OpenAI Codex CLI with full agentic capabilities
//   - claude: Anthropic Claude CLI for code analysis
//   - openai: Direct OpenAI API access
//   - anthropic: Direct Anthropic API access
//
// # Configuration
//
// AI capabilities are configured in .deputy.yaml:
//
//	ai:
//	  default_provider: codex
//	  providers:
//	    codex:
//	      model: o3
//	      sandbox: workspace-write
//	    claude:
//	      model: claude-sonnet-4-20250514
//	    openai:
//	      api_key: ${OPENAI_API_KEY}
//	      model: gpt-4o
//	  approval:
//	    required: false
//	    commands: true    # Require approval for shell commands
//	    file_writes: true # Require approval for file modifications
//
// # Usage
//
// Basic completion:
//
//	provider, _ := ai.GetProvider("openai")
//	resp, _ := provider.Complete(ctx, &ai.CompletionRequest{
//	    Prompt: "Explain this CVE in one sentence",
//	    System: "You are a security expert",
//	})
//	fmt.Println(resp.Text)
//
// Streaming with events:
//
//	for event, err := range provider.Stream(ctx, req) {
//	    if err != nil {
//	        return err
//	    }
//	    switch e := event.(type) {
//	    case ai.TextEvent:
//	        fmt.Print(e.Text)
//	    case ai.ToolCallEvent:
//	        // Handle tool invocation
//	    }
//	}
//
// Agentic session:
//
//	session := ai.NewSession(provider, ai.SessionConfig{
//	    WorkDir: "/path/to/repo",
//	    Sandbox: ai.SandboxWorkspaceWrite,
//	    Tools:   []ai.Tool{ai.ShellTool{}, ai.FileTool{}},
//	})
//	result, _ := session.Run(ctx, "Fix the vulnerability in package.json")
//
// # Extending
//
// To add a new provider:
//
//  1. Create a package under internal/ai/providers/<name>/
//  2. Implement the [Provider] interface
//  3. Register via init(): ai.RegisterProvider(&MyProvider{})
//
// See the providers subpackage for reference implementations.
package ai
