package ai

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"slices"
	"sync"
)

// Provider represents an LLM backend capable of generating completions.
// Providers are stateless and handle the raw API/CLI communication.
// For stateful interactions, use [Session].
type Provider interface {
	// Name returns the unique identifier for this provider.
	Name() string

	// Complete sends a prompt and returns the full response.
	// Use this for simple, single-turn completions.
	Complete(ctx context.Context, req *CompletionRequest) (*CompletionResponse, error)

	// Stream sends a prompt and yields events as they occur.
	// Use this for real-time display of long-running generations.
	Stream(ctx context.Context, req *CompletionRequest) iter.Seq2[StreamEvent, error]

	// Capabilities returns what this provider supports.
	Capabilities() ProviderCapabilities
}

// ProviderCapabilities describes what a provider can do.
type ProviderCapabilities struct {
	// Streaming indicates the provider supports real-time event streaming.
	Streaming bool

	// ToolUse indicates the provider supports tool/function calling.
	ToolUse bool

	// Vision indicates the provider can process images.
	Vision bool

	// Agentic indicates the provider can execute code and modify files.
	// This is true for CLI-based agents like Codex and Claude Code.
	Agentic bool

	// SessionResumption indicates the provider supports resuming conversations.
	SessionResumption bool

	// MaxContextTokens is the maximum context window size (0 = unknown).
	MaxContextTokens int
}

// CompletionRequest contains parameters for a completion request.
type CompletionRequest struct {
	// Prompt is the user's input message.
	Prompt string

	// System is the system prompt that sets the AI's behavior.
	// Optional; providers may have defaults.
	System string

	// Messages is the conversation history for multi-turn interactions.
	// If provided, Prompt is appended as the final user message.
	Messages []Message

	// Model overrides the provider's default model.
	Model string

	// MaxTokens limits the response length.
	// 0 means use provider default.
	MaxTokens int

	// Temperature controls randomness (0.0 = deterministic, 1.0+ = creative).
	// Negative values mean use provider default.
	Temperature float64

	// Tools are the tools/functions available to the model.
	Tools []Tool

	// SessionID resumes a previous conversation (provider-specific).
	SessionID string

	// WorkDir is the working directory for agentic providers.
	WorkDir string

	// Sandbox controls file/command permissions for agentic providers.
	Sandbox Sandbox
}

// CompletionResponse contains the result of a completion request.
type CompletionResponse struct {
	// Text is the generated text response.
	Text string

	// ToolCalls contains any tool invocations requested by the model.
	ToolCalls []ToolCall

	// SessionID is for resuming this conversation later.
	SessionID string

	// Usage contains token usage statistics.
	Usage Usage

	// FinishReason indicates why generation stopped.
	FinishReason FinishReason
}

// Message represents a single message in a conversation.
type Message struct {
	Role    Role   // user, assistant, system, tool
	Content string
	Name    string // For tool messages, the tool name
}

// Role identifies who sent a message.
type Role string

const (
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
	RoleSystem    Role = "system"
	RoleTool      Role = "tool"
)

// Usage contains token usage statistics.
type Usage struct {
	PromptTokens     int
	CompletionTokens int
	TotalTokens      int
}

// FinishReason indicates why generation stopped.
type FinishReason string

const (
	FinishReasonStop      FinishReason = "stop"       // Natural completion
	FinishReasonLength    FinishReason = "length"     // Hit max tokens
	FinishReasonToolCalls FinishReason = "tool_calls" // Model wants to use tools
	FinishReasonError     FinishReason = "error"      // Error during generation
)

// Sandbox controls what an agentic provider can do.
type Sandbox string

const (
	// SandboxReadOnly allows read-only access to the workspace.
	SandboxReadOnly Sandbox = "read-only"

	// SandboxWorkspaceWrite allows read/write within the workspace only.
	SandboxWorkspaceWrite Sandbox = "workspace-write"

	// SandboxFullAccess allows unrestricted access (dangerous).
	SandboxFullAccess Sandbox = "full-access"
)

// Tool represents a function/tool that can be called by the model.
type Tool interface {
	// Name returns the tool's identifier.
	Name() string

	// Description returns a human-readable description for the model.
	Description() string

	// Schema returns the JSON Schema for the tool's parameters.
	Schema() map[string]any
}

// ToolCall represents a request from the model to invoke a tool.
type ToolCall struct {
	ID        string
	Name      string
	Arguments map[string]any
}

// StreamEvent represents an event during streaming generation.
type StreamEvent interface {
	eventType() streamEventType
}

type streamEventType string

const (
	streamEventText    streamEventType = "text"
	streamEventTool    streamEventType = "tool"
	streamEventCommand streamEventType = "command"
	streamEventFile    streamEventType = "file"
	streamEventError   streamEventType = "error"
	streamEventDone    streamEventType = "done"
	streamEventStatus  streamEventType = "status"
)

// TextEvent contains incremental text output.
type TextEvent struct {
	Text string
}

func (TextEvent) eventType() streamEventType { return streamEventText }

// ToolCallEvent indicates the model wants to call a tool.
type ToolCallEvent struct {
	Call ToolCall
}

func (ToolCallEvent) eventType() streamEventType { return streamEventTool }

// CommandEvent represents a shell command execution (agentic providers).
type CommandEvent struct {
	Command  string
	Status   string // "running", "completed", "failed"
	ExitCode *int
	Output   string
}

func (CommandEvent) eventType() streamEventType { return streamEventCommand }

// FileEvent represents a file operation (agentic providers).
type FileEvent struct {
	Path   string
	Action string // "create", "modify", "delete", "read"
	Status string // "pending", "completed", "failed"
}

func (FileEvent) eventType() streamEventType { return streamEventFile }

// ErrorEvent represents an error during streaming.
type ErrorEvent struct {
	Message string
	Err     error
}

func (ErrorEvent) eventType() streamEventType { return streamEventError }

// Error returns the underlying error.
func (e ErrorEvent) Error() error {
	if e.Err != nil {
		return e.Err
	}
	if e.Message != "" {
		return errors.New(e.Message)
	}
	return errors.New("unknown AI error")
}

// DoneEvent signals that generation is complete.
type DoneEvent struct {
	SessionID    string
	FinishReason FinishReason
	Usage        Usage  // Token usage for this generation
	Model        string // Model that was actually used (if reported by provider)
}

func (DoneEvent) eventType() streamEventType { return streamEventDone }

// UsageEvent reports token usage during streaming (emitted periodically or at end).
type UsageEvent struct {
	Usage Usage
}

func (UsageEvent) eventType() streamEventType { return streamEventDone } // Reuse done type for simplicity

// StatusEvent provides progress hints during streaming (for spinner updates).
// These events don't contain content but indicate what the agent is doing.
type StatusEvent struct {
	Status string // e.g., "thinking", "analyzing", "waiting"
}

func (StatusEvent) eventType() streamEventType { return streamEventStatus }

// Registry manages available AI providers.
type Registry struct {
	mu        sync.RWMutex
	providers map[string]Provider
}

// NewRegistry creates an empty provider registry.
func NewRegistry() *Registry {
	return &Registry{
		providers: make(map[string]Provider),
	}
}

// Register adds a provider to the registry.
func (r *Registry) Register(p Provider) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	name := p.Name()
	if _, exists := r.providers[name]; exists {
		return fmt.Errorf("ai provider %q already registered", name)
	}
	r.providers[name] = p
	return nil
}

// MustRegister adds a provider, panicking on error.
// Use only in init() functions.
func (r *Registry) MustRegister(p Provider) {
	if err := r.Register(p); err != nil {
		panic(err)
	}
}

// Get retrieves a provider by name.
func (r *Registry) Get(name string) (Provider, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	p, ok := r.providers[name]
	if !ok {
		return nil, fmt.Errorf("unknown ai provider %q", name)
	}
	return p, nil
}

// List returns all registered provider names, sorted.
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.providers))
	for name := range r.providers {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// Available returns all registered providers.
func (r *Registry) Available() []Provider {
	r.mu.RLock()
	defer r.mu.RUnlock()

	providers := make([]Provider, 0, len(r.providers))
	for _, p := range r.providers {
		providers = append(providers, p)
	}
	return providers
}

// DefaultRegistry is the global provider registry.
var DefaultRegistry = NewRegistry()

// RegisterProvider adds a provider to the default registry.
func RegisterProvider(p Provider) error {
	return DefaultRegistry.Register(p)
}

// MustRegisterProvider adds a provider, panicking on error.
func MustRegisterProvider(p Provider) {
	DefaultRegistry.MustRegister(p)
}

// GetProvider retrieves a provider from the default registry.
func GetProvider(name string) (Provider, error) {
	return DefaultRegistry.Get(name)
}

// ListProviders returns all registered provider names.
func ListProviders() []string {
	return DefaultRegistry.List()
}

// AvailableProviders returns all registered providers.
func AvailableProviders() []Provider {
	return DefaultRegistry.Available()
}
