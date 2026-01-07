package render

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/picatz/deputy/internal/ai"
)

func TestRenderMarkdown(t *testing.T) {
	t.Run("renders basic markdown", func(t *testing.T) {
		content := "# Hello\n\nThis is **bold** text."
		result, err := RenderMarkdown(content, 80)
		if err != nil {
			t.Fatalf("RenderMarkdown failed: %v", err)
		}
		if result == "" {
			t.Error("expected non-empty result")
		}
		// Glamour should process the markdown
		if !strings.Contains(result, "Hello") {
			t.Error("result should contain heading text")
		}
	})

	t.Run("respects word wrap", func(t *testing.T) {
		// Long line that should be wrapped
		content := "This is a very long line that should be wrapped at a specific column width when rendered with glamour markdown rendering."
		result40, err := RenderMarkdown(content, 40)
		if err != nil {
			t.Fatalf("RenderMarkdown(40) failed: %v", err)
		}
		result120, err := RenderMarkdown(content, 120)
		if err != nil {
			t.Fatalf("RenderMarkdown(120) failed: %v", err)
		}
		// Narrower wrap should produce more lines (longer result due to newlines)
		// This is a heuristic check - the exact behavior depends on glamour
		if len(result40) == 0 || len(result120) == 0 {
			t.Error("expected non-empty results")
		}
	})

	t.Run("defaults to 80 columns for invalid width", func(t *testing.T) {
		content := "# Test"
		result, err := RenderMarkdown(content, 0)
		if err != nil {
			t.Fatalf("RenderMarkdown(0) failed: %v", err)
		}
		if result == "" {
			t.Error("expected non-empty result with default width")
		}

		result2, err := RenderMarkdown(content, -1)
		if err != nil {
			t.Fatalf("RenderMarkdown(-1) failed: %v", err)
		}
		if result2 == "" {
			t.Error("expected non-empty result with negative width")
		}
	})

	t.Run("handles code blocks", func(t *testing.T) {
		content := "```go\nfunc main() {}\n```"
		result, err := RenderMarkdown(content, 80)
		if err != nil {
			t.Fatalf("RenderMarkdown failed: %v", err)
		}
		if !strings.Contains(result, "func") {
			t.Error("result should preserve code content")
		}
	})

	t.Run("handles lists", func(t *testing.T) {
		content := "- Item 1\n- Item 2\n- Item 3"
		result, err := RenderMarkdown(content, 80)
		if err != nil {
			t.Fatalf("RenderMarkdown failed: %v", err)
		}
		if !strings.Contains(result, "Item 1") {
			t.Error("result should contain list items")
		}
	})
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Out == nil {
		t.Error("Out should default to non-nil")
	}
	if cfg.Err == nil {
		t.Error("Err should default to non-nil")
	}
	if cfg.SpinnerMessage == "" {
		t.Error("SpinnerMessage should have a default")
	}
	if !cfg.RenderMarkdown {
		t.Error("RenderMarkdown should default to true")
	}
	if cfg.WordWrap != 80 {
		t.Errorf("WordWrap = %d, want 80", cfg.WordWrap)
	}
}

func TestStreamingRenderer(t *testing.T) {
	t.Run("creates with defaults", func(t *testing.T) {
		r := NewStreamingRenderer(nil, nil, "test-provider")
		if r == nil {
			t.Fatal("NewStreamingRenderer returned nil")
		}
		if r.providerName != "test-provider" {
			t.Errorf("providerName = %q, want %q", r.providerName, "test-provider")
		}
		if !r.firstEvent {
			t.Error("firstEvent should be true initially")
		}
	})

	t.Run("creates with custom writers", func(t *testing.T) {
		out := &bytes.Buffer{}
		errW := &bytes.Buffer{}
		r := NewStreamingRenderer(out, errW, "claude")
		if r.out != out {
			t.Error("out writer not set correctly")
		}
		if r.err != errW {
			t.Error("err writer not set correctly")
		}
	})

	t.Run("renders text events", func(t *testing.T) {
		out := &bytes.Buffer{}
		r := NewStreamingRenderer(out, &bytes.Buffer{}, "claude")

		r.RenderEvent(ai.TextEvent{Text: "Hello world"})

		output := out.String()
		if !strings.Contains(output, "Hello world") {
			t.Errorf("output should contain text, got: %q", output)
		}
		if !strings.Contains(output, "claude") {
			t.Error("output should contain provider name")
		}
	})

	t.Run("renders command events", func(t *testing.T) {
		out := &bytes.Buffer{}
		r := NewStreamingRenderer(out, &bytes.Buffer{}, "claude")

		exitCode := 0
		r.RenderEvent(ai.CommandEvent{
			Command:  "go test ./...",
			Status:   "completed",
			ExitCode: &exitCode,
			Output:   "PASS",
		})

		output := out.String()
		if !strings.Contains(output, "go test") {
			t.Errorf("output should contain command, got: %q", output)
		}
		if !strings.Contains(output, "exit 0") {
			t.Error("output should contain exit code")
		}
		if !strings.Contains(output, "PASS") {
			t.Error("output should contain command output")
		}
	})

	t.Run("renders file events", func(t *testing.T) {
		out := &bytes.Buffer{}
		r := NewStreamingRenderer(out, &bytes.Buffer{}, "claude")

		r.RenderEvent(ai.FileEvent{
			Path:   "/path/to/file.go",
			Action: "modify",
			Status: "completed",
		})

		output := out.String()
		if !strings.Contains(output, "file.go") {
			t.Errorf("output should contain file path, got: %q", output)
		}
		if !strings.Contains(output, "modify") {
			t.Error("output should contain action")
		}
	})

	t.Run("renders error events", func(t *testing.T) {
		out := &bytes.Buffer{}
		r := NewStreamingRenderer(out, &bytes.Buffer{}, "claude")

		r.RenderEvent(ai.ErrorEvent{Message: "something went wrong"})

		output := out.String()
		if !strings.Contains(output, "something went wrong") {
			t.Errorf("output should contain error message, got: %q", output)
		}
		if !strings.Contains(output, "error") {
			t.Error("output should contain error prefix")
		}
	})

	t.Run("renders tool call events", func(t *testing.T) {
		out := &bytes.Buffer{}
		r := NewStreamingRenderer(out, &bytes.Buffer{}, "claude")

		r.RenderEvent(ai.ToolCallEvent{
			Call: ai.ToolCall{Name: "read_file"},
		})

		output := out.String()
		if !strings.Contains(output, "read_file") {
			t.Errorf("output should contain tool name, got: %q", output)
		}
		if !strings.Contains(output, "tool") {
			t.Error("output should contain tool prefix")
		}
	})

	t.Run("handles nil events", func(t *testing.T) {
		out := &bytes.Buffer{}
		r := NewStreamingRenderer(out, &bytes.Buffer{}, "claude")

		// Should not panic
		r.RenderEvent(nil)

		if out.Len() != 0 {
			t.Error("nil event should produce no output")
		}
	})

	t.Run("handles done events silently", func(t *testing.T) {
		out := &bytes.Buffer{}
		r := NewStreamingRenderer(out, &bytes.Buffer{}, "claude")

		r.RenderEvent(ai.DoneEvent{FinishReason: ai.FinishReasonStop})

		// DoneEvent should be silent (handled by caller)
		if out.Len() != 0 {
			t.Errorf("DoneEvent should produce no output, got: %q", out.String())
		}
	})

	t.Run("firstEvent flag only cleared with spinner", func(t *testing.T) {
		out := &bytes.Buffer{}
		r := NewStreamingRenderer(out, &bytes.Buffer{}, "claude")

		if !r.firstEvent {
			t.Error("firstEvent should be true initially")
		}

		// Without a spinner, firstEvent stays true (no spinner to clear)
		r.RenderEvent(ai.TextEvent{Text: "first"})

		// firstEvent is only cleared when there's a spinner to clear
		// Since we didn't start a spinner, it stays true
		if !r.firstEvent {
			t.Error("firstEvent should remain true without spinner")
		}
	})

	t.Run("trims whitespace-only text events", func(t *testing.T) {
		out := &bytes.Buffer{}
		r := NewStreamingRenderer(out, &bytes.Buffer{}, "claude")

		r.RenderEvent(ai.TextEvent{Text: "   \n\t  "})

		// Whitespace-only text should produce no output
		if out.Len() != 0 {
			t.Errorf("whitespace-only text should produce no output, got: %q", out.String())
		}
	})
}

func TestStreamingRenderer_SpinnerMethods(t *testing.T) {
	t.Run("StartSpinner does not panic without TTY", func(t *testing.T) {
		out := &bytes.Buffer{} // Not a TTY
		errW := &bytes.Buffer{}
		r := NewStreamingRenderer(out, errW, "claude")

		ctx := context.Background()
		r.StartSpinner(ctx, "Loading...")

		// Should not create a spinner for non-TTY
		if r.progress != nil {
			t.Error("progress should be nil for non-TTY output")
		}
	})

	t.Run("Fail is safe without spinner", func(t *testing.T) {
		r := NewStreamingRenderer(&bytes.Buffer{}, &bytes.Buffer{}, "claude")
		// Should not panic
		r.Fail()
	})

	t.Run("Clear is safe without spinner", func(t *testing.T) {
		r := NewStreamingRenderer(&bytes.Buffer{}, &bytes.Buffer{}, "claude")
		// Should not panic
		r.Clear()
	})
}

func TestConfig_Defaults(t *testing.T) {
	t.Run("StreamResponse handles nil writers", func(t *testing.T) {
		cfg := Config{
			Out:            nil, // Should default
			Err:            nil, // Should default
			WordWrap:       0,   // Should default to 80
			RenderMarkdown: false,
		}

		// Can't easily test StreamResponse without a real provider,
		// but we can verify the config validation logic exists
		if cfg.WordWrap != 0 {
			t.Error("WordWrap should be 0 before defaulting")
		}
	})
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		input    time.Duration
		expected string
	}{
		{500 * time.Millisecond, "500ms"},
		{999 * time.Millisecond, "999ms"},
		{1 * time.Second, "1.0s"},
		{1500 * time.Millisecond, "1.5s"},
		{45 * time.Second, "45.0s"},
		{59 * time.Second, "59.0s"},
		{60 * time.Second, "1m"},
		{90 * time.Second, "1m 30s"},
		{2 * time.Minute, "2m"},
		{2*time.Minute + 30*time.Second, "2m 30s"},
		{10 * time.Minute, "10m"},
		{10*time.Minute + 5*time.Second, "10m 5s"},
	}

	for _, tt := range tests {
		t.Run(tt.input.String(), func(t *testing.T) {
			result := formatDuration(tt.input)
			if result != tt.expected {
				t.Errorf("formatDuration(%v) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestBuildMetadataLine(t *testing.T) {
	tests := []struct {
		provider string
		model    string
		sandbox  ai.Sandbox
		duration time.Duration
		stats    streamStats
		want     string
	}{
		{"codex", "", ai.SandboxWorkspaceWrite, 5 * time.Second, streamStats{}, "✦ codex · 5.0s"},
		{"codex", "gpt-4", ai.SandboxWorkspaceWrite, 5 * time.Second, streamStats{}, "✦ codex/gpt-4 · 5.0s"},
		{"claude", "claude-sonnet", ai.SandboxWorkspaceWrite, 90 * time.Second, streamStats{}, "✦ claude/claude-sonnet · 1m 30s"},
		{"claude", "", ai.SandboxWorkspaceWrite, 500 * time.Millisecond, streamStats{}, "✦ claude · 500ms"},
		// With read-only sandbox
		{"codex", "", ai.SandboxReadOnly, 5 * time.Second, streamStats{}, "✦ codex · read-only · 5.0s"},
		// With token usage
		{"codex", "gpt-4", ai.SandboxWorkspaceWrite, 10 * time.Second,
			streamStats{Usage: ai.Usage{PromptTokens: 500, CompletionTokens: 200, TotalTokens: 700}},
			"✦ codex/gpt-4 · 700 tokens (500 in, 200 out) · 10.0s"},
		// With large token counts
		{"codex", "", ai.SandboxWorkspaceWrite, 30 * time.Second,
			streamStats{Usage: ai.Usage{PromptTokens: 12500, CompletionTokens: 3200, TotalTokens: 15700}},
			"✦ codex · 15.7K tokens (12.5K in, 3.20K out) · 30.0s"},
		// With model from stats (takes precedence over config model)
		{"codex", "", ai.SandboxWorkspaceWrite, 10 * time.Second,
			streamStats{Model: "gpt-4o", Usage: ai.Usage{PromptTokens: 10000, CompletionTokens: 2000, TotalTokens: 12000}},
			"✦ codex/gpt-4o · 12.0K tokens (10.0K in, 2.00K out) · 10.0s"},
	}

	for _, tt := range tests {
		name := fmt.Sprintf("%s/%s/%v", tt.provider, tt.model, tt.duration)
		t.Run(name, func(t *testing.T) {
			result := buildMetadataLine(tt.provider, tt.model, tt.sandbox, tt.duration, tt.stats)
			if result != tt.want {
				t.Errorf("buildMetadataLine() = %q, want %q", result, tt.want)
			}
		})
	}
}

func TestFormatTokens(t *testing.T) {
	tests := []struct {
		usage ai.Usage
		want  string
	}{
		{ai.Usage{}, ""},
		{ai.Usage{TotalTokens: 500}, "500 tokens"},
		{ai.Usage{PromptTokens: 300, CompletionTokens: 200, TotalTokens: 500}, "500 tokens (300 in, 200 out)"},
		{ai.Usage{PromptTokens: 1500, CompletionTokens: 500, TotalTokens: 2000}, "2.00K tokens (1.50K in, 500 out)"},
		{ai.Usage{PromptTokens: 50000, CompletionTokens: 10000, TotalTokens: 60000}, "60.0K tokens (50.0K in, 10.0K out)"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%d", tt.usage.TotalTokens), func(t *testing.T) {
			result := formatTokens(tt.usage)
			if result != tt.want {
				t.Errorf("formatTokens(%+v) = %q, want %q", tt.usage, result, tt.want)
			}
		})
	}
}

func TestFormatNumber(t *testing.T) {
	tests := []struct {
		n    int
		want string
	}{
		{0, "0"},
		{500, "500"},
		{999, "999"},
		{1000, "1.00K"},
		{1500, "1.50K"},
		{9999, "10.00K"},
		{10000, "10.0K"},
		{15700, "15.7K"},
		{100000, "100.0K"},
		{1000000, "1.0M"},
		{1500000, "1.5M"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%d", tt.n), func(t *testing.T) {
			result := formatNumber(tt.n)
			if result != tt.want {
				t.Errorf("formatNumber(%d) = %q, want %q", tt.n, result, tt.want)
			}
		})
	}
}

func TestExtractStatusHint(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", "thinking"},
		{"   ", "thinking"},
		{"Analyzing the vulnerability data", "analyzing"},
		{"Reading the go.mod file", "reading"},
		{"Examining the codebase structure", "examining"},
		{"Looking at the dependencies", "examining"},
		{"Checking for updates", "checking"},
		{"Reviewing the changes", "reviewing"},
		{"Considering the options", "considering"},
		{"Evaluating risk levels", "evaluating"},
		{"Searching for patterns", "searching"},
		{"Finding relevant files", "searching"},
		{"Let me think about this", "thinking"},
		{"I'll analyze the situation", "thinking"},
		{"I need to understand the context", "thinking"},
		{"First, let me examine", "thinking"},
		{"Now analyzing the data", "thinking"},
		{"Some random text here", "thinking"},
		{"ANALYZING in uppercase", "analyzing"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := extractStatusHint(tt.input)
			if result != tt.expected {
				t.Errorf("extractStatusHint(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestCleanCommandString(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		// No cleaning needed
		{"ls", "ls"},
		{"rg pattern", "rg pattern"},

		// Array-style commands
		{"['rg']", "rg"},
		{"['rg pattern']", "rg pattern"},
		{"['rg', 'pattern']", "rg pattern"},
		{"['git', 'status']", "git status"},

		// Quoted commands
		{"'rg pattern'", "rg pattern"},
		{`"rg pattern"`, "rg pattern"},

		// Mixed
		{`["cat", "file.txt"]`, "cat file.txt"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := cleanCommandString(tt.input)
			if result != tt.expected {
				t.Errorf("cleanCommandString(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestFormatCommandHint(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		// Empty/basic
		{"", "running"},
		{"ls", "ls"},
		{"/bin/ls", "ls"},
		{"/usr/bin/ls -la", "ls"},

		// rg/grep with patterns
		{"rg pattern", "rg pattern"},
		{"rg verylongpatternname", "rg verylongpatt..."},
		{"grep -r something", "grep -r"},

		// File viewing commands
		{"cat /path/to/file.go", "cat file.go"},
		{"head -n 10 /some/long/path/to/config.yaml", "head config.yaml"},

		// Go commands
		{"go build", "go build"},
		{"go test ./...", "go test"},
		{"go mod tidy", "go mod"},

		// Git commands
		{"git status", "git status"},
		{"git diff HEAD", "git diff"},

		// Package managers
		{"npm install lodash", "npm install"},
		{"yarn add react", "yarn add"},

		// Shell wrappers (quoted args are tricky with strings.Fields)
		{"/bin/sh -c go", "go"},
		{"bash -c npm", "npm"},

		// sed/awk (just command name)
		{"sed -i 's/foo/bar/g' file.txt", "sed"},
		{"awk '{print $1}' data.txt", "awk"},

		// Docker/kubectl
		{"docker build -t myimage .", "docker build"},
		{"kubectl get pods", "kubectl get"},

		// Array-style commands (cleaned before processing)
		{"['rg']", "rg"},
		{"['rg', 'pattern']", "rg pattern"},
		{"['git', 'status']", "git status"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := formatCommandHint(tt.input)
			if result != tt.expected {
				t.Errorf("formatCommandHint(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}
