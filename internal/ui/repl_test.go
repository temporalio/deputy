package ui

import (
	"bytes"
	"strings"
	"testing"
)

func TestREPLOutput_Prompt(t *testing.T) {
	var buf bytes.Buffer
	r := NewREPLOutput(&buf)
	r.Prompt("proxy")

	out := buf.String()
	if !strings.Contains(out, "proxy") {
		t.Errorf("prompt should contain context 'proxy', got: %s", out)
	}
	if !strings.Contains(out, "cel") {
		t.Errorf("prompt should contain 'cel', got: %s", out)
	}
	if !strings.Contains(out, ">") {
		t.Errorf("prompt should contain '>', got: %s", out)
	}
}

func TestREPLOutput_Result(t *testing.T) {
	tests := []struct {
		name     string
		value    any
		contains string
	}{
		{"true boolean", true, "true"},
		{"false boolean", false, "false"},
		{"string", "hello", "hello"},
		{"int", 42, "42"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			r := NewREPLOutput(&buf)
			r.Result(tt.value)

			out := buf.String()
			if !strings.Contains(out, tt.contains) {
				t.Errorf("result should contain %q, got: %s", tt.contains, out)
			}
			if !strings.Contains(out, "→") {
				t.Errorf("result should contain arrow, got: %s", out)
			}
		})
	}
}

func TestREPLOutput_ResultWithType(t *testing.T) {
	var buf bytes.Buffer
	r := NewREPLOutput(&buf)
	r.ResultWithType(true, "bool")

	out := buf.String()
	if !strings.Contains(out, "true") {
		t.Errorf("result should contain value, got: %s", out)
	}
	if !strings.Contains(out, "(bool)") {
		t.Errorf("result should contain type annotation, got: %s", out)
	}
}

func TestREPLOutput_Error(t *testing.T) {
	var buf bytes.Buffer
	r := NewREPLOutput(&buf)
	r.Error("something went wrong")

	out := buf.String()
	if !strings.Contains(out, "something went wrong") {
		t.Errorf("error should contain message, got: %s", out)
	}
	if !strings.Contains(out, "✗") {
		t.Errorf("error should contain error symbol, got: %s", out)
	}
}

func TestREPLOutput_ErrorWithHint(t *testing.T) {
	var buf bytes.Buffer
	r := NewREPLOutput(&buf)
	r.ErrorWithHint("undefined variable", "try :show to see available context")

	out := buf.String()
	if !strings.Contains(out, "undefined variable") {
		t.Errorf("should contain error message, got: %s", out)
	}
	if !strings.Contains(out, "hint:") {
		t.Errorf("should contain hint prefix, got: %s", out)
	}
	if !strings.Contains(out, ":show") {
		t.Errorf("should contain hint text, got: %s", out)
	}
}

func TestREPLOutput_CommandHelp(t *testing.T) {
	var buf bytes.Buffer
	r := NewREPLOutput(&buf)
	r.CommandHelp(":set key=value", "set request field")

	out := buf.String()
	if !strings.Contains(out, ":set key=value") {
		t.Errorf("should contain command, got: %s", out)
	}
	if !strings.Contains(out, "set request field") {
		t.Errorf("should contain description, got: %s", out)
	}
}

func TestREPLOutput_KeyValue(t *testing.T) {
	var buf bytes.Buffer
	r := NewREPLOutput(&buf)
	r.KeyValue("request.ecosystem", "npm")

	out := buf.String()
	if !strings.Contains(out, "request.ecosystem") {
		t.Errorf("should contain key, got: %s", out)
	}
	if !strings.Contains(out, "npm") {
		t.Errorf("should contain value, got: %s", out)
	}
	if !strings.Contains(out, "=") {
		t.Errorf("should contain equals sign, got: %s", out)
	}
}

func TestREPLOutput_Table(t *testing.T) {
	var buf bytes.Buffer
	r := NewREPLOutput(&buf)
	r.Table([]TableRow{
		{Label: "severity.CRITICAL", Value: "\"CRITICAL\""},
		{Label: "severity.HIGH", Value: "\"HIGH\""},
	})

	out := buf.String()
	if !strings.Contains(out, "severity.CRITICAL") {
		t.Errorf("should contain first label, got: %s", out)
	}
	if !strings.Contains(out, "severity.HIGH") {
		t.Errorf("should contain second label, got: %s", out)
	}
}

func TestHighlightCEL(t *testing.T) {
	expr := `request.ecosystem == "npm"`
	highlighted := HighlightCEL(expr, "monokai")

	// Should return something (at minimum the original)
	if highlighted == "" {
		t.Error("highlighted should not be empty")
	}
	// Basic sanity: should contain keywords
	if !strings.Contains(highlighted, "request") {
		t.Errorf("highlighted should contain 'request', got: %s", highlighted)
	}
}

func TestHighlightCEL_InvalidStyle(t *testing.T) {
	expr := `request.ecosystem`
	// Even with invalid style name, should fallback gracefully
	highlighted := HighlightCEL(expr, "nonexistent-style")
	if highlighted == "" {
		t.Error("should return something even with invalid style")
	}
}

func TestREPLOutput_FormatContext(t *testing.T) {
	var buf bytes.Buffer
	r := NewREPLOutput(&buf)

	t.Run("empty context", func(t *testing.T) {
		buf.Reset()
		r.FormatContext("request", map[string]any{})
		out := buf.String()
		if !strings.Contains(out, "empty") {
			t.Errorf("should indicate empty context, got: %s", out)
		}
	})

	t.Run("populated context", func(t *testing.T) {
		buf.Reset()
		r.FormatContext("request", map[string]any{
			"ecosystem": "npm",
			"package":   "@acme/test",
		})
		out := buf.String()
		if !strings.Contains(out, "request.ecosystem") {
			t.Errorf("should contain prefixed key, got: %s", out)
		}
		if !strings.Contains(out, "npm") {
			t.Errorf("should contain value, got: %s", out)
		}
	})
}

func TestREPLOutput_Welcome(t *testing.T) {
	var buf bytes.Buffer
	r := NewREPLOutput(&buf)
	r.Welcome("CEL Policy REPL", "Type :help for commands")

	out := buf.String()
	if !strings.Contains(out, "CEL Policy REPL") {
		t.Errorf("should contain title, got: %s", out)
	}
	if !strings.Contains(out, ":help") {
		t.Errorf("should contain subtitle, got: %s", out)
	}
}
