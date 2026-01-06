package otel

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"
)

func TestAuditHandler_FiltersNonAuditMessages(t *testing.T) {
	var buf bytes.Buffer
	handler := NewAuditHandler(&buf, "deputy.")
	logger := slog.New(handler)

	// Log a non-audit message
	logger.Info("regular log message", "key", "value")

	// Should not appear in audit log
	if buf.Len() > 0 {
		t.Errorf("non-audit message should not be written, got: %s", buf.String())
	}
}

func TestAuditHandler_PassesAuditMessages(t *testing.T) {
	var buf bytes.Buffer
	handler := NewAuditHandler(&buf, "deputy.")
	logger := slog.New(handler)

	// Log an audit message
	logger.Info("deputy.scan.completed", "target", "github.com/example/repo", "vulns", 5)

	// Should appear in audit log as JSON
	if buf.Len() == 0 {
		t.Fatal("audit message should be written")
	}

	// Parse the JSON output
	var record map[string]any
	if err := json.Unmarshal(buf.Bytes(), &record); err != nil {
		t.Fatalf("failed to parse JSON output: %v", err)
	}

	// Verify message
	if msg, ok := record["msg"].(string); !ok || msg != "deputy.scan.completed" {
		t.Errorf("msg = %v, want 'deputy.scan.completed'", record["msg"])
	}

	// Verify attributes
	if target, ok := record["target"].(string); !ok || target != "github.com/example/repo" {
		t.Errorf("target = %v, want 'github.com/example/repo'", record["target"])
	}
}

func TestAuditHandler_DifferentPrefixes(t *testing.T) {
	tests := []struct {
		prefix  string
		message string
		want    bool // should be written
	}{
		{"deputy.", "deputy.scan.started", true},
		{"deputy.", "deputy.policy.denied", true},
		{"deputy.", "regular message", false},
		{"audit.", "audit.action.performed", true},
		{"audit.", "deputy.scan.started", false},
		{"", "any message", true}, // Empty prefix matches all
	}

	for _, tt := range tests {
		t.Run(tt.prefix+"_"+tt.message, func(t *testing.T) {
			var buf bytes.Buffer
			handler := NewAuditHandler(&buf, tt.prefix)
			logger := slog.New(handler)

			logger.Info(tt.message)

			written := buf.Len() > 0
			if written != tt.want {
				t.Errorf("written = %v, want %v", written, tt.want)
			}
		})
	}
}

func TestAuditHandler_WithAttrs(t *testing.T) {
	var buf bytes.Buffer
	handler := NewAuditHandler(&buf, "deputy.")
	handlerWithAttrs := handler.WithAttrs([]slog.Attr{slog.String("source", "test")})
	logger := slog.New(handlerWithAttrs)

	logger.Info("deputy.test.event", "extra", "value")

	var record map[string]any
	if err := json.Unmarshal(buf.Bytes(), &record); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	if record["source"] != "test" {
		t.Errorf("source = %v, want 'test'", record["source"])
	}
}

func TestAuditHandler_WithGroup(t *testing.T) {
	var buf bytes.Buffer
	handler := NewAuditHandler(&buf, "deputy.")
	handlerWithGroup := handler.WithGroup("context")
	logger := slog.New(handlerWithGroup)

	logger.Info("deputy.test.event", "key", "value")

	var record map[string]any
	if err := json.Unmarshal(buf.Bytes(), &record); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	// The key should be nested under "context" group
	if ctx, ok := record["context"].(map[string]any); ok {
		if ctx["key"] != "value" {
			t.Errorf("context.key = %v, want 'value'", ctx["key"])
		}
	} else {
		t.Errorf("expected 'context' group in output, got: %v", record)
	}
}

func TestTraceContextHandler_AddsTraceInfo(t *testing.T) {
	var buf bytes.Buffer
	baseHandler := slog.NewJSONHandler(&buf, nil)
	handler := NewTraceContextHandler(baseHandler)
	logger := slog.New(handler)

	// Without trace context, should still work
	logger.Info("test message")

	if buf.Len() == 0 {
		t.Fatal("message should be written")
	}
}

func TestMultiHandler_FansOut(t *testing.T) {
	var buf1, buf2 bytes.Buffer
	h1 := slog.NewJSONHandler(&buf1, nil)
	h2 := slog.NewJSONHandler(&buf2, nil)
	multi := NewMultiHandler(h1, h2)
	logger := slog.New(multi)

	logger.Info("test message")

	if buf1.Len() == 0 {
		t.Error("first handler should receive message")
	}
	if buf2.Len() == 0 {
		t.Error("second handler should receive message")
	}
}

func TestMultiHandler_Enabled(t *testing.T) {
	h1 := slog.NewJSONHandler(nil, &slog.HandlerOptions{Level: slog.LevelError})
	h2 := slog.NewJSONHandler(nil, &slog.HandlerOptions{Level: slog.LevelDebug})
	multi := NewMultiHandler(h1, h2)

	// Should be enabled if any handler is enabled
	if !multi.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("multi handler should be enabled for Info if any child is enabled")
	}
}
