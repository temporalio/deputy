package otel

import (
	"context"
	"errors"
	"testing"

	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

func TestStartSpan(t *testing.T) {
	ctx := context.Background()
	newCtx, span := StartSpan(ctx, "test.span")

	if newCtx == nil {
		t.Error("StartSpan returned nil context")
	}
	if span == nil {
		t.Error("StartSpan returned nil span")
	}

	span.End()
}

func TestSpanFromContext_NoSpan(t *testing.T) {
	ctx := context.Background()
	span := SpanFromContext(ctx)

	if span == nil {
		t.Error("SpanFromContext should return non-nil span")
	}
	// Should return a no-op span
	if span.SpanContext().IsValid() {
		t.Error("expected invalid span context for empty context")
	}
}

func TestSetSpanError_NilError(t *testing.T) {
	_, span := StartSpan(context.Background(), "test")
	defer span.End()

	// Should not panic
	SetSpanError(span, nil)
}

func TestSetSpanError_WithError(t *testing.T) {
	// Use a recording span to verify the error was set
	_, span := StartSpan(context.Background(), "test")
	defer span.End()

	testErr := errors.New("test error")
	SetSpanError(span, testErr)

	// The span should have the error recorded
	// We can't easily verify this without a custom exporter,
	// but we ensure it doesn't panic
}

func TestSetSpanOK(t *testing.T) {
	_, span := StartSpan(context.Background(), "test")
	defer span.End()

	// Should not panic
	SetSpanOK(span)
}

func TestAddSpanEvent(t *testing.T) {
	_, span := StartSpan(context.Background(), "test")
	defer span.End()

	// Should not panic
	AddSpanEvent(span, "test.event", AttrCommand.String("scan"))
}

func TestAttributeKeys(t *testing.T) {
	// Verify attribute keys are defined and create valid attributes
	t.Run("AttrCommand", func(t *testing.T) {
		attr := AttrCommand.String("scan")
		if string(attr.Key) != "deputy.command" {
			t.Errorf("unexpected key: %s", attr.Key)
		}
	})
	t.Run("AttrTargetPath", func(t *testing.T) {
		attr := AttrTargetPath.String("/path/to/repo")
		if string(attr.Key) != "deputy.target.path" {
			t.Errorf("unexpected key: %s", attr.Key)
		}
	})
	t.Run("AttrPackageCount", func(t *testing.T) {
		attr := AttrPackageCount.Int(100)
		if string(attr.Key) != "deputy.package.count" {
			t.Errorf("unexpected key: %s", attr.Key)
		}
	})
}

func TestWithCommandAttrs(t *testing.T) {
	opt := WithCommandAttrs("scan")
	if opt == nil {
		t.Error("WithCommandAttrs returned nil")
	}
}

func TestWithTargetAttrs(t *testing.T) {
	opt := WithTargetAttrs("/path/to/repo", "main", true)
	if opt == nil {
		t.Error("WithTargetAttrs returned nil")
	}
}

func TestWithEcosystemAttr(t *testing.T) {
	opt := WithEcosystemAttr("go")
	if opt == nil {
		t.Error("WithEcosystemAttr returned nil")
	}
}

func TestWithOSVAttrs(t *testing.T) {
	opt := WithOSVAttrs(100, "batch")
	if opt == nil {
		t.Error("WithOSVAttrs returned nil")
	}
}

func TestWithPolicyAttrs(t *testing.T) {
	opt := WithPolicyAttrs("block-critical", "scan_vulnerability")
	if opt == nil {
		t.Error("WithPolicyAttrs returned nil")
	}
}

func TestWithProxyAttrs(t *testing.T) {
	opt := WithProxyAttrs("go-proxy", "go", "github.com/foo/bar", "v1.2.3")
	if opt == nil {
		t.Error("WithProxyAttrs returned nil")
	}
}

func TestRecordScanResults(t *testing.T) {
	_, span := StartSpan(context.Background(), "test")
	defer span.End()

	// Should not panic
	RecordScanResults(span, 100, 5, 1, 2, 1, 1)
}

func TestRecordCacheAccess(t *testing.T) {
	_, span := StartSpan(context.Background(), "test")
	defer span.End()

	// Should not panic
	RecordCacheAccess(span, "osv", true, "CVE-2021-1234")
	RecordCacheAccess(span, "osv", false, "CVE-2021-5678")
}

func TestRecordPolicyResult(t *testing.T) {
	_, span := StartSpan(context.Background(), "test")
	defer span.End()

	// Should not panic
	RecordPolicyResult(span, "test-policy", "deny")
	RecordPolicyResult(span, "test-policy", "allow")
}

// mockSpan is a simple mock for testing span operations
type mockSpan struct {
	noop.Span
	statusCode    codes.Code
	statusMessage string
	errorRecorded error
}

func (s *mockSpan) SetStatus(code codes.Code, msg string) {
	s.statusCode = code
	s.statusMessage = msg
}

func (s *mockSpan) RecordError(err error, _ ...trace.EventOption) {
	s.errorRecorded = err
}

func TestSetSpanError_SetsStatus(t *testing.T) {
	span := &mockSpan{}
	testErr := errors.New("test error")

	SetSpanError(span, testErr)

	if span.statusCode != codes.Error {
		t.Errorf("expected status code Error, got %v", span.statusCode)
	}
	if span.errorRecorded != testErr {
		t.Errorf("expected error to be recorded")
	}
}

func TestSetSpanOK_SetsStatus(t *testing.T) {
	span := &mockSpan{}

	SetSpanOK(span)

	if span.statusCode != codes.Ok {
		t.Errorf("expected status code Ok, got %v", span.statusCode)
	}
}

func TestRecordScanCompletion_DoesNotPanic(t *testing.T) {
	ctx := context.Background()
	_, span := StartSpan(ctx, "test")
	defer span.End()

	// Should not panic even with no collector
	RecordScanCompletion(ctx, ScanCompletion{
		Span:         span,
		Duration:     1.5,
		Ecosystem:    "go",
		PackageCount: 100,
		Severity: SeverityCounts{
			Critical: 1,
			High:     2,
			Medium:   3,
			Low:      4,
		},
	})
}

func TestScanCompletion_Fields(t *testing.T) {
	// Verify struct fields can be set correctly
	sc := ScanCompletion{
		Duration:     2.5,
		Ecosystem:    "npm",
		PackageCount: 50,
		Severity: SeverityCounts{
			Critical: 0,
			High:     1,
			Medium:   2,
			Low:      3,
		},
	}

	if sc.Duration != 2.5 {
		t.Errorf("Duration = %f, want 2.5", sc.Duration)
	}
	if sc.Ecosystem != "npm" {
		t.Errorf("Ecosystem = %q, want npm", sc.Ecosystem)
	}
	if sc.PackageCount != 50 {
		t.Errorf("PackageCount = %d, want 50", sc.PackageCount)
	}
	if sc.Severity.Total() != 6 {
		t.Errorf("Severity.Total() = %d, want 6", sc.Severity.Total())
	}
}
