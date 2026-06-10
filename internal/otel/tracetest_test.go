package otel

import (
	"context"
	"errors"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// setupTracetestProvider creates an in-memory span recorder for testing.
// Returns the recorder and a cleanup function that restores the global tracer.
func setupTracetestProvider(t *testing.T) *tracetest.SpanRecorder {
	t.Helper()

	recorder := tracetest.NewSpanRecorder()
	provider := trace.NewTracerProvider(trace.WithSpanProcessor(recorder))

	// Save old provider and restore after test
	oldProvider := otel.GetTracerProvider()
	otel.SetTracerProvider(provider)

	t.Cleanup(func() {
		provider.Shutdown(context.Background())
		otel.SetTracerProvider(oldProvider)
	})

	return recorder
}

// TestStartSpan_RecordsSpan verifies spans are recorded with correct name.
func TestStartSpan_RecordsSpan(t *testing.T) {
	recorder := setupTracetestProvider(t)

	ctx, span := StartSpan(context.Background(), "test.operation")
	span.End()

	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}

	if spans[0].Name() != "test.operation" {
		t.Errorf("expected span name 'test.operation', got %q", spans[0].Name())
	}

	// Verify span context was propagated
	if !span.SpanContext().IsValid() {
		t.Error("expected valid span context")
	}

	// Verify context contains the span
	spanFromCtx := SpanFromContext(ctx)
	if spanFromCtx.SpanContext().TraceID() != span.SpanContext().TraceID() {
		t.Error("span from context should have same trace ID")
	}
}

// TestSetSpanErrorRecordsErrorStatus verifies error status and attributes.
func TestSetSpanErrorRecordsErrorStatus(t *testing.T) {
	recorder := setupTracetestProvider(t)

	ctx, span := StartSpan(context.Background(), "test.error")
	_ = ctx // ctx unused in this test
	testErr := errors.New("something went wrong")
	SetSpanError(span, testErr)
	span.End()

	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}

	s := spans[0]
	if s.Status().Code != codes.Error {
		t.Errorf("expected Error status code, got %v", s.Status().Code)
	}

	if s.Status().Description != "something went wrong" {
		t.Errorf("expected error description, got %q", s.Status().Description)
	}

	// Verify error event was recorded
	events := s.Events()
	foundErrorEvent := false
	for _, e := range events {
		if e.Name == "exception" {
			foundErrorEvent = true
			break
		}
	}
	if !foundErrorEvent {
		t.Error("expected exception event to be recorded")
	}
}

// TestSetSpanOK_RecordsOKStatus verifies OK status is set correctly.
func TestSetSpanOK_RecordsOKStatus(t *testing.T) {
	recorder := setupTracetestProvider(t)

	_, span := StartSpan(context.Background(), "test.success")
	SetSpanOK(span)
	span.End()

	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}

	if spans[0].Status().Code != codes.Ok {
		t.Errorf("expected Ok status code, got %v", spans[0].Status().Code)
	}
}

// TestRecordScanResults_SetsAttributes verifies scan result attributes.
func TestRecordScanResults_SetsAttributes(t *testing.T) {
	recorder := setupTracetestProvider(t)

	_, span := StartSpan(context.Background(), "deputy.scan")
	RecordScanResults(span, 100, 15, 2, 5, 6, 2)
	span.End()

	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}

	attrs := spans[0].Attributes()
	attrMap := make(map[attribute.Key]attribute.Value)
	for _, a := range attrs {
		attrMap[a.Key] = a.Value
	}

	// Verify all scan result attributes
	tests := []struct {
		key      attribute.Key
		expected int64
	}{
		{AttrPackageCount, 100},
		{AttrVulnerabilityCount, 15},
		{AttrVulnerabilityCritical, 2},
		{AttrVulnerabilityHigh, 5},
		{AttrVulnerabilityMedium, 6},
		{AttrVulnerabilityLow, 2},
	}

	for _, tt := range tests {
		v, ok := attrMap[tt.key]
		if !ok {
			t.Errorf("missing attribute %s", tt.key)
			continue
		}
		if v.AsInt64() != tt.expected {
			t.Errorf("%s = %d, want %d", tt.key, v.AsInt64(), tt.expected)
		}
	}
}

// TestAddSpanEvent_RecordsEvent verifies events with attributes.
func TestAddSpanEvent_RecordsEvent(t *testing.T) {
	recorder := setupTracetestProvider(t)

	_, span := StartSpan(context.Background(), "test.events")
	AddSpanEvent(span, "cache.access",
		AttrCacheType.String("osv"),
		AttrCacheHit.Bool(true),
	)
	span.End()

	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}

	events := spans[0].Events()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	e := events[0]
	if e.Name != "cache.access" {
		t.Errorf("expected event name 'cache.access', got %q", e.Name)
	}

	// Check event attributes
	attrMap := make(map[attribute.Key]attribute.Value)
	for _, a := range e.Attributes {
		attrMap[a.Key] = a.Value
	}

	if v, ok := attrMap[AttrCacheType]; !ok || v.AsString() != "osv" {
		t.Errorf("expected cache.type=osv, got %v", v)
	}
	if v, ok := attrMap[AttrCacheHit]; !ok || !v.AsBool() {
		t.Errorf("expected cache.hit=true, got %v", v)
	}
}

// TestRecordCacheAccess_AddsEvent verifies cache access helper.
func TestRecordCacheAccess_AddsEvent(t *testing.T) {
	recorder := setupTracetestProvider(t)

	_, span := StartSpan(context.Background(), "test.cache")
	RecordCacheAccess(span, "depsdev", true, "pkg:golang/example")
	RecordCacheAccess(span, "osv", false, "CVE-2021-1234")
	span.End()

	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}

	events := spans[0].Events()
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}

	// Both events should be cache.access
	for _, e := range events {
		if e.Name != "cache.access" {
			t.Errorf("expected event name 'cache.access', got %q", e.Name)
		}
	}
}

// TestRecordPolicyResult_AddsEvent verifies policy result helper.
func TestRecordPolicyResult_AddsEvent(t *testing.T) {
	recorder := setupTracetestProvider(t)

	_, span := StartSpan(context.Background(), "test.policy")
	RecordPolicyResult(span, "block-critical", "deny")
	span.End()

	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}

	events := spans[0].Events()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	e := events[0]
	if e.Name != "policy.evaluated" {
		t.Errorf("expected event name 'policy.evaluated', got %q", e.Name)
	}

	attrMap := make(map[attribute.Key]attribute.Value)
	for _, a := range e.Attributes {
		attrMap[a.Key] = a.Value
	}

	if v, ok := attrMap[AttrPolicyName]; !ok || v.AsString() != "block-critical" {
		t.Errorf("expected policy.name=block-critical, got %v", v)
	}
	if v, ok := attrMap[AttrPolicyAction]; !ok || v.AsString() != "deny" {
		t.Errorf("expected policy.action=deny, got %v", v)
	}
}

// TestWithCommandAttrs_SetsCommandAttribute verifies command span options.
func TestWithCommandAttrs_SetsCommandAttribute(t *testing.T) {
	recorder := setupTracetestProvider(t)

	_, span := StartSpan(context.Background(), "deputy.cli",
		WithCommandAttrs("scan"))
	span.End()

	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}

	attrs := spans[0].Attributes()
	found := false
	for _, a := range attrs {
		if a.Key == AttrCommand && a.Value.AsString() == "scan" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected command attribute to be set")
	}
}

// TestWithTargetAttrs_SetsTargetAttributes verifies target span options.
func TestWithTargetAttrs_SetsTargetAttributes(t *testing.T) {
	recorder := setupTracetestProvider(t)

	_, span := StartSpan(context.Background(), "deputy.scan",
		WithTargetAttrs("/path/to/repo", "v1.2.3", false))
	span.End()

	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}

	attrs := spans[0].Attributes()
	attrMap := make(map[attribute.Key]attribute.Value)
	for _, a := range attrs {
		attrMap[a.Key] = a.Value
	}

	if v, ok := attrMap[AttrTargetPath]; !ok || v.AsString() != "/path/to/repo" {
		t.Errorf("expected target.path, got %v", v)
	}
	if v, ok := attrMap[AttrTargetRef]; !ok || v.AsString() != "v1.2.3" {
		t.Errorf("expected target.ref, got %v", v)
	}
	if v, ok := attrMap[AttrTargetRemote]; !ok || v.AsBool() != false {
		t.Errorf("expected target.remote=false, got %v", v)
	}
}

// TestNestedSpans_PreservesHierarchy verifies parent-child relationships.
func TestNestedSpans_PreservesHierarchy(t *testing.T) {
	recorder := setupTracetestProvider(t)

	ctx, parentSpan := StartSpan(context.Background(), "parent")
	ctx, childSpan := StartSpan(ctx, "child")
	_, grandchildSpan := StartSpan(ctx, "grandchild")

	grandchildSpan.End()
	childSpan.End()
	parentSpan.End()

	spans := recorder.Ended()
	if len(spans) != 3 {
		t.Fatalf("expected 3 spans, got %d", len(spans))
	}

	// Find spans by name
	spanByName := make(map[string]trace.ReadOnlySpan)
	for _, s := range spans {
		spanByName[s.Name()] = s
	}

	parent := spanByName["parent"]
	child := spanByName["child"]
	grandchild := spanByName["grandchild"]

	// All should share the same trace ID
	traceID := parent.SpanContext().TraceID()
	if child.SpanContext().TraceID() != traceID {
		t.Error("child should have same trace ID as parent")
	}
	if grandchild.SpanContext().TraceID() != traceID {
		t.Error("grandchild should have same trace ID as parent")
	}

	// Verify parent relationships
	if child.Parent().SpanID() != parent.SpanContext().SpanID() {
		t.Error("child's parent should be parent span")
	}
	if grandchild.Parent().SpanID() != child.SpanContext().SpanID() {
		t.Error("grandchild's parent should be child span")
	}
}

// TestSeverityCounts_Integration verifies the SeverityCounts helper.
func TestSeverityCounts_Integration(t *testing.T) {
	recorder := setupTracetestProvider(t)

	ctx, span := StartSpan(context.Background(), "deputy.scan")

	sc := SeverityCounts{
		Critical: 1,
		High:     3,
		Medium:   5,
		Low:      2,
	}

	// RecordScanCompletion should set both span attributes and call metrics
	RecordScanCompletion(ctx, ScanCompletion{
		Span:         span,
		Duration:     2.5,
		Ecosystem:    "go",
		PackageCount: 150,
		Severity:     sc,
	})
	span.End()

	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}

	attrs := spans[0].Attributes()
	attrMap := make(map[attribute.Key]attribute.Value)
	for _, a := range attrs {
		attrMap[a.Key] = a.Value
	}

	// Verify vulnerability count (should be Total())
	if v, ok := attrMap[AttrVulnerabilityCount]; !ok || v.AsInt64() != 11 {
		t.Errorf("expected vulnerability count 11, got %v", v)
	}
}

// TestSpanFromContext_ReturnsNoOpWhenMissing verifies graceful handling.
func TestSpanFromContext_ReturnsNoOpWhenMissing(t *testing.T) {
	// Don't set up a provider - use empty context
	span := SpanFromContext(context.Background())

	// Should return a no-op span that doesn't panic
	span.SetAttributes(attribute.String("key", "value"))
	span.AddEvent("test")
	SetSpanError(span, errors.New("test"))
	SetSpanOK(span)
	span.End()

	// If we got here without panicking, the test passes
}

// TestConcurrentSpans_ThreadSafe verifies spans can be created concurrently.
func TestConcurrentSpans_ThreadSafe(t *testing.T) {
	recorder := setupTracetestProvider(t)

	const numGoroutines = 100
	done := make(chan bool, numGoroutines)

	for i := range numGoroutines {
		go func(id int) {
			_, span := StartSpan(context.Background(), "concurrent.span")
			span.SetAttributes(attribute.Int("goroutine.id", id))
			span.End()
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for range numGoroutines {
		<-done
	}

	spans := recorder.Ended()
	if len(spans) != numGoroutines {
		t.Errorf("expected %d spans, got %d", numGoroutines, len(spans))
	}
}

// TestOSVAttributes_Correctness verifies OSV-specific attributes.
func TestOSVAttributes_Correctness(t *testing.T) {
	recorder := setupTracetestProvider(t)

	_, span := StartSpan(context.Background(), "deputy.osv.query",
		WithOSVAttrs(50, "batch"))
	span.End()

	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}

	attrs := spans[0].Attributes()
	attrMap := make(map[attribute.Key]attribute.Value)
	for _, a := range attrs {
		attrMap[a.Key] = a.Value
	}

	if v, ok := attrMap[AttrOSVBatchSize]; !ok || v.AsInt64() != 50 {
		t.Errorf("expected osv.batch_size=50, got %v", v)
	}
	if v, ok := attrMap[AttrOSVQueryType]; !ok || v.AsString() != "batch" {
		t.Errorf("expected osv.query_type=batch, got %v", v)
	}
}

// TestPolicyAttributes_Correctness verifies policy-specific attributes.
func TestPolicyAttributes_Correctness(t *testing.T) {
	recorder := setupTracetestProvider(t)

	_, span := StartSpan(context.Background(), "deputy.policy.eval",
		WithPolicyAttrs("block-critical", "scan_vulnerability"))
	span.End()

	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}

	attrs := spans[0].Attributes()
	attrMap := make(map[attribute.Key]attribute.Value)
	for _, a := range attrs {
		attrMap[a.Key] = a.Value
	}

	if v, ok := attrMap[AttrPolicyName]; !ok || v.AsString() != "block-critical" {
		t.Errorf("expected policy.name=block-critical, got %v", v)
	}
	if v, ok := attrMap[AttrPolicyEntrypoint]; !ok || v.AsString() != "scan_vulnerability" {
		t.Errorf("expected policy.entrypoint=scan_vulnerability, got %v", v)
	}
}

// TestProxyAttributes_Correctness verifies proxy-specific attributes.
func TestProxyAttributes_Correctness(t *testing.T) {
	recorder := setupTracetestProvider(t)

	_, span := StartSpan(context.Background(), "deputy.proxy.request",
		WithProxyAttrs("go-proxy", "go", "github.com/foo/bar", "v1.2.3"))
	span.End()

	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}

	attrs := spans[0].Attributes()
	attrMap := make(map[attribute.Key]attribute.Value)
	for _, a := range attrs {
		attrMap[a.Key] = a.Value
	}

	if v, ok := attrMap[AttrProxyListener]; !ok || v.AsString() != "go-proxy" {
		t.Errorf("expected proxy.listener, got %v", v)
	}
	if v, ok := attrMap[AttrEcosystem]; !ok || v.AsString() != "go" {
		t.Errorf("expected ecosystem, got %v", v)
	}
	if v, ok := attrMap[AttrProxyPackage]; !ok || v.AsString() != "github.com/foo/bar" {
		t.Errorf("expected proxy.package, got %v", v)
	}
	if v, ok := attrMap[AttrProxyVersion]; !ok || v.AsString() != "v1.2.3" {
		t.Errorf("expected proxy.version, got %v", v)
	}
}
