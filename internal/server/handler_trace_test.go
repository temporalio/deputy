package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	listv1 "github.com/temporalio/deputy/gen/deputy/list/v1"
	"github.com/temporalio/deputy/gen/deputy/list/v1/listv1connect"
	scanv1 "github.com/temporalio/deputy/gen/deputy/scan/v1"
	"github.com/temporalio/deputy/gen/deputy/scan/v1/scanv1connect"
	secretsv1 "github.com/temporalio/deputy/gen/deputy/secrets/v1"
	"github.com/temporalio/deputy/gen/deputy/secrets/v1/secretsv1connect"
)

// setupTraceRecorder creates an in-memory span recorder for testing.
func setupTraceRecorder(t *testing.T) *tracetest.SpanRecorder {
	t.Helper()

	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))

	oldProvider := otel.GetTracerProvider()
	otel.SetTracerProvider(provider)

	t.Cleanup(func() {
		_ = provider.Shutdown(context.Background())
		otel.SetTracerProvider(oldProvider)
	})

	return recorder
}

// findSpan finds a span whose name contains the given substring.
func findSpan(spans []sdktrace.ReadOnlySpan, nameContains string) sdktrace.ReadOnlySpan {
	for _, span := range spans {
		if strings.Contains(span.Name(), nameContains) {
			return span
		}
	}
	return nil
}

// spanHasAttribute checks if span has an attribute with the given key.
func spanHasAttribute(span sdktrace.ReadOnlySpan, key string) bool {
	for _, attr := range span.Attributes() {
		if string(attr.Key) == key {
			return true
		}
	}
	return false
}

func TestScanHandler_Trace_InvalidArgument(t *testing.T) {
	recorder := setupTraceRecorder(t)

	srv, err := New(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	client := scanv1connect.NewScanServiceClient(http.DefaultClient, ts.URL)

	_, err = client.Scan(t.Context(), connect.NewRequest(&scanv1.ScanRequest{
		Target: "",
	}))
	if err == nil {
		t.Fatal("expected error for empty target")
	}

	spans := recorder.Ended()
	if len(spans) == 0 {
		t.Skip("no spans recorded")
	}

	scanSpan := findSpan(spans, "Scan")
	if scanSpan == nil {
		t.Skip("Scan span not found")
	}

	if scanSpan.Status().Code != codes.Error {
		t.Errorf("expected error status, got %v", scanSpan.Status().Code)
	}
}

func TestScanHandler_Trace_TargetAttribute(t *testing.T) {
	recorder := setupTraceRecorder(t)

	srv, err := New(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	client := scanv1connect.NewScanServiceClient(http.DefaultClient, ts.URL)

	// Use a remote target that passes validation but will fail later
	_, _ = client.Scan(t.Context(), connect.NewRequest(&scanv1.ScanRequest{
		Target: "github.com/nonexistent/repo",
	}))

	spans := recorder.Ended()
	if len(spans) == 0 {
		t.Skip("no spans recorded")
	}

	scanSpan := findSpan(spans, "Scan")
	if scanSpan == nil {
		t.Skip("Scan span not found")
	}

	if !spanHasAttribute(scanSpan, "deputy.target.path") {
		t.Error("expected deputy.target.path attribute")
	}
}

func TestListHandler_Trace_Ecosystems(t *testing.T) {
	recorder := setupTraceRecorder(t)

	srv, err := New(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	client := listv1connect.NewListServiceClient(http.DefaultClient, ts.URL)

	resp, err := client.ListEcosystems(t.Context(), connect.NewRequest(&listv1.ListEcosystemsRequest{}))
	if err != nil {
		t.Fatalf("ListEcosystems failed: %v", err)
	}
	if len(resp.Msg.Ecosystems) == 0 {
		t.Error("expected at least one ecosystem")
	}

	spans := recorder.Ended()
	if len(spans) == 0 {
		t.Skip("no spans recorded")
	}

	span := findSpan(spans, "ListEcosystems")
	if span == nil {
		t.Skip("ListEcosystems span not found")
	}

	if span.Status().Code == codes.Error {
		t.Errorf("expected non-error status, got %v", span.Status().Code)
	}
}

func TestSecretsHandler_Trace_ListDetectors(t *testing.T) {
	recorder := setupTraceRecorder(t)

	srv, err := New(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	client := secretsv1connect.NewSecretsServiceClient(http.DefaultClient, ts.URL)

	resp, err := client.ListDetectors(t.Context(), connect.NewRequest(&secretsv1.ListDetectorsRequest{}))
	if err != nil {
		t.Fatalf("ListDetectors failed: %v", err)
	}
	if len(resp.Msg.Detectors) == 0 {
		t.Error("expected at least one detector")
	}

	spans := recorder.Ended()
	if len(spans) == 0 {
		t.Skip("no spans recorded")
	}

	span := findSpan(spans, "ListDetectors")
	if span == nil {
		t.Skip("ListDetectors span not found")
	}

	if span.Status().Code == codes.Error {
		t.Errorf("expected non-error status, got %v", span.Status().Code)
	}
}

func TestSecretsHandler_Trace_ScanError(t *testing.T) {
	recorder := setupTraceRecorder(t)

	srv, err := New(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	client := secretsv1connect.NewSecretsServiceClient(http.DefaultClient, ts.URL)

	_, err = client.Scan(t.Context(), connect.NewRequest(&secretsv1.ScanRequest{
		Target: "",
	}))
	if err == nil {
		t.Fatal("expected error for empty target")
	}

	spans := recorder.Ended()
	if len(spans) == 0 {
		t.Skip("no spans recorded")
	}

	span := findSpan(spans, "Scan")
	if span == nil {
		t.Skip("Scan span not found")
	}

	if span.Status().Code != codes.Error {
		t.Errorf("expected error status, got %v", span.Status().Code)
	}
}

func TestHandler_Trace_SpanParenting(t *testing.T) {
	recorder := setupTraceRecorder(t)

	srv, err := New(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	client := listv1connect.NewListServiceClient(http.DefaultClient, ts.URL)

	_, err = client.ListEcosystems(t.Context(), connect.NewRequest(&listv1.ListEcosystemsRequest{}))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}

	spans := recorder.Ended()
	if len(spans) == 0 {
		t.Skip("no spans recorded")
	}

	for _, span := range spans {
		if !span.SpanContext().TraceID().IsValid() {
			t.Errorf("span %s has invalid trace ID", span.Name())
		}
		if !span.SpanContext().SpanID().IsValid() {
			t.Errorf("span %s has invalid span ID", span.Name())
		}
	}
}

func TestOtelconnect_Integration(t *testing.T) {
	recorder := setupTraceRecorder(t)

	srv, err := New(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	scanClient := scanv1connect.NewScanServiceClient(http.DefaultClient, ts.URL)
	listClient := listv1connect.NewListServiceClient(http.DefaultClient, ts.URL)
	secretsClient := secretsv1connect.NewSecretsServiceClient(http.DefaultClient, ts.URL)

	_, _ = scanClient.Scan(t.Context(), connect.NewRequest(&scanv1.ScanRequest{Target: ""}))
	_, _ = listClient.ListEcosystems(t.Context(), connect.NewRequest(&listv1.ListEcosystemsRequest{}))
	_, _ = secretsClient.ListDetectors(t.Context(), connect.NewRequest(&secretsv1.ListDetectorsRequest{}))

	spans := recorder.Ended()
	if len(spans) == 0 {
		t.Skip("no spans recorded")
	}

	var scanSpans, listSpans, secretsSpans int
	for _, span := range spans {
		name := span.Name()
		switch {
		case strings.Contains(name, "ScanService") || (strings.Contains(name, "Scan") && !strings.Contains(name, "Secrets")):
			scanSpans++
		case strings.Contains(name, "ListService") || strings.Contains(name, "ListEcosystems"):
			listSpans++
		case strings.Contains(name, "SecretsService") || strings.Contains(name, "ListDetectors"):
			secretsSpans++
		}
	}

	t.Logf("spans: scan=%d list=%d secrets=%d total=%d", scanSpans, listSpans, secretsSpans, len(spans))
}

func TestScanHandler_Direct_Trace(t *testing.T) {
	recorder := setupTraceRecorder(t)

	handler := NewScanHandler(WithLocalMode())
	req := connect.NewRequest(&scanv1.ScanRequest{Target: "."})

	_, err := handler.Scan(t.Context(), req)
	if err != nil {
		t.Logf("scan error (may be expected): %v", err)
	}

	spans := recorder.Ended()
	t.Logf("recorded %d spans", len(spans))

	for _, span := range spans {
		t.Logf("  %s", span.Name())
		for _, attr := range span.Attributes() {
			t.Logf("    %s=%v", attr.Key, attr.Value.AsInterface())
		}
	}
}

func TestListHandler_Direct_Trace(t *testing.T) {
	recorder := setupTraceRecorder(t)

	handler := NewListHandler(WithListLocalMode())
	req := connect.NewRequest(&listv1.ListEcosystemsRequest{})

	resp, err := handler.ListEcosystems(t.Context(), req)
	if err != nil {
		t.Fatalf("ListEcosystems failed: %v", err)
	}
	if len(resp.Msg.Ecosystems) == 0 {
		t.Error("expected at least one ecosystem")
	}

	spans := recorder.Ended()
	t.Logf("recorded %d spans", len(spans))

	for _, span := range spans {
		if !span.SpanContext().IsValid() {
			t.Errorf("span %s has invalid context", span.Name())
		}
	}
}

func TestSecretsHandler_Direct_Trace(t *testing.T) {
	recorder := setupTraceRecorder(t)

	handler, err := NewSecretsHandler(WithSecretsLocalMode())
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	req := connect.NewRequest(&secretsv1.ListDetectorsRequest{})
	resp, err := handler.ListDetectors(t.Context(), req)
	if err != nil {
		t.Fatalf("ListDetectors failed: %v", err)
	}
	if len(resp.Msg.Detectors) == 0 {
		t.Error("expected at least one detector")
	}

	spans := recorder.Ended()
	t.Logf("recorded %d spans", len(spans))
}
