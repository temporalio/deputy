package server

import (
	"context"
	"net/http"
	"net/http/httptest"
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

// findSpan finds the span with the exact given name. otelconnect names RPC
// spans after the full procedure (e.g. "deputy.scan.v1.ScanService/Scan"), so
// exact matching prevents a test from accidentally latching onto a span from
// a different service that shares a method name.
func findSpan(spans []sdktrace.ReadOnlySpan, name string) sdktrace.ReadOnlySpan {
	for _, span := range spans {
		if span.Name() == name {
			return span
		}
	}
	return nil
}

// spanNames lists the recorded span names for failure messages.
func spanNames(spans []sdktrace.ReadOnlySpan) []string {
	names := make([]string, 0, len(spans))
	for _, span := range spans {
		names = append(names, span.Name())
	}
	return names
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
		t.Fatal("no spans recorded")
	}

	scanSpan := findSpan(spans, "deputy.scan.v1.ScanService/Scan")
	if scanSpan == nil {
		t.Fatalf("Scan span not found, got %v", spanNames(spans))
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
		t.Fatal("no spans recorded")
	}

	scanSpan := findSpan(spans, "deputy.scan.v1.ScanService/Scan")
	if scanSpan == nil {
		t.Fatalf("Scan span not found, got %v", spanNames(spans))
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
		t.Fatal("no spans recorded")
	}

	span := findSpan(spans, "deputy.list.v1.ListService/ListEcosystems")
	if span == nil {
		t.Fatalf("ListEcosystems span not found, got %v", spanNames(spans))
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
		t.Fatal("no spans recorded")
	}

	span := findSpan(spans, "deputy.secrets.v1.SecretsService/ListDetectors")
	if span == nil {
		t.Fatalf("ListDetectors span not found, got %v", spanNames(spans))
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
		t.Fatal("no spans recorded")
	}

	// Exact name: a bare "Scan" substring would also match the scan
	// service's span, which is not the RPC under test here.
	span := findSpan(spans, "deputy.secrets.v1.SecretsService/Scan")
	if span == nil {
		t.Fatalf("secrets Scan span not found, got %v", spanNames(spans))
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
		t.Fatal("no spans recorded")
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
		t.Fatal("no spans recorded")
	}

	// Each RPC must have produced its otelconnect server span.
	for _, want := range []string{
		"deputy.scan.v1.ScanService/Scan",
		"deputy.list.v1.ListService/ListEcosystems",
		"deputy.secrets.v1.SecretsService/ListDetectors",
	} {
		if findSpan(spans, want) == nil {
			t.Errorf("expected span %q, got %v", want, spanNames(spans))
		}
	}
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
