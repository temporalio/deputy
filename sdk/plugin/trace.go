// Distributed tracing support for Deputy extractor plugins.
//
// This file provides OpenTelemetry trace context propagation, enabling plugins
// to participate in distributed traces with Deputy. When OTEL_EXPORTER_OTLP_ENDPOINT
// is set, traces flow seamlessly across process boundaries.
//
// # Trace Context Flow
//
//	Deputy Process                              Plugin Process
//	+-----------------------+                   +------------------------+
//	|                       |                   |                        |
//	|  ctx with span        |                   |  extractTraceContext() |
//	|       |               |                   |       |                |
//	|       v               |                   |       v                |
//	|  injectTraceContext() |                   |  ctx with linked span  |
//	|       |               |                   |       |                |
//	|       v               |   TraceContext    |       v                |
//	|  "00-abc-def-01" -----|---- field ------->|  startSpan()           |
//	|                       |   in request      |       |                |
//	|                       |                   |       v                |
//	|                       |                   |  child span created    |
//	+-----------------------+                   +------------------------+
//
// The TraceContext field in FileRequiredRequest and ExtractRequest carries
// the W3C traceparent header value (e.g., "00-traceid-spanid-01").
package plugin

import (
	"context"
	"os"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

const (
	// TracerName is the tracer name for plugin spans.
	// All spans created by plugin SDK use this tracer for identification.
	TracerName = "github.com/temporalio/deputy/plugin"
)

// extractTraceContext extracts W3C trace context from a traceparent header value
// and returns a context with the remote span context attached.
func extractTraceContext(ctx context.Context, traceContext string) context.Context {
	if traceContext == "" {
		return ctx
	}

	// Create a carrier with the traceparent header
	carrier := propagation.MapCarrier{
		"traceparent": traceContext,
	}

	// Extract the trace context using W3C TraceContext propagator
	propagator := propagation.TraceContext{}
	return propagator.Extract(ctx, carrier)
}

// startSpan starts a new span as a child of any trace context in the request.
// If OTel is not configured, returns a no-op span.
func startSpan(ctx context.Context, traceContext, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	// Extract parent trace context if provided
	ctx = extractTraceContext(ctx, traceContext)

	// Start span
	tracer := otel.Tracer(TracerName)
	ctx, span := tracer.Start(ctx, name, trace.WithAttributes(attrs...))
	return ctx, span
}

// setSpanError records an error on the span.
func setSpanError(span trace.Span, err error) {
	if err == nil {
		return
	}
	span.RecordError(err)
	span.SetStatus(codes.Error, err.Error())
}

// setSpanOK marks the span as successful.
func setSpanOK(span trace.Span) {
	span.SetStatus(codes.Ok, "")
}

// isOTelEnabled returns true if OpenTelemetry is configured.
func isOTelEnabled() bool {
	return os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") != ""
}
