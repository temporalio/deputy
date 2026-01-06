// Package otel provides OpenTelemetry instrumentation for Deputy.
//
// This package handles initialization and configuration of OpenTelemetry
// tracing and metrics. When enabled, it exports telemetry data to an
// OTLP-compatible collector.
//
// # Configuration
//
// Enable OpenTelemetry via environment variables:
//
//	export DEPUTY_OTEL_ENABLED=true
//	export OTEL_EXPORTER_OTLP_ENDPOINT=localhost:4317
//
// Or via configuration file (.deputy.yaml):
//
//	otel:
//	  enabled: true
//	  endpoint: localhost:4317
//	  insecure: true
//
// # Initialization
//
// Initialize OpenTelemetry early in program startup:
//
//	provider, err := otel.Init(ctx, cfg)
//	if err != nil {
//	    log.Warn("failed to initialize OpenTelemetry", "error", err)
//	}
//	defer provider.Shutdown(context.Background())
//
// # Creating Spans
//
// Use [StartSpan] to create traced operations:
//
//	ctx, span := otel.StartSpan(ctx, "deputy.scan",
//	    trace.WithAttributes(
//	        attribute.String("target", target),
//	    ))
//	defer span.End()
//
//	// ... do work ...
//
//	otel.SetSpanOK(span)  // or otel.SetSpanError(span, err)
//
// # HTTP Instrumentation
//
// Wrap HTTP handlers for automatic tracing:
//
//	handler := otel.WrapHandler(myHandler, "my-handler")
//
// # Checking Status
//
// Check if OpenTelemetry is enabled:
//
//	if otel.IsEnabled() {
//	    // Include trace context in logs
//	}
package otel
