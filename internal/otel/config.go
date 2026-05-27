// Package otel provides OpenTelemetry instrumentation for Deputy.
// It handles SDK initialization, shutdown, and provides helpers for
// traces, metrics, and log correlation.
package otel

import (
	"time"

	"github.com/temporalio/deputy/internal/errors"
)

// Config configures OpenTelemetry instrumentation.
type Config struct {
	// Enabled controls whether OTel instrumentation is active.
	// Default: false (zero overhead when disabled).
	Enabled bool `yaml:"enabled"`

	// ServiceName identifies the service in traces/metrics.
	// Default: "deputy"
	ServiceName string `yaml:"service_name"`

	// ServiceVersion is the service version for resource attributes.
	// If empty, uses the build version.
	ServiceVersion string `yaml:"service_version"`

	// Exporter configures the OTLP exporter.
	Exporter ExporterConfig `yaml:"exporter"`

	// Traces configures tracing behavior.
	Traces TracesConfig `yaml:"traces"`

	// Metrics configures metrics collection.
	Metrics MetricsConfig `yaml:"metrics"`

	// Logs configures log correlation.
	Logs LogsConfig `yaml:"logs"`
}

// ExporterConfig configures the OTLP exporter.
type ExporterConfig struct {
	// Protocol selects OTLP transport: "grpc" (default) or "http".
	Protocol string `yaml:"protocol"`

	// Endpoint is the collector address.
	// For gRPC: "localhost:4317" (default)
	// For HTTP: "localhost:4318"
	Endpoint string `yaml:"endpoint"`

	// Insecure disables TLS. Use for local development only.
	Insecure bool `yaml:"insecure"`

	// Headers for authentication (e.g., {"Authorization": "Bearer token"}).
	Headers map[string]string `yaml:"headers"`

	// Timeout for export operations. Default: 10s.
	Timeout time.Duration `yaml:"timeout"`
}

// TracesConfig configures tracing behavior.
type TracesConfig struct {
	// Enabled controls trace collection. Default: true when OTel enabled.
	Enabled bool `yaml:"enabled"`

	// SampleRate is the probability of sampling (0.0-1.0).
	// Default: 1.0 (sample everything).
	SampleRate float64 `yaml:"sample_rate"`

	// Propagators selects context propagation formats.
	// Default: ["tracecontext", "baggage"]
	Propagators []string `yaml:"propagators"`
}

// MetricsConfig configures metrics collection.
type MetricsConfig struct {
	// Enabled controls metrics collection. Default: true when OTel enabled.
	Enabled bool `yaml:"enabled"`

	// Interval is the metrics export interval.
	// Default: 5s (optimized for interactive demos).
	// For production, consider 60s to reduce overhead.
	// Can be overridden with OTEL_METRIC_EXPORT_INTERVAL env var.
	Interval time.Duration `yaml:"interval"`
}

// LogsConfig configures log correlation.
type LogsConfig struct {
	// Enabled controls log export to OTel. Default: true when OTel enabled.
	Enabled bool `yaml:"enabled"`

	// IncludeTraceContext adds trace_id/span_id to log records.
	// Default: true.
	IncludeTraceContext bool `yaml:"include_trace_context"`
}

// DefaultConfig returns a configuration with sensible defaults.
// Note: Enabled defaults to false for zero overhead.
func DefaultConfig() Config {
	return Config{
		Enabled:     false,
		ServiceName: "deputy",
		Exporter: ExporterConfig{
			Protocol: "grpc",
			Endpoint: "localhost:4317",
			Insecure: false,
			Timeout:  10 * time.Second,
		},
		Traces: TracesConfig{
			Enabled:     true,
			SampleRate:  1.0,
			Propagators: []string{"tracecontext", "baggage"},
		},
		Metrics: MetricsConfig{
			Enabled:  true,
			Interval: 5 * time.Second, // Fast export for interactive demos
		},
		Logs: LogsConfig{
			Enabled:             true,
			IncludeTraceContext: true,
		},
	}
}

// Validate checks the configuration for invalid values.
func (c *Config) Validate() error {
	if !c.Enabled {
		return nil // No validation needed when disabled
	}

	if c.ServiceName == "" {
		c.ServiceName = "deputy"
	}

	// Validate protocol
	switch c.Exporter.Protocol {
	case "", "grpc":
		c.Exporter.Protocol = "grpc"
	case "http":
		// valid
	default:
		return &errors.ValidationError{
			Field:   "exporter.protocol",
			Value:   c.Exporter.Protocol,
			Message: "must be 'grpc' or 'http'",
		}
	}

	// Set default endpoint based on protocol
	if c.Exporter.Endpoint == "" {
		if c.Exporter.Protocol == "grpc" {
			c.Exporter.Endpoint = "localhost:4317"
		} else {
			c.Exporter.Endpoint = "localhost:4318"
		}
	}

	// Validate sample rate
	if c.Traces.SampleRate < 0 || c.Traces.SampleRate > 1 {
		return &errors.ValidationError{
			Field:   "traces.sample_rate",
			Value:   c.Traces.SampleRate,
			Message: "must be between 0.0 and 1.0",
		}
	}

	// Set defaults for intervals
	if c.Exporter.Timeout == 0 {
		c.Exporter.Timeout = 10 * time.Second
	}
	if c.Metrics.Interval == 0 {
		c.Metrics.Interval = 5 * time.Second // Fast export for demos
	}

	return nil
}
