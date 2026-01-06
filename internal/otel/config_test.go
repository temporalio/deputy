package otel

import (
	"testing"
	"time"

	"github.com/picatz/deputy/internal/errors"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Enabled {
		t.Error("expected Enabled to be false by default")
	}
	if cfg.ServiceName != "deputy" {
		t.Errorf("expected ServiceName 'deputy', got %q", cfg.ServiceName)
	}
	if cfg.Exporter.Protocol != "grpc" {
		t.Errorf("expected Protocol 'grpc', got %q", cfg.Exporter.Protocol)
	}
	if cfg.Exporter.Endpoint != "localhost:4317" {
		t.Errorf("expected Endpoint 'localhost:4317', got %q", cfg.Exporter.Endpoint)
	}
	if cfg.Traces.SampleRate != 1.0 {
		t.Errorf("expected SampleRate 1.0, got %f", cfg.Traces.SampleRate)
	}
	if cfg.Metrics.Interval != 5*time.Second {
		t.Errorf("expected Metrics.Interval 5s, got %v", cfg.Metrics.Interval)
	}
}

func TestConfig_Validate_Disabled(t *testing.T) {
	cfg := Config{Enabled: false}
	if err := cfg.Validate(); err != nil {
		t.Errorf("validation should pass for disabled config, got: %v", err)
	}
}

func TestConfig_Validate_InvalidProtocol(t *testing.T) {
	cfg := Config{
		Enabled: true,
		Exporter: ExporterConfig{
			Protocol: "invalid",
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for invalid protocol")
	}
	valErr, ok := err.(*errors.ValidationError)
	if !ok {
		t.Fatalf("expected *errors.ValidationError, got %T", err)
	}
	if valErr.Field != "exporter.protocol" {
		t.Errorf("expected field 'exporter.protocol', got %q", valErr.Field)
	}
}

func TestConfig_Validate_InvalidSampleRate(t *testing.T) {
	tests := []struct {
		name       string
		sampleRate float64
		wantErr    bool
	}{
		{"negative", -0.1, true},
		{"too high", 1.1, true},
		{"zero", 0.0, false},
		{"half", 0.5, false},
		{"one", 1.0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				Enabled: true,
				Traces: TracesConfig{
					SampleRate: tt.sampleRate,
				},
			}
			err := cfg.Validate()
			if tt.wantErr && err == nil {
				t.Error("expected error")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestConfig_Validate_SetsDefaults(t *testing.T) {
	cfg := Config{
		Enabled:     true,
		ServiceName: "",
		Exporter: ExporterConfig{
			Protocol: "",
			Endpoint: "",
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("validation failed: %v", err)
	}

	if cfg.ServiceName != "deputy" {
		t.Errorf("expected ServiceName default 'deputy', got %q", cfg.ServiceName)
	}
	if cfg.Exporter.Protocol != "grpc" {
		t.Errorf("expected Protocol default 'grpc', got %q", cfg.Exporter.Protocol)
	}
	if cfg.Exporter.Endpoint != "localhost:4317" {
		t.Errorf("expected Endpoint default 'localhost:4317', got %q", cfg.Exporter.Endpoint)
	}
	if cfg.Exporter.Timeout != 10*time.Second {
		t.Errorf("expected Timeout default 10s, got %v", cfg.Exporter.Timeout)
	}
	if cfg.Metrics.Interval != 5*time.Second {
		t.Errorf("expected Metrics.Interval default 5s, got %v", cfg.Metrics.Interval)
	}
}

func TestConfig_Validate_HTTPProtocol(t *testing.T) {
	cfg := Config{
		Enabled: true,
		Exporter: ExporterConfig{
			Protocol: "http",
			Endpoint: "",
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("validation failed: %v", err)
	}

	// HTTP should default to port 4318
	if cfg.Exporter.Endpoint != "localhost:4318" {
		t.Errorf("expected HTTP endpoint 'localhost:4318', got %q", cfg.Exporter.Endpoint)
	}
}

func TestValidationError_FromValidate(t *testing.T) {
	// Test that Validate returns properly structured ValidationError
	cfg := Config{
		Enabled: true,
		Exporter: ExporterConfig{
			Protocol: "invalid",
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error")
	}
	valErr, ok := err.(*errors.ValidationError)
	if !ok {
		t.Fatalf("expected *errors.ValidationError, got %T", err)
	}
	if valErr.Field != "exporter.protocol" {
		t.Errorf("expected Field 'exporter.protocol', got %q", valErr.Field)
	}
	if valErr.Value != "invalid" {
		t.Errorf("expected Value 'invalid', got %v", valErr.Value)
	}
	if valErr.Message != "must be 'grpc' or 'http'" {
		t.Errorf("unexpected Message: %q", valErr.Message)
	}
}
