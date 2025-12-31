package otel

import (
	"context"
	"os"
	"sync"
	"testing"
)

func TestInit_DisabledByDefault(t *testing.T) {
	// Reset global state
	resetGlobalProvider()

	cfg := DefaultConfig()
	provider, err := Init(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer provider.Shutdown(context.Background())

	if provider.Enabled() {
		t.Error("expected provider to be disabled by default")
	}
}

func TestInit_EnvOverride(t *testing.T) {
	// Reset global state
	resetGlobalProvider()

	// Set environment variable
	os.Setenv("DEPUTY_OTEL_ENABLED", "true")
	defer os.Unsetenv("DEPUTY_OTEL_ENABLED")

	cfg := DefaultConfig()
	cfg.Enabled = false // Config says disabled
	cfg.Exporter.Insecure = true

	// Environment should override
	provider, err := Init(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer provider.Shutdown(context.Background())

	// Note: The provider will be "enabled" from config perspective,
	// but actual provider creation may fail without a collector.
	// We're testing that the env var override works.
	if !provider.enabled {
		t.Error("expected environment override to enable OTel")
	}
}

func TestInit_EnvOverride_False(t *testing.T) {
	// Reset global state
	resetGlobalProvider()

	// Set environment variable to false
	os.Setenv("DEPUTY_OTEL_ENABLED", "false")
	defer os.Unsetenv("DEPUTY_OTEL_ENABLED")

	cfg := DefaultConfig()
	cfg.Enabled = true // Config says enabled

	provider, err := Init(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer provider.Shutdown(context.Background())

	if provider.Enabled() {
		t.Error("expected environment override to disable OTel")
	}
}

func TestInit_MultipleCallsReturnSameProvider(t *testing.T) {
	// Reset global state
	resetGlobalProvider()

	cfg := DefaultConfig()

	p1, err := Init(context.Background(), cfg)
	if err != nil {
		t.Fatalf("first Init failed: %v", err)
	}

	p2, err := Init(context.Background(), cfg)
	if err != nil {
		t.Fatalf("second Init failed: %v", err)
	}

	if p1 != p2 {
		t.Error("expected same provider instance from multiple Init calls")
	}

	p1.Shutdown(context.Background())
}

func TestProvider_Shutdown_NilSafe(t *testing.T) {
	var p *Provider
	// Should not panic
	if err := p.Shutdown(context.Background()); err != nil {
		t.Errorf("nil provider shutdown should return nil, got: %v", err)
	}
}

func TestProvider_Shutdown_DisabledSafe(t *testing.T) {
	p := &Provider{enabled: false}
	if err := p.Shutdown(context.Background()); err != nil {
		t.Errorf("disabled provider shutdown should return nil, got: %v", err)
	}
}

func TestProvider_Enabled(t *testing.T) {
	tests := []struct {
		name     string
		provider *Provider
		want     bool
	}{
		{"nil provider", nil, false},
		{"disabled", &Provider{enabled: false}, false},
		{"enabled", &Provider{enabled: true}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.provider.Enabled(); got != tt.want {
				t.Errorf("Enabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsEnabled(t *testing.T) {
	// Reset and test when no provider
	resetGlobalProvider()
	if IsEnabled() {
		t.Error("expected IsEnabled() false when no provider")
	}

	// Test with disabled provider
	cfg := DefaultConfig()
	provider, _ := Init(context.Background(), cfg)
	defer func() {
		provider.Shutdown(context.Background())
		resetGlobalProvider()
	}()

	if IsEnabled() {
		t.Error("expected IsEnabled() false when provider is disabled")
	}
}

func TestTracer_ReturnsNonNil(t *testing.T) {
	tracer := Tracer("test")
	if tracer == nil {
		t.Error("Tracer should return non-nil even when OTel disabled")
	}
}

func TestMeter_ReturnsNonNil(t *testing.T) {
	meter := Meter("test")
	if meter == nil {
		t.Error("Meter should return non-nil even when OTel disabled")
	}
}

func TestBuildPropagator_Defaults(t *testing.T) {
	prop := buildPropagator(nil)
	if prop == nil {
		t.Error("buildPropagator should return non-nil propagator")
	}
}

func TestBuildPropagator_Empty(t *testing.T) {
	prop := buildPropagator([]string{})
	if prop == nil {
		t.Error("buildPropagator should return non-nil propagator for empty slice")
	}
}

func TestBuildPropagator_CustomFormats(t *testing.T) {
	tests := []struct {
		name    string
		formats []string
	}{
		{"tracecontext only", []string{"tracecontext"}},
		{"baggage only", []string{"baggage"}},
		{"both", []string{"tracecontext", "baggage"}},
		{"case insensitive", []string{"TRACECONTEXT", "BAGGAGE"}},
		{"unknown format ignored", []string{"unknown"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prop := buildPropagator(tt.formats)
			if prop == nil {
				t.Error("buildPropagator should return non-nil propagator")
			}
		})
	}
}

// resetGlobalProvider clears the global provider for test isolation.
// This is necessary because Init() is designed to be called once.
func resetGlobalProvider() {
	providerMu.Lock()
	defer providerMu.Unlock()
	if globalProvider != nil {
		globalProvider.Shutdown(context.Background())
	}
	globalProvider = nil
	// Reset sync.Once by creating a new one is not possible,
	// so we rely on the nil check in Init().
	metricsOnce = sync.Once{}
}
