package proxy

import (
	"strings"
	"testing"
	"time"
)

func TestResolveTimeout(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		configured time.Duration
		defaultVal time.Duration
		want       time.Duration
	}{
		{
			name:       "zero uses default",
			configured: 0,
			defaultVal: 5 * time.Second,
			want:       5 * time.Second,
		},
		{
			name:       "negative uses default",
			configured: -1 * time.Second,
			defaultVal: 5 * time.Second,
			want:       5 * time.Second,
		},
		{
			name:       "positive uses configured",
			configured: 10 * time.Second,
			defaultVal: 5 * time.Second,
			want:       10 * time.Second,
		},
		{
			name:       "very small positive uses configured",
			configured: 1 * time.Nanosecond,
			defaultVal: 5 * time.Second,
			want:       1 * time.Nanosecond,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveTimeout(tt.configured, tt.defaultVal)
			if got != tt.want {
				t.Errorf("resolveTimeout(%v, %v) = %v, want %v", tt.configured, tt.defaultVal, got, tt.want)
			}
		})
	}
}

func TestResolveListenerTimeouts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cfg  ListenerConfig
		want listenerTimeouts
	}{
		{
			name: "all defaults",
			cfg:  ListenerConfig{},
			want: listenerTimeouts{
				ReadHeader: proxyReadHeaderTimeout,
				Write:      proxyWriteTimeout,
				Idle:       proxyIdleTimeout,
			},
		},
		{
			name: "all configured",
			cfg: ListenerConfig{
				ReadHeaderTimeout: 1 * time.Second,
				WriteTimeout:      2 * time.Second,
				IdleTimeout:       3 * time.Second,
			},
			want: listenerTimeouts{
				ReadHeader: 1 * time.Second,
				Write:      2 * time.Second,
				Idle:       3 * time.Second,
			},
		},
		{
			name: "partial configuration",
			cfg: ListenerConfig{
				ReadHeaderTimeout: 1 * time.Second,
				// WriteTimeout: default
				IdleTimeout: 3 * time.Second,
			},
			want: listenerTimeouts{
				ReadHeader: 1 * time.Second,
				Write:      proxyWriteTimeout,
				Idle:       3 * time.Second,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveListenerTimeouts(tt.cfg)
			if got != tt.want {
				t.Errorf("resolveListenerTimeouts() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestCreateEcosystemHandler_UnsupportedEcosystem(t *testing.T) {
	t.Parallel()

	_, err := createEcosystemHandler("test-listener", "unsupported", "http://upstream", nil)
	if err == nil {
		t.Fatal("expected error for unsupported ecosystem")
	}
	// Check that error contains listener name and indicates unsupported ecosystem
	errStr := err.Error()
	if !strings.Contains(errStr, "test-listener") || !strings.Contains(errStr, "unsupported") {
		t.Errorf("error = %q, want error containing listener name and ecosystem", errStr)
	}
}
