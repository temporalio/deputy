package httputil

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewTransport(t *testing.T) {
	t.Parallel()
	transport := NewTransport()

	if transport == nil {
		t.Fatal("expected non-nil transport")
	}
	if transport.IdleConnTimeout != DefaultIdleConnTimeout {
		t.Errorf("IdleConnTimeout = %v, want %v", transport.IdleConnTimeout, DefaultIdleConnTimeout)
	}
	if transport.TLSHandshakeTimeout != DefaultTLSHandshakeTimeout {
		t.Errorf("TLSHandshakeTimeout = %v, want %v", transport.TLSHandshakeTimeout, DefaultTLSHandshakeTimeout)
	}
	if transport.ResponseHeaderTimeout != DefaultResponseHeaderTimeout {
		t.Errorf("ResponseHeaderTimeout = %v, want %v", transport.ResponseHeaderTimeout, DefaultResponseHeaderTimeout)
	}
	if transport.MaxIdleConns != DefaultMaxIdleConns {
		t.Errorf("MaxIdleConns = %d, want %d", transport.MaxIdleConns, DefaultMaxIdleConns)
	}
	if !transport.ForceAttemptHTTP2 {
		t.Error("expected ForceAttemptHTTP2 to be true")
	}
}

func TestNewClient(t *testing.T) {
	t.Parallel()
	timeout := 5 * time.Second
	client := NewClient(timeout)

	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if client.Timeout != timeout {
		t.Errorf("Timeout = %v, want %v", client.Timeout, timeout)
	}
	if client.Transport == nil {
		t.Error("expected non-nil transport")
	}
}

func TestNewRetryableClient(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		timeout time.Duration
	}{
		{"short timeout", 5 * time.Second},
		{"medium timeout", 30 * time.Second},
		{"long timeout", 2 * time.Minute},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			client := NewRetryableClient(tt.timeout)

			if client == nil {
				t.Fatal("expected non-nil client")
			}
			if client.Timeout != tt.timeout {
				t.Errorf("Timeout = %v, want %v", client.Timeout, tt.timeout)
			}
			if client.Transport == nil {
				t.Error("expected non-nil transport")
			}
		})
	}
}

func TestNewRetryableClientWithConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		timeout      time.Duration
		retryMax     int
		retryWaitMin time.Duration
		retryWaitMax time.Duration
	}{
		{
			name:         "default-like config",
			timeout:      30 * time.Second,
			retryMax:     3,
			retryWaitMin: 500 * time.Millisecond,
			retryWaitMax: 5 * time.Second,
		},
		{
			name:         "aggressive retry",
			timeout:      10 * time.Second,
			retryMax:     5,
			retryWaitMin: 100 * time.Millisecond,
			retryWaitMax: 1 * time.Second,
		},
		{
			name:         "no retries",
			timeout:      5 * time.Second,
			retryMax:     0,
			retryWaitMin: 0,
			retryWaitMax: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			client := NewRetryableClientWithConfig(tt.timeout, tt.retryMax, tt.retryWaitMin, tt.retryWaitMax)

			if client == nil {
				t.Fatal("expected non-nil client")
			}
			if client.Timeout != tt.timeout {
				t.Errorf("Timeout = %v, want %v", client.Timeout, tt.timeout)
			}
			if client.Transport == nil {
				t.Error("expected non-nil transport")
			}
		})
	}
}

func TestRetryableClient_RetriesOnServerError(t *testing.T) {
	t.Parallel()

	var attempts atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt := attempts.Add(1)
		if attempt < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	}))
	defer server.Close()

	client := NewRetryableClientWithConfig(10*time.Second, 3, 10*time.Millisecond, 50*time.Millisecond)

	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if got := attempts.Load(); got != 3 {
		t.Errorf("attempts = %d, want 3", got)
	}
}

func TestRetryableClient_RespectsMaxRetries(t *testing.T) {
	t.Parallel()

	var attempts atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	// Configure for 2 retries (3 total attempts: initial + 2 retries)
	client := NewRetryableClientWithConfig(10*time.Second, 2, 10*time.Millisecond, 50*time.Millisecond)

	_, err := client.Get(server.URL)
	// retryablehttp returns an error when all retries are exhausted
	if err == nil {
		t.Fatal("expected error after exhausting retries")
	}
	// Initial request + 2 retries = 3 attempts
	if got := attempts.Load(); got != 3 {
		t.Errorf("attempts = %d, want 3", got)
	}
}

func TestRetryableClient_NoRetryOn4xx(t *testing.T) {
	t.Parallel()

	var attempts atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewRetryableClientWithConfig(10*time.Second, 3, 10*time.Millisecond, 50*time.Millisecond)

	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
	// Should not retry on 4xx errors
	if got := attempts.Load(); got != 1 {
		t.Errorf("attempts = %d, want 1 (no retries on 4xx)", got)
	}
}

func TestDefaultClientConfig(t *testing.T) {
	t.Parallel()

	cfg := DefaultClientConfig()

	if cfg.Timeout != 30*time.Second {
		t.Errorf("Timeout = %v, want 30s", cfg.Timeout)
	}
	if cfg.DialTimeout != DefaultDialTimeout {
		t.Errorf("DialTimeout = %v, want %v", cfg.DialTimeout, DefaultDialTimeout)
	}
	if cfg.TLSHandshakeTimeout != DefaultTLSHandshakeTimeout {
		t.Errorf("TLSHandshakeTimeout = %v, want %v", cfg.TLSHandshakeTimeout, DefaultTLSHandshakeTimeout)
	}
	if cfg.MaxIdleConns != DefaultMaxIdleConns {
		t.Errorf("MaxIdleConns = %d, want %d", cfg.MaxIdleConns, DefaultMaxIdleConns)
	}
	if cfg.MaxIdleConnsPerHost != DefaultMaxIdleConnsPerHost {
		t.Errorf("MaxIdleConnsPerHost = %d, want %d", cfg.MaxIdleConnsPerHost, DefaultMaxIdleConnsPerHost)
	}
	if !cfg.RetryEnabled {
		t.Error("expected RetryEnabled to be true")
	}
	if cfg.RetryMax != DefaultRetryMax {
		t.Errorf("RetryMax = %d, want %d", cfg.RetryMax, DefaultRetryMax)
	}
}

func TestNewTransportFromConfig(t *testing.T) {
	t.Parallel()

	cfg := ClientConfig{
		DialTimeout:           15 * time.Second,
		KeepAlive:             45 * time.Second,
		TLSHandshakeTimeout:   12 * time.Second,
		ResponseHeaderTimeout: 25 * time.Second,
		IdleConnTimeout:       60 * time.Second,
		MaxIdleConns:          50,
		MaxIdleConnsPerHost:   25,
	}

	transport := NewTransportFromConfig(cfg)

	if transport.TLSHandshakeTimeout != cfg.TLSHandshakeTimeout {
		t.Errorf("TLSHandshakeTimeout = %v, want %v", transport.TLSHandshakeTimeout, cfg.TLSHandshakeTimeout)
	}
	if transport.ResponseHeaderTimeout != cfg.ResponseHeaderTimeout {
		t.Errorf("ResponseHeaderTimeout = %v, want %v", transport.ResponseHeaderTimeout, cfg.ResponseHeaderTimeout)
	}
	if transport.IdleConnTimeout != cfg.IdleConnTimeout {
		t.Errorf("IdleConnTimeout = %v, want %v", transport.IdleConnTimeout, cfg.IdleConnTimeout)
	}
	if transport.MaxIdleConns != cfg.MaxIdleConns {
		t.Errorf("MaxIdleConns = %d, want %d", transport.MaxIdleConns, cfg.MaxIdleConns)
	}
	if transport.MaxIdleConnsPerHost != cfg.MaxIdleConnsPerHost {
		t.Errorf("MaxIdleConnsPerHost = %d, want %d", transport.MaxIdleConnsPerHost, cfg.MaxIdleConnsPerHost)
	}
	if !transport.ForceAttemptHTTP2 {
		t.Error("expected ForceAttemptHTTP2 to be true")
	}
}

func TestNewClientFromConfig_NoRetry(t *testing.T) {
	t.Parallel()

	cfg := ClientConfig{
		Timeout:      30 * time.Second,
		DialTimeout:  10 * time.Second,
		RetryEnabled: false,
		RetryMax:     3,
	}

	client := NewClientFromConfig(cfg)

	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if client.Timeout != cfg.Timeout {
		t.Errorf("Timeout = %v, want %v", client.Timeout, cfg.Timeout)
	}
}

func TestNewClientFromConfig_WithRetry(t *testing.T) {
	t.Parallel()

	cfg := ClientConfig{
		Timeout:      30 * time.Second,
		DialTimeout:  10 * time.Second,
		RetryEnabled: true,
		RetryMax:     3,
		RetryWaitMin: 100 * time.Millisecond,
		RetryWaitMax: 1 * time.Second,
	}

	client := NewClientFromConfig(cfg)

	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if client.Timeout != cfg.Timeout {
		t.Errorf("Timeout = %v, want %v", client.Timeout, cfg.Timeout)
	}
}

func TestNewClientFromConfig_RetryBehavior(t *testing.T) {
	t.Parallel()

	var attempts atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt := attempts.Add(1)
		if attempt < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := ClientConfig{
		Timeout:      10 * time.Second,
		DialTimeout:  5 * time.Second,
		RetryEnabled: true,
		RetryMax:     3,
		RetryWaitMin: 10 * time.Millisecond,
		RetryWaitMax: 50 * time.Millisecond,
	}

	client := NewClientFromConfig(cfg)
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if got := attempts.Load(); got != 3 {
		t.Errorf("attempts = %d, want 3", got)
	}
}

func TestNewClientFromConfig_NoRetryWhenDisabled(t *testing.T) {
	t.Parallel()

	var attempts atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	cfg := ClientConfig{
		Timeout:      10 * time.Second,
		DialTimeout:  5 * time.Second,
		RetryEnabled: false,
		RetryMax:     3,
	}

	client := NewClientFromConfig(cfg)
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	// Should not retry when disabled
	if got := attempts.Load(); got != 1 {
		t.Errorf("attempts = %d, want 1 (retries disabled)", got)
	}
}

func TestNewClientFromConfig_ZeroRetryMax(t *testing.T) {
	t.Parallel()

	var attempts atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	cfg := ClientConfig{
		Timeout:      10 * time.Second,
		DialTimeout:  5 * time.Second,
		RetryEnabled: true,
		RetryMax:     0, // Zero means no retries
	}

	client := NewClientFromConfig(cfg)
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	// Should not retry when RetryMax is 0
	if got := attempts.Load(); got != 1 {
		t.Errorf("attempts = %d, want 1 (RetryMax is 0)", got)
	}
}
