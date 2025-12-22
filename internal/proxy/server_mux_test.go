package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func TestListenerMux_HealthzAndReadyz(t *testing.T) {
	cfg := ListenerConfig{Name: "test", Upstream: "http://example.com"}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	t.Run("readyz disabled", func(t *testing.T) {
		var ready atomic.Bool
		srv := httptest.NewServer(newListenerMux(cfg, Options{}, nil, nil, "test", "go", &ready, handler))
		t.Cleanup(srv.Close)

		resp, err := srv.Client().Get(srv.URL + "/healthz")
		if err != nil {
			t.Fatalf("GET /healthz: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("/healthz status=%d want=%d", resp.StatusCode, http.StatusOK)
		}

		resp, err = srv.Client().Get(srv.URL + "/readyz")
		if err != nil {
			t.Fatalf("GET /readyz: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("/readyz status=%d want=%d", resp.StatusCode, http.StatusNotFound)
		}
	})

	t.Run("readyz enabled", func(t *testing.T) {
		var ready atomic.Bool
		srv := httptest.NewServer(newListenerMux(cfg, Options{EnableReadyz: true}, nil, nil, "test", "go", &ready, handler))
		t.Cleanup(srv.Close)

		resp, err := srv.Client().Get(srv.URL + "/readyz")
		if err != nil {
			t.Fatalf("GET /readyz: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("/readyz status=%d want=%d", resp.StatusCode, http.StatusServiceUnavailable)
		}

		ready.Store(true)
		resp, err = srv.Client().Get(srv.URL + "/readyz")
		if err != nil {
			t.Fatalf("GET /readyz (ready): %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("/readyz (ready) status=%d want=%d", resp.StatusCode, http.StatusOK)
		}
	})
}

func TestListenerMux_ConcurrencyLimit429(t *testing.T) {
	cfg := ListenerConfig{Name: "test", Upstream: "http://example.com", MaxConcurrentRequests: 1}
	var ready atomic.Bool
	ready.Store(true)

	entered := make(chan struct{})
	release := make(chan struct{})
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-entered:
		default:
			close(entered)
		}
		<-release
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(newListenerMux(cfg, Options{}, nil, nil, "test", "go", &ready, handler))
	t.Cleanup(srv.Close)

	req1Done := make(chan struct{})
	go func() {
		defer close(req1Done)
		resp, err := srv.Client().Get(srv.URL + "/block")
		if err == nil {
			_ = resp.Body.Close()
		}
	}()
	<-entered

	resp, err := srv.Client().Get(srv.URL + "/blocked")
	if err != nil {
		t.Fatalf("second GET: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status=%d want=%d", resp.StatusCode, http.StatusTooManyRequests)
	}
	if got := resp.Header.Get("Retry-After"); got != "1" {
		t.Fatalf("Retry-After=%q want=%q", got, "1")
	}

	close(release)
	<-req1Done
}

func TestListenerMux_RequestIDAndForwardingHeaders(t *testing.T) {
	var (
		gotHost               string
		gotXFF, gotXFH, gotXP string
		gotReqID              string
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		gotXFF = r.Header.Get("X-Forwarded-For")
		gotXFH = r.Header.Get("X-Forwarded-Host")
		gotXP = r.Header.Get("X-Forwarded-Proto")
		gotReqID = r.Header.Get("X-Request-ID")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("upstream-ok"))
	}))
	t.Cleanup(upstream.Close)
	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream: %v", err)
	}

	cfg := ListenerConfig{Name: "test", Upstream: upstream.URL}
	var ready atomic.Bool
	ready.Store(true)
	proxyHandler := newUpstreamReverseProxy(u, "test", http.DefaultTransport)
	srv := httptest.NewServer(newListenerMux(cfg, Options{}, nil, nil, "test", "go", &ready, proxyHandler))
	t.Cleanup(srv.Close)

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/something", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-Forwarded-For", "1.2.3.4")

	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	_ = resp.Body.Close()

	respReqID := strings.TrimSpace(resp.Header.Get("X-Request-ID"))
	if respReqID == "" {
		t.Fatalf("missing X-Request-ID response header")
	}
	if gotReqID != respReqID {
		t.Fatalf("upstream X-Request-ID=%q want=%q", gotReqID, respReqID)
	}

	if gotHost != u.Host {
		t.Fatalf("upstream host=%q want=%q", gotHost, u.Host)
	}
	if gotXP != "http" {
		t.Fatalf("X-Forwarded-Proto=%q want=%q", gotXP, "http")
	}
	if gotXFH == "" {
		t.Fatalf("missing X-Forwarded-Host")
	}
	if !strings.Contains(gotXFF, "1.2.3.4") {
		t.Fatalf("X-Forwarded-For=%q missing client chain", gotXFF)
	}
	if !strings.Contains(gotXFF, ",") {
		t.Fatalf("X-Forwarded-For=%q expected appended client IP", gotXFF)
	}
}

func TestListenerMux_MaxRequestBodyBytes(t *testing.T) {
	cfg := ListenerConfig{Name: "test", Upstream: "http://example.com", MaxRequestBodyBytes: 10}
	var ready atomic.Bool
	ready.Store(true)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(newListenerMux(cfg, Options{}, nil, nil, "test", "go", &ready, handler))
	t.Cleanup(srv.Close)

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/upload", bytes.NewReader([]byte("01234567890123456789")))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d want=%d", resp.StatusCode, http.StatusRequestEntityTooLarge)
	}
}

