package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestUpstreamReverseProxy_HostAndHopByHopHeaders(t *testing.T) {
	var gotHost string
	gotHeaders := http.Header{}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		gotHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	proxy := newUpstreamReverseProxy(u, "test", http.DefaultTransport)
	proxySrv := httptest.NewServer(proxy)
	t.Cleanup(proxySrv.Close)

	req, err := http.NewRequest(http.MethodGet, proxySrv.URL+"/something", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Connection", "X-Hop")
	req.Header.Set("X-Hop", "should-not-forward")

	resp, err := proxySrv.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	_ = resp.Body.Close()

	if gotHost != u.Host {
		t.Fatalf("upstream host=%q want=%q", gotHost, u.Host)
	}

	if gotHeaders.Get("Connection") != "" {
		t.Fatalf("expected hop-by-hop header Connection stripped, got %q", gotHeaders.Get("Connection"))
	}
	if gotHeaders.Get("X-Hop") != "" {
		t.Fatalf("expected hop-by-hop header listed in Connection stripped, got %q", gotHeaders.Get("X-Hop"))
	}
}

// TestUpstreamReverseProxy_PreservesXForwardedForAndPath pins the bespoke
// Rewrite behavior: an inbound X-Forwarded-For chain is preserved (and
// extended by SetXForwarded) and the request path is forwarded to the upstream.
func TestUpstreamReverseProxy_PreservesXForwardedForAndPath(t *testing.T) {
	var gotXFF, gotPath string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotXFF = r.Header.Get("X-Forwarded-For")
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	proxy := newUpstreamReverseProxy(u, "test", http.DefaultTransport)
	proxySrv := httptest.NewServer(proxy)
	t.Cleanup(proxySrv.Close)

	req, err := http.NewRequest(http.MethodGet, proxySrv.URL+"/pkg/foo", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-Forwarded-For", "203.0.113.7")

	resp, err := proxySrv.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	_ = resp.Body.Close()

	if !strings.Contains(gotXFF, "203.0.113.7") {
		t.Fatalf("expected inbound X-Forwarded-For preserved, upstream saw %q", gotXFF)
	}
	if gotPath != "/pkg/foo" {
		t.Fatalf("expected path forwarded as /pkg/foo, upstream saw %q", gotPath)
	}
}
