package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
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
