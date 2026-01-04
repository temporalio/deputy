package cmd

import (
	"strings"
	"testing"
)

func TestResolveOCIProxyTarget(t *testing.T) {
	tests := []struct {
		name       string
		host       string
		url        string
		wantHost   string
		wantScheme string
		wantErr    bool
	}{
		{name: "host_only", host: "127.0.0.1:8084", wantHost: "127.0.0.1:8084", wantScheme: "http"},
		{name: "url_https", url: "https://proxy.local:8443", wantHost: "proxy.local:8443", wantScheme: "https"},
		{name: "host_with_scheme", host: "http://127.0.0.1:8084", wantHost: "127.0.0.1:8084", wantScheme: "http"},
		{name: "both_set", host: "127.0.0.1:8084", url: "http://127.0.0.1:8084", wantErr: true},
		{name: "none_set", wantErr: true},
		{name: "url_no_host", url: "http://", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotHost, gotScheme, err := resolveOCIProxyTarget(tt.host, tt.url)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if gotHost != tt.wantHost {
				t.Fatalf("host=%q want=%q", gotHost, tt.wantHost)
			}
			if gotScheme != tt.wantScheme {
				t.Fatalf("scheme=%q want=%q", gotScheme, tt.wantScheme)
			}
		})
	}
}

func TestRenderOCIConfigSnippets(t *testing.T) {
	out := renderOCIConfigSnippets("127.0.0.1:8084", "http", "")
	for _, want := range []string{
		"registry-mirrors",
		"http://127.0.0.1:8084",
		"insecure-registries",
		"127.0.0.1:8084",
		"[[registry]]",
		"registry.mirror",
		"insecure = true",
		"<UPSTREAM_REGISTRY>",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output", want)
		}
	}

	secure := renderOCIConfigSnippets("proxy.local:8443", "https", "ghcr.io")
	if !strings.Contains(secure, "insecure = false") {
		t.Fatalf("expected insecure=false for https")
	}
	if !strings.Contains(secure, "prefix = \"ghcr.io\"") {
		t.Fatalf("expected upstream prefix")
	}
}
