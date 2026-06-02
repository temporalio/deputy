package mise

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
)

func TestMiseRegistryHTTPClientBackends(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path != "/registry/protoc.toml" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`
aliases = ["protobuf"]
backends = [
  "aqua:protocolbuffers/protobuf/protoc",
  "asdf:paxosglobal/asdf-protoc",
]
`))
	}))
	t.Cleanup(server.Close)

	client := &miseRegistryHTTPClient{
		baseURL:    server.URL + "/registry",
		httpClient: server.Client(),
		maxBytes:   defaultMiseRegistryMaxBytes,
	}

	got, err := client.Backends(t.Context(), "protoc")
	if err != nil {
		t.Fatalf("Backends: %v", err)
	}
	want := []string{"aqua:protocolbuffers/protobuf/protoc", "asdf:paxosglobal/asdf-protoc"}
	if len(got) != len(want) {
		t.Fatalf("Backends = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Backends = %v, want %v", got, want)
		}
	}

	if _, err := client.Backends(t.Context(), "protoc"); err != nil {
		t.Fatalf("cached Backends: %v", err)
	}
	if requests != 1 {
		t.Errorf("requests = %d, want 1", requests)
	}
}

func TestMiseRegistryHTTPClientBackendsAcceptMixedEntries(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/registry/npm.toml":
			_, _ = w.Write([]byte(`
backends = [
  { full = "aqua:npm/cli", platforms = ["linux", "macos"] },
  "npm:npm",
]
`))
		case "/registry/azure.toml":
			_, _ = w.Write([]byte(`
[[backends]]
full = "pipx:azure-cli"

[backends.options]
uvx_args = "--prerelease=allow"
`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	client := &miseRegistryHTTPClient{
		baseURL:    server.URL + "/registry",
		httpClient: server.Client(),
		maxBytes:   defaultMiseRegistryMaxBytes,
	}

	got, err := client.Backends(t.Context(), "npm")
	if err != nil {
		t.Fatalf("Backends: %v", err)
	}
	want := []string{"aqua:npm/cli", "npm:npm"}
	if !slices.Equal(got, want) {
		t.Errorf("Backends = %v, want %v", got, want)
	}

	got, err = client.Backends(t.Context(), "azure-cli")
	if err != nil {
		t.Fatalf("Backends azure-cli: %v", err)
	}
	want = []string{"pipx:azure-cli"}
	if !slices.Equal(got, want) {
		t.Errorf("Backends = %v, want %v", got, want)
	}
}

func TestMiseRegistryHTTPClientNotFound(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(server.Close)

	client := &miseRegistryHTTPClient{
		baseURL:    server.URL,
		httpClient: server.Client(),
		maxBytes:   defaultMiseRegistryMaxBytes,
	}

	if _, err := client.Backends(t.Context(), "missing"); !errors.Is(err, errMiseRegistryToolNotFound) {
		t.Fatalf("Backends error = %v, want %v", err, errMiseRegistryToolNotFound)
	}
}

func TestMiseRegistryToolFile(t *testing.T) {
	tests := []struct {
		name string
		want string
		ok   bool
	}{
		{name: "protoc", want: "protoc.toml", ok: true},
		{name: "golangci-lint", want: "golangci-lint.toml", ok: true},
		{name: "llama.cpp", want: "llama.cpp.toml", ok: true},
		{name: "aws", want: "aws-cli.toml", ok: true},
		{name: "op", want: "1password.toml", ok: true},
		{name: "azure-cli", want: "azure.toml", ok: true},
		{name: "../protoc"},
		{name: "github:cli/cli"},
		{name: "bad/name"},
		{name: "bad name"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := miseRegistryToolFile(tt.name)
			if ok != tt.ok {
				t.Fatalf("ok = %v, want %v", ok, tt.ok)
			}
			if got != tt.want {
				t.Errorf("file = %q, want %q", got, tt.want)
			}
		})
	}
}
