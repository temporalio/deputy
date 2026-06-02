package releases

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHashiCorpClientList(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"name":"terraform",
			"versions":{
				"1.15.5":{"version":"1.15.5"},
				"1.16.0-beta1":{"version":"1.16.0-beta1"},
				"0.1.0":{}
			}
		}`))
	}))
	t.Cleanup(server.Close)

	got, err := NewHashiCorpClient("terraform", WithEndpoint(server.URL), WithHTTPClient(server.Client())).List(t.Context())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	seen := map[string]Release{}
	for _, release := range got {
		seen[release.Version] = release
	}
	tests := map[string]Release{
		"1.15.5":       {Version: "1.15.5", Stable: true},
		"1.16.0-beta1": {Version: "1.16.0-beta1", Stable: false},
		"0.1.0":        {Version: "0.1.0", Stable: true},
	}
	for version, want := range tests {
		if got := seen[version]; got != want {
			t.Errorf("release %q = %+v, want %+v", version, got, want)
		}
	}
}

func TestHashiCorpClientRejectsEmptyProduct(t *testing.T) {
	_, err := NewHashiCorpClient("").List(t.Context())
	if err == nil {
		t.Fatal("List returned nil error, want empty product error")
	}
}

func TestHashiCorpEndpoint(t *testing.T) {
	if got, want := hashicorpEndpoint("terraform-plugin"), "https://releases.hashicorp.com/terraform-plugin/index.json"; got != want {
		t.Errorf("hashicorpEndpoint = %q, want %q", got, want)
	}
}
