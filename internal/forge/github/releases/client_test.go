package releases

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	gh "github.com/google/go-github/v63/github"
	"github.com/temporalio/deputy/internal/releases"
)

func TestClientList(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/o/r/releases", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[
			{"tag_name":"v1.2.0","prerelease":false,"draft":false},
			{"tag_name":"v1.3.0-rc.1","prerelease":true,"draft":false},
			{"tag_name":"v1.1.0","prerelease":false,"draft":true}
		]`))
	})
	mux.HandleFunc("/repos/o/r/tags", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{"name":"v1.2.1"},{"name":"not-semver"}]`))
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	client := gh.NewClient(server.Client())
	baseURL, err := url.Parse(server.URL + "/")
	if err != nil {
		t.Fatalf("parse base URL: %v", err)
	}
	client.BaseURL = baseURL

	got, err := New(client).List(t.Context(), "o", "r")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	want := []releases.Release{
		{Version: "v1.2.0", Stable: true},
		{Version: "v1.3.0-rc.1", Stable: false},
		{Version: "v1.2.1", Stable: true},
		{Version: "not-semver", Stable: true},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d releases, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("release %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestClientListMatchingTags(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/o/r/git/matching-refs/tags/maven-3", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[
			{"ref":"refs/tags/maven-3.9.16"},
			{"ref":"refs/tags/maven-3.9.15"}
		]`))
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	client := gh.NewClient(server.Client())
	baseURL, err := url.Parse(server.URL + "/")
	if err != nil {
		t.Fatalf("parse base URL: %v", err)
	}
	client.BaseURL = baseURL

	got, err := New(client).ListMatchingTags(t.Context(), "o", "r", "maven-3")
	if err != nil {
		t.Fatalf("ListMatchingTags: %v", err)
	}
	want := []releases.Release{
		{Version: "maven-3.9.16", Stable: true},
		{Version: "maven-3.9.15", Stable: true},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d releases, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("release %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}
