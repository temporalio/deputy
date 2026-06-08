package releases

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestTemurinClientListFeature(t *testing.T) {
	var gotQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"versions":[
				{"semver":"21.0.11+10.0.LTS","optional":"LTS"},
				{"semver":"21.0.12-beta+1","optional":"LTS"},
				{"semver":"21.0.10+7.0.LTS","optional":"LTS"}
			]
		}`))
	}))
	t.Cleanup(server.Close)

	got, err := NewTemurinClient(WithEndpoint(server.URL), WithHTTPClient(server.Client())).ListFeature(t.Context(), 21)
	if err != nil {
		t.Fatalf("ListFeature: %v", err)
	}
	want := []Release{
		{Version: "21.0.11+10.0.LTS", Stable: true, Channel: "lts"},
		{Version: "21.0.12-beta+1", Stable: false, Channel: "lts"},
		{Version: "21.0.10+7.0.LTS", Stable: true, Channel: "lts"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d releases, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("release %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	if gotQuery == "" {
		t.Fatal("query is empty")
	}
	if gotFeature := firstQueryValue(t, gotQuery, "version"); gotFeature != "[21,22)" {
		t.Errorf("version query = %q, want [21,22)", gotFeature)
	}
}

func TestTemurinEndpoint(t *testing.T) {
	got, err := temurinEndpoint("https://example.invalid/releases?existing=1", 17)
	if err != nil {
		t.Fatalf("temurinEndpoint: %v", err)
	}
	want := "https://example.invalid/releases?existing=1&page_size=200&project=jdk&release_type=ga&sort_order=DESC&version=%5B17%2C18%29"
	if got != want {
		t.Errorf("temurinEndpoint = %q, want %q", got, want)
	}
}

func firstQueryValue(t *testing.T, rawQuery, key string) string {
	t.Helper()
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		t.Fatalf("parse query: %v", err)
	}
	return values.Get(key)
}
