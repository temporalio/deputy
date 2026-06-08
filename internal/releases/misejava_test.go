package releases

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMiseJavaClientList(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[
			{"vendor":"openjdk","version":"21.0.2","image_type":"jdk"},
			{"vendor":"openjdk","version":"21.0.2","image_type":"jre"},
			{"vendor":"temurin","version":"21.0.11+10.0.LTS","image_type":"jdk"},
			{"vendor":"openjdk","version":"22.0.0-ea","image_type":"jdk"}
		]`))
	}))
	t.Cleanup(server.Close)

	got, err := NewMiseJavaClient("openjdk", WithEndpoint(server.URL), WithHTTPClient(server.Client())).List(t.Context())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	want := []Release{
		{Version: "21.0.2", Stable: true},
		{Version: "22.0.0-ea", Stable: false},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d releases, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("release %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestMiseJavaClientListRequiresVendor(t *testing.T) {
	_, err := NewMiseJavaClient("").List(t.Context())
	if err == nil {
		t.Fatal("List returned nil error, want vendor error")
	}
}
