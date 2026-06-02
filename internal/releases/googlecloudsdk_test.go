package releases

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGoogleCloudSDKClientList(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"version":"571.0.0","revision":"20260529041429"}`))
	}))
	t.Cleanup(server.Close)

	got, err := NewGoogleCloudSDKClient(
		WithEndpoint(server.URL),
		WithHTTPClient(server.Client()),
	).List(t.Context())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	want := []Release{{Version: "571.0.0", Stable: true}}
	if len(got) != len(want) {
		t.Fatalf("got %d releases, want %d: %v", len(got), len(want), got)
	}
	if got[0] != want[0] {
		t.Errorf("release = %+v, want %+v", got[0], want[0])
	}
}
