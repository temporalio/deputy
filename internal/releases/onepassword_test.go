package releases

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOnePasswordCLIClientList(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"available":"1","version":"2.34.0","relnotes":"https://example.com/notes"}`))
	}))
	t.Cleanup(server.Close)

	got, err := NewOnePasswordCLIClient(
		WithEndpoint(server.URL),
		WithHTTPClient(server.Client()),
	).List(t.Context())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	want := []Release{{Version: "2.34.0", Stable: true}}
	if len(got) != len(want) {
		t.Fatalf("got %d releases, want %d: %v", len(got), len(want), got)
	}
	if got[0] != want[0] {
		t.Errorf("release = %+v, want %+v", got[0], want[0])
	}
}
