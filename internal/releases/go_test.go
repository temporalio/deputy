package releases

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGoClientList(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[{"version":"go1.26.4","stable":true},{"version":"go1.27rc1","stable":false}]`))
	}))
	t.Cleanup(server.Close)

	got, err := NewGoClient(WithEndpoint(server.URL), WithHTTPClient(server.Client())).List(t.Context())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	want := []Release{
		{Version: "go1.26.4", Stable: true},
		{Version: "go1.27rc1", Stable: false},
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
