package releases

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNodeClientList(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[
			{"version":"v26.3.0","lts":false},
			{"version":"v24.12.0-rc.1","lts":false},
			{"version":"v22.17.1","lts":"Jod"}
		]`))
	}))
	t.Cleanup(server.Close)

	got, err := NewNodeClient(WithEndpoint(server.URL), WithHTTPClient(server.Client())).List(t.Context())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	want := []Release{
		{Version: "v26.3.0", Stable: true},
		{Version: "v24.12.0-rc.1", Stable: false},
		{Version: "v22.17.1", Stable: true, Channel: "lts"},
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
