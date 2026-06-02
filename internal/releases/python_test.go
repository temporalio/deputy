package releases

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPythonClientList(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[
			{"name":"Python 3.14.2","is_published":true,"pre_release":false},
			{"name":"Python 3.15.0a1","is_published":true,"pre_release":true},
			{"name":"Python 3.13.9","is_published":false,"pre_release":false}
		]`))
	}))
	t.Cleanup(server.Close)

	got, err := NewPythonClient(WithEndpoint(server.URL), WithHTTPClient(server.Client())).List(t.Context())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	want := []Release{
		{Version: "3.14.2", Stable: true},
		{Version: "3.15.0a1", Stable: false},
		{Version: "3.13.9", Stable: false},
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
