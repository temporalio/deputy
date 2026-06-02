package graph

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGoProxyClientFetchInfo(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sigs.k8s.io/controller-runtime/tools/setup-envtest/@v/release-0.19.info" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"Version":"v0.0.0-20250308055145-5fe7bb3edc86","Time":"2025-03-08T05:51:45Z"}`))
	}))
	t.Cleanup(server.Close)

	client := NewGoProxyClient(server.URL)
	client.httpClient = server.Client()

	got, err := client.FetchInfo(t.Context(), "sigs.k8s.io/controller-runtime/tools/setup-envtest", "release-0.19")
	if err != nil {
		t.Fatalf("FetchInfo: %v", err)
	}
	if got.Version != "v0.0.0-20250308055145-5fe7bb3edc86" {
		t.Errorf("Version = %q, want v0.0.0-20250308055145-5fe7bb3edc86", got.Version)
	}
	if want := time.Date(2025, 3, 8, 5, 51, 45, 0, time.UTC); !got.Time.Equal(want) {
		t.Errorf("Time = %s, want %s", got.Time, want)
	}
}

func TestGoProxyClientFetchInfoNotFound(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(server.Close)

	client := NewGoProxyClient(server.URL)
	client.httpClient = server.Client()

	_, err := client.FetchInfo(t.Context(), "example.com/missing", "main")
	if !errors.Is(err, ErrModuleNotFound) {
		t.Fatalf("FetchInfo error = %v, want %v", err, ErrModuleNotFound)
	}
}
