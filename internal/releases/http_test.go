package releases

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDecodeJSONNon200(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"version":"1.0.0"}`))
	}))
	t.Cleanup(server.Close)

	var out map[string]any
	err := decodeJSON(t.Context(), server.Client(), server.URL, defaultJSONMaxBytes, &out)
	if err == nil {
		t.Fatal("decodeJSON returned nil error for non-200 response")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error %q does not mention the status code", err)
	}
}

func TestDecodeJSONMalformed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"version": `)) // truncated/invalid JSON
	}))
	t.Cleanup(server.Close)

	var out map[string]any
	if err := decodeJSON(t.Context(), server.Client(), server.URL, defaultJSONMaxBytes, &out); err == nil {
		t.Fatal("decodeJSON returned nil error for malformed JSON")
	}
}

// TestClientPropagatesHTTPError confirms a List method surfaces transport-layer
// errors rather than returning an empty list.
func TestClientPropagatesHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(server.Close)

	if _, err := NewGoClient(WithEndpoint(server.URL), WithHTTPClient(server.Client())).List(t.Context()); err == nil {
		t.Fatal("List returned nil error for a 404 endpoint")
	}
}

// TestWithMaxBytes confirms the response bound is enforced: a body longer than
// the bound is truncated, producing a decode error.
func TestWithMaxBytes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{"version":"go1.26.4","stable":true}]`))
	}))
	t.Cleanup(server.Close)

	_, err := NewGoClient(
		WithEndpoint(server.URL),
		WithHTTPClient(server.Client()),
		WithMaxBytes(4), // far smaller than the body; decode must fail on truncation
	).List(t.Context())
	if err == nil {
		t.Fatal("List returned nil error when response exceeded WithMaxBytes bound")
	}
}
