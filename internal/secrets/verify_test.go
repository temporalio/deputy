package secrets

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestGitHubVerifier_DoesNotLeakResponseBody(t *testing.T) {
	t.Parallel()

	body := "Token ghp_example123 is expired"
	client := &http.Client{
		Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Body:       io.NopCloser(strings.NewReader(body)),
				Header:     make(http.Header),
			}, nil
		}),
	}

	verifier := newGitHubVerifier(client)
	result := verifier.Verify(context.Background(), "ghp_example123", TypeGitHubToken)

	if result.Status != StatusError {
		t.Fatalf("expected StatusError, got %s", result.Status)
	}
	if strings.Contains(result.Error, "ghp_example123") || strings.Contains(result.Error, "Token") {
		t.Fatalf("error should not include response body; got %q", result.Error)
	}
}
