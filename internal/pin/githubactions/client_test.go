package githubactions

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestGithubCheckRetry(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name       string
		status     int
		retryAfter string
		wantRetry  bool
	}{
		{"429 retries", 429, "", true},
		{"429 with Retry-After retries", 429, "5", true},
		{"403 without Retry-After does not retry", 403, "", false},
		{"403 with Retry-After retries", 403, "60", true},
		{"500 retries", 500, "", true},
		{"502 retries", 502, "", true},
		{"200 does not retry", 200, "", false},
		{"404 does not retry", 404, "", false},
		{"401 does not retry", 401, "", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := &http.Response{
				StatusCode: tc.status,
				Header:     http.Header{},
			}
			if tc.retryAfter != "" {
				resp.Header.Set("Retry-After", tc.retryAfter)
			}

			got, err := githubCheckRetry(ctx, resp, nil)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.wantRetry {
				t.Errorf("githubCheckRetry(status=%d, retry-after=%q) = %v, want %v",
					tc.status, tc.retryAfter, got, tc.wantRetry)
			}
		})
	}
}

func TestGithubCheckRetry_NilResp(t *testing.T) {
	got, err := githubCheckRetry(context.Background(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got {
		t.Error("nil response should not retry")
	}
}

func TestGithubCheckRetry_ConnectionError(t *testing.T) {
	got, err := githubCheckRetry(context.Background(), nil, &net.DNSError{})
	if err != nil {
		t.Fatal(err)
	}
	if !got {
		t.Error("connection errors should retry")
	}
}

func TestGithubCheckRetry_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	got, err := githubCheckRetry(ctx, nil, nil)
	if err == nil {
		t.Fatal("expected context error")
	}
	if got {
		t.Error("cancelled context should not retry")
	}
}

func TestGithubBackoff_RespectsRetryAfter(t *testing.T) {
	resp := &http.Response{
		StatusCode: 429,
		Header:     http.Header{},
	}
	resp.Header.Set("Retry-After", "10")

	wait := githubBackoff(1*time.Second, 60*time.Second, 0, resp)
	if wait != 10*time.Second {
		t.Errorf("expected 10s from Retry-After, got %v", wait)
	}
}

func TestGithubBackoff_ClampsRetryAfterToMax(t *testing.T) {
	resp := &http.Response{
		StatusCode: 429,
		Header:     http.Header{},
	}
	resp.Header.Set("Retry-After", "300")

	wait := githubBackoff(1*time.Second, 60*time.Second, 0, resp)
	if wait != 60*time.Second {
		t.Errorf("expected 60s (clamped max), got %v", wait)
	}
}

func TestGithubBackoff_FallsBackToDefault(t *testing.T) {
	resp := &http.Response{
		StatusCode: 500,
		Header:     http.Header{},
	}

	wait := githubBackoff(1*time.Second, 30*time.Second, 0, resp)
	if wait < 1*time.Second || wait > 30*time.Second {
		t.Errorf("expected default backoff between 1s-30s, got %v", wait)
	}
}

func TestParseRetryAfter(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  time.Duration
	}{
		{"valid", "60", 60 * time.Second},
		{"zero", "0", 0},
		{"empty", "", 0},
		{"non-numeric", "abc", 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := &http.Response{Header: http.Header{}}
			if tc.value != "" {
				resp.Header.Set("Retry-After", tc.value)
			}
			got := parseRetryAfter(resp)
			if got != tc.want {
				t.Errorf("parseRetryAfter(%q) = %v, want %v", tc.value, got, tc.want)
			}
		})
	}
}

func TestParseRetryAfter_NilResponse(t *testing.T) {
	if got := parseRetryAfter(nil); got != 0 {
		t.Errorf("nil response should return 0, got %v", got)
	}
}
