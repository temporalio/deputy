package proxy

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOnUpstreamError_StatusMapping(t *testing.T) {
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	req := httptest.NewRequest(http.MethodGet, "http://example.local/some/path", nil)

	tests := []struct {
		name   string
		err    error
		status int
	}{
		{name: "Canceled", err: context.Canceled, status: http.StatusRequestTimeout},
		{name: "DeadlineExceeded", err: context.DeadlineExceeded, status: http.StatusRequestTimeout},
		{name: "Other", err: io.EOF, status: http.StatusBadGateway},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			onUpstreamError(rr, req, "test", tt.err)
			if rr.Code != tt.status {
				t.Fatalf("status=%d want=%d body=%q", rr.Code, tt.status, rr.Body.String())
			}
			if rr.Body.Len() == 0 {
				t.Fatalf("expected non-empty body")
			}
		})
	}
}
