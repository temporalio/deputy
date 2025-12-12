package proxy

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
)

// onUpstreamError maps upstream transport errors to stable HTTP responses.
//
// Reverse proxies can fail for many reasons; for local/dev and production usage we prefer:
// - cancellations/timeouts: 408 (request timeout) so callers can retry or treat as transient
// - other upstream failures: 502 (bad gateway)
func onUpstreamError(w http.ResponseWriter, r *http.Request, ecosystem string, err error) {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		http.Error(w, "request canceled", http.StatusRequestTimeout)
		return
	}
	slog.Warn("upstream request failed", "ecosystem", ecosystem, "path", r.URL.Path, "error", err)
	http.Error(w, "upstream fetch failed", http.StatusBadGateway)
}
