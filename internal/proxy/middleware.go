package proxy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	deputyotel "github.com/temporalio/deputy/internal/otel"
)

type requestIDKey struct{}

// statusRecorderPool reduces allocations for status recording middleware.
// Each request needs a statusRecorder, so pooling them helps under load.
var statusRecorderPool = sync.Pool{
	New: func() any {
		return &statusRecorder{}
	},
}

func requestIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

func newRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	return hex.EncodeToString(b[:])
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(p []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(p)
	r.bytes += int64(n)
	return n, err
}

func withRequestID(header string) func(http.Handler) http.Handler {
	hdr := strings.TrimSpace(header)
	if hdr == "" {
		hdr = "X-Request-ID"
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := strings.TrimSpace(r.Header.Get(hdr))
			if id == "" {
				id = newRequestID()
			}
			if id != "" {
				w.Header().Set(hdr, id)
				r.Header.Set(hdr, id)
				r = r.WithContext(context.WithValue(r.Context(), requestIDKey{}, id))
			}
			next.ServeHTTP(w, r)
		})
	}
}

func withMaxRequestBodyBytes(maxBytes int64) func(http.Handler) http.Handler {
	if maxBytes <= 0 {
		return func(next http.Handler) http.Handler { return next }
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ContentLength > maxBytes && r.ContentLength != -1 {
				http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
				return
			}
			if r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			}
			next.ServeHTTP(w, r)
		})
	}
}

func withConcurrencyLimit(max int) func(http.Handler) http.Handler {
	if max <= 0 {
		return func(next http.Handler) http.Handler { return next }
	}
	sem := make(chan struct{}, max)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
				next.ServeHTTP(w, r)
			default:
				w.Header().Set("Retry-After", "1")
				http.Error(w, "too many requests", http.StatusTooManyRequests)
			}
		})
	}
}

func withRequestLogging(logger *slog.Logger, listenerName, ecosystem, upstream string, skipPaths map[string]bool) func(http.Handler) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if skipPaths != nil && skipPaths[r.URL.Path] {
				next.ServeHTTP(w, r)
				return
			}

			start := time.Now()
			rec := statusRecorderPool.Get().(*statusRecorder)
			rec.ResponseWriter = w
			rec.status = 0
			rec.bytes = 0

			next.ServeHTTP(rec, r)
			dur := time.Since(start)

			status := rec.status
			if status == 0 {
				status = http.StatusOK
			}
			bytes := rec.bytes

			// Clear references before returning to pool to avoid retaining memory
			rec.ResponseWriter = nil
			statusRecorderPool.Put(rec)

			level := slog.LevelInfo
			switch {
			case status >= 500:
				level = slog.LevelError
			case status >= 400:
				level = slog.LevelWarn
			}

			// Record OTel metrics for proxy requests
			deputyotel.RecordProxyRequest(r.Context(), dur.Seconds(), ecosystem, status)

			logger.Log(r.Context(), level, "proxy request",
				"request_id", requestIDFromContext(r.Context()),
				"listener", listenerName,
				"ecosystem", ecosystem,
				"upstream", upstream,
				"method", r.Method,
				"path", r.URL.Path,
				"status", status,
				"bytes", bytes,
				"duration_ms", dur.Milliseconds(),
			)
		})
	}
}
