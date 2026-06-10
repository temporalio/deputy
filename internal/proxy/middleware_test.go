package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestRequestIDFromContext(t *testing.T) {
	tests := []struct {
		name string
		ctx  context.Context
		want string
	}{
		{
			name: "nil context",
			ctx:  nil,
			want: "",
		},
		{
			name: "empty context",
			ctx:  context.Background(),
			want: "",
		},
		{
			name: "context with request ID",
			ctx:  context.WithValue(context.Background(), requestIDKey{}, "test-id-123"),
			want: "test-id-123",
		},
		{
			name: "context with wrong type",
			ctx:  context.WithValue(context.Background(), requestIDKey{}, 12345),
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := requestIDFromContext(tt.ctx)
			if got != tt.want {
				t.Errorf("requestIDFromContext() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNewRequestID(t *testing.T) {
	t.Parallel()

	id := newRequestID()
	if id == "" {
		t.Fatal("expected non-empty request ID")
	}
	if len(id) != 32 { // 16 bytes = 32 hex chars
		t.Errorf("expected 32 char request ID, got %d", len(id))
	}

	// Verify uniqueness
	seen := make(map[string]bool)
	for range 100 {
		id := newRequestID()
		if seen[id] {
			t.Errorf("duplicate request ID generated: %s", id)
		}
		seen[id] = true
	}
}

func TestWithRequestID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		headerName   string
		incomingID   string
		wantGenerate bool
	}{
		{
			name:         "no incoming ID, default header",
			headerName:   "",
			incomingID:   "",
			wantGenerate: true,
		},
		{
			name:         "incoming ID preserved",
			headerName:   "X-Request-ID",
			incomingID:   "existing-id-123",
			wantGenerate: false,
		},
		{
			name:         "custom header name",
			headerName:   "X-Correlation-ID",
			incomingID:   "correlation-123",
			wantGenerate: false,
		},
		{
			name:         "whitespace trimmed from incoming ID",
			headerName:   "X-Request-ID",
			incomingID:   "  trimmed-id  ",
			wantGenerate: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var contextID string
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				contextID = requestIDFromContext(r.Context())
				w.WriteHeader(http.StatusOK)
			})

			headerName := tt.headerName
			if headerName == "" {
				headerName = "X-Request-ID"
			}

			wrapped := withRequestID(tt.headerName)(handler)
			req := httptest.NewRequest("GET", "/test", nil)
			if tt.incomingID != "" {
				req.Header.Set(headerName, tt.incomingID)
			}
			rec := httptest.NewRecorder()

			wrapped.ServeHTTP(rec, req)

			respID := rec.Header().Get(headerName)
			if tt.wantGenerate {
				if respID == "" {
					t.Error("expected generated request ID in response")
				}
				if len(respID) != 32 {
					t.Errorf("expected 32 char generated ID, got %d", len(respID))
				}
			} else {
				expectedID := strings.TrimSpace(tt.incomingID)
				if respID != expectedID {
					t.Errorf("response ID = %q, want %q", respID, expectedID)
				}
			}

			if contextID == "" {
				t.Error("expected request ID in context")
			}
		})
	}
}

func TestWithMaxRequestBodyBytes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		maxBytes      int64
		contentLength int64
		bodySize      int
		wantStatus    int
	}{
		{
			name:          "within limit",
			maxBytes:      1024,
			contentLength: 100,
			bodySize:      100,
			wantStatus:    http.StatusOK,
		},
		{
			name:          "at limit",
			maxBytes:      100,
			contentLength: 100,
			bodySize:      100,
			wantStatus:    http.StatusOK,
		},
		{
			name:          "over limit by Content-Length",
			maxBytes:      100,
			contentLength: 200,
			bodySize:      200,
			wantStatus:    http.StatusRequestEntityTooLarge,
		},
		{
			name:          "disabled when maxBytes <= 0",
			maxBytes:      0,
			contentLength: 10000,
			bodySize:      10000,
			wantStatus:    http.StatusOK,
		},
		{
			name:          "negative maxBytes disables check",
			maxBytes:      -1,
			contentLength: 10000,
			bodySize:      10000,
			wantStatus:    http.StatusOK,
		},
		{
			name:          "unknown content length (-1)",
			maxBytes:      100,
			contentLength: -1,
			bodySize:      50,
			wantStatus:    http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Try to read the body
				if r.Body != nil {
					io.Copy(io.Discard, r.Body)
				}
				w.WriteHeader(http.StatusOK)
			})

			wrapped := withMaxRequestBodyBytes(tt.maxBytes)(handler)

			body := strings.NewReader(strings.Repeat("x", tt.bodySize))
			req := httptest.NewRequest("POST", "/test", body)
			if tt.contentLength >= 0 {
				req.ContentLength = tt.contentLength
			} else {
				req.ContentLength = -1
			}
			rec := httptest.NewRecorder()

			wrapped.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
		})
	}
}

func TestWithConcurrencyLimit(t *testing.T) {
	t.Parallel()

	t.Run("allows requests within limit", func(t *testing.T) {
		t.Parallel()

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		wrapped := withConcurrencyLimit(10)(handler)
		req := httptest.NewRequest("GET", "/test", nil)
		rec := httptest.NewRecorder()

		wrapped.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
		}
	})

	t.Run("disabled when max <= 0", func(t *testing.T) {
		t.Parallel()

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		wrapped := withConcurrencyLimit(0)(handler)
		req := httptest.NewRequest("GET", "/test", nil)
		rec := httptest.NewRecorder()

		wrapped.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
		}
	})

	t.Run("rejects when at limit", func(t *testing.T) {
		// Use synctest for deterministic concurrent testing
		synctest.Test(t, func(t *testing.T) {
			const maxConcurrent = 2
			var activeRequests atomic.Int32
			var rejectedCount atomic.Int32
			var successCount atomic.Int32

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				activeRequests.Add(1)
				// Simulate work - the request is "in flight"
				time.Sleep(50 * time.Millisecond)
				activeRequests.Add(-1)
				successCount.Add(1)
				w.WriteHeader(http.StatusOK)
			})

			wrapped := withConcurrencyLimit(maxConcurrent)(handler)

			// Launch more requests than the limit allows
			var wg sync.WaitGroup
			for range maxConcurrent + 3 {
				wg.Go(func() {
					req := httptest.NewRequest("GET", "/test", nil)
					rec := httptest.NewRecorder()
					wrapped.ServeHTTP(rec, req)

					if rec.Code == http.StatusTooManyRequests {
						rejectedCount.Add(1)
						// Verify Retry-After header
						if rec.Header().Get("Retry-After") != "1" {
							t.Errorf("expected Retry-After: 1, got %q", rec.Header().Get("Retry-After"))
						}
					}
				})
			}

			// Wait for all goroutines
			synctest.Wait()
			wg.Wait()

			// Some requests should have been rejected
			rejected := rejectedCount.Load()
			success := successCount.Load()

			if rejected == 0 {
				t.Error("expected some requests to be rejected")
			}
			if success+rejected != int32(maxConcurrent+3) {
				t.Errorf("total requests = %d, want %d", success+rejected, maxConcurrent+3)
			}
		})
	})
}

func TestStatusRecorder(t *testing.T) {
	t.Parallel()

	t.Run("records status code", func(t *testing.T) {
		t.Parallel()

		rec := httptest.NewRecorder()
		sr := &statusRecorder{ResponseWriter: rec}

		sr.WriteHeader(http.StatusNotFound)

		if sr.status != http.StatusNotFound {
			t.Errorf("status = %d, want %d", sr.status, http.StatusNotFound)
		}
	})

	t.Run("defaults to 200 on Write without WriteHeader", func(t *testing.T) {
		t.Parallel()

		rec := httptest.NewRecorder()
		sr := &statusRecorder{ResponseWriter: rec}

		sr.Write([]byte("hello"))

		if sr.status != http.StatusOK {
			t.Errorf("status = %d, want %d", sr.status, http.StatusOK)
		}
	})

	t.Run("tracks bytes written", func(t *testing.T) {
		t.Parallel()

		rec := httptest.NewRecorder()
		sr := &statusRecorder{ResponseWriter: rec}

		sr.Write([]byte("hello"))
		sr.Write([]byte(" world"))

		if sr.bytes != 11 {
			t.Errorf("bytes = %d, want 11", sr.bytes)
		}
	})
}

func TestStatusRecorderPool(t *testing.T) {
	t.Parallel()

	// Verify pool returns usable recorders
	for range 10 {
		rec := statusRecorderPool.Get().(*statusRecorder)
		if rec == nil {
			t.Fatal("pool returned nil")
		}

		// Use it
		rec.ResponseWriter = httptest.NewRecorder()
		rec.status = 0
		rec.bytes = 0
		rec.WriteHeader(http.StatusOK)
		rec.Write([]byte("test"))

		// Return to pool
		rec.ResponseWriter = nil
		statusRecorderPool.Put(rec)
	}
}

func TestWithRequestLogging(t *testing.T) {
	t.Parallel()

	t.Run("skips paths in skipPaths", func(t *testing.T) {
		t.Parallel()

		var handlerCalled bool
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
			w.WriteHeader(http.StatusOK)
		})

		skipPaths := map[string]bool{"/health": true}
		wrapped := withRequestLogging(nil, "test", "go", "upstream", skipPaths)(handler)

		req := httptest.NewRequest("GET", "/health", nil)
		rec := httptest.NewRecorder()
		wrapped.ServeHTTP(rec, req)

		if !handlerCalled {
			t.Error("handler should have been called")
		}
		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
		}
	})

	t.Run("logs non-skipped paths", func(t *testing.T) {
		t.Parallel()

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("response body"))
		})

		skipPaths := map[string]bool{"/health": true}
		wrapped := withRequestLogging(nil, "test", "go", "upstream", skipPaths)(handler)

		req := httptest.NewRequest("GET", "/api/packages", nil)
		rec := httptest.NewRecorder()
		wrapped.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
		}
	})
}
