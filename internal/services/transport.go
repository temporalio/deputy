// Package services provides the unified service layer for Deputy.
//
// This package implements the proto-first architecture where services
// directly implement ConnectRPC generated handler interfaces. The same
// implementations work both in-process (via inProcessTransport) and
// over the network (via standard HTTP/2).
//
// # Architecture
//
// Services implement the generated *ServiceHandler interfaces:
//
//	type ScanService struct { ... }
//	var _ scanv1connect.ScanServiceHandler = (*ScanService)(nil)
//
// CLI and other consumers use the generated *ServiceClient interfaces:
//
//	var client scanv1connect.ScanServiceClient
//
// The inProcessTransport bridges these, allowing handlers to be used
// as clients without network overhead:
//
//	transport := NewInProcessTransport(handlers)
//	client := scanv1connect.NewScanServiceClient(transport, "")
//
// # Benefits
//
//   - Single implementation serves both in-process and remote modes
//   - Generated interfaces ensure type safety
//   - No manual client interface maintenance
//   - Compatible with pluginrpc for plugin extensibility
package services

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
)

// InProcessTransport implements http.RoundTripper by routing requests
// directly to registered HTTP handlers without network overhead.
//
// This enables using ConnectRPC generated clients with handler implementations
// in the same process, providing the same API for both local and remote execution.
type InProcessTransport struct {
	mu       sync.RWMutex
	handlers map[string]http.Handler // path prefix -> handler
	mux      *http.ServeMux          // fallback multiplexer
}

// NewInProcessTransport creates a transport that routes to the given handlers.
// The mux is used as a fallback for requests not matching registered handlers.
func NewInProcessTransport(mux *http.ServeMux) *InProcessTransport {
	return &InProcessTransport{
		handlers: make(map[string]http.Handler),
		mux:      mux,
	}
}

// RegisterHandler registers a handler for a path prefix.
// This is typically called with the path returned by New*ServiceHandler functions.
func (t *InProcessTransport) RegisterHandler(pathPrefix string, handler http.Handler) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.handlers[pathPrefix] = handler
}

// RoundTrip implements http.RoundTripper by invoking handlers directly.
func (t *InProcessTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Find matching handler
	handler := t.findHandler(req.URL.Path)
	if handler == nil {
		// No handler found - return 404
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Status:     "404 Not Found",
			Body:       io.NopCloser(strings.NewReader("handler not found")),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	}

	// Use httptest.ResponseRecorder to capture the response
	recorder := httptest.NewRecorder()

	// Clone request body if present (it may be read multiple times)
	var bodyBytes []byte
	if req.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	// Serve the request
	handler.ServeHTTP(recorder, req)

	// Build response
	result := recorder.Result()
	result.Request = req

	return result, nil
}

// findHandler finds the handler for a given path.
func (t *InProcessTransport) findHandler(path string) http.Handler {
	t.mu.RLock()
	defer t.mu.RUnlock()

	// Try exact prefix match first
	for prefix, handler := range t.handlers {
		if strings.HasPrefix(path, prefix) {
			return handler
		}
	}

	// Fall back to mux if available
	if t.mux != nil {
		return t.mux
	}

	return nil
}

// HTTPClient returns an http.Client that uses this transport.
// This is the client to pass to NewScanServiceClient and similar functions.
func (t *InProcessTransport) HTTPClient() *http.Client {
	return &http.Client{Transport: t}
}
