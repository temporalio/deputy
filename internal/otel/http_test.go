package otel

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/otel/attribute"
)

func TestInstrumentedTransport_NilBase(t *testing.T) {
	transport := InstrumentedTransport(nil)
	if transport == nil {
		t.Error("expected non-nil transport")
	}
}

func TestInstrumentedTransport_WithBase(t *testing.T) {
	base := &http.Transport{
		MaxIdleConns: 10,
	}
	transport := InstrumentedTransport(base)
	if transport == nil {
		t.Error("expected non-nil transport")
	}
}

func TestInstrumentedHandler(t *testing.T) {
	called := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	instrumented := InstrumentedHandler(handler, "test.operation")
	if instrumented == nil {
		t.Fatal("expected non-nil handler")
	}

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	instrumented.ServeHTTP(rec, req)

	if !called {
		t.Error("expected handler to be called")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestInstrumentedMiddleware(t *testing.T) {
	called := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	middleware := InstrumentedMiddleware("test.operation")
	wrapped := middleware(handler)
	if wrapped == nil {
		t.Fatal("expected non-nil handler")
	}

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if !called {
		t.Error("expected handler to be called")
	}
}

func TestWithServiceName(t *testing.T) {
	opt := WithServiceName("test-service")
	if opt == nil {
		t.Error("expected non-nil option")
	}
}

func TestWithSpanNameFormatter(t *testing.T) {
	formatter := func(operation string, r *http.Request) string {
		return "custom." + operation
	}
	opt := WithSpanNameFormatter(formatter)
	if opt == nil {
		t.Error("expected non-nil option")
	}
}

func TestWithPublicEndpoint(t *testing.T) {
	opt := WithPublicEndpoint()
	if opt == nil {
		t.Error("expected non-nil option")
	}
}

func TestWithPublicEndpointFn(t *testing.T) {
	fn := func(r *http.Request) bool {
		return r.URL.Path == "/public"
	}
	opt := WithPublicEndpointFn(fn)
	if opt == nil {
		t.Error("expected non-nil option")
	}
}

func TestProxySpanNameFormatter(t *testing.T) {
	formatter := ProxySpanNameFormatter("go")

	tests := []struct {
		method   string
		path     string
		expected string
	}{
		{"GET", "/mod/@v/list", "deputy.proxy.go GET /mod/@v/list"},
		{"GET", "/github.com/pkg/errors/@v/v0.9.1.info", "deputy.proxy.go GET /github.com/pkg/errors/@v/v0.9.1.info"},
		{"POST", "/sumdb/lookup", "deputy.proxy.go POST /sumdb/lookup"},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			result := formatter("operation", req)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestClientSpanNameFormatter(t *testing.T) {
	formatter := ClientSpanNameFormatter("osv-api")

	tests := []struct {
		method   string
		path     string
		expected string
	}{
		{"POST", "/v1/query", "HTTP POST osv-api"},
		{"GET", "/vulns/GHSA-xxx", "HTTP GET osv-api"},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "https://api.osv.dev"+tt.path, nil)
			result := formatter("operation", req)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestRequestAttributes(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		url            string
		host           string
		contentLength  int64
		userAgent      string
		expectedAttrs  map[string]string
		expectedInt64s map[string]int64
	}{
		{
			name:          "basic GET request",
			method:        http.MethodGet,
			url:           "/test",
			host:          "example.com",
			contentLength: 0,
			userAgent:     "",
			expectedAttrs: map[string]string{
				"http.method": "GET",
				"http.host":   "example.com",
			},
		},
		{
			name:          "POST request with content length and user agent",
			method:        http.MethodPost,
			url:           "/api/data",
			host:          "api.example.com",
			contentLength: 1024,
			userAgent:     "deputy/1.0",
			expectedAttrs: map[string]string{
				"http.method":     "POST",
				"http.host":       "api.example.com",
				"http.user_agent": "deputy/1.0",
			},
			expectedInt64s: map[string]int64{
				"http.request_content_length": 1024,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "http://"+tt.host+tt.url, nil)
			req.Host = tt.host
			req.ContentLength = tt.contentLength
			if tt.userAgent != "" {
				req.Header.Set("User-Agent", tt.userAgent)
			}

			attrs := RequestAttributes(req)

			// Check that expected string attributes are present
			for key, expectedVal := range tt.expectedAttrs {
				found := false
				for _, attr := range attrs {
					if string(attr.Key) == key {
						found = true
						if attr.Value.AsString() != expectedVal {
							t.Errorf("attribute %s: expected %q, got %q", key, expectedVal, attr.Value.AsString())
						}
						break
					}
				}
				if !found {
					t.Errorf("expected attribute %s not found", key)
				}
			}

			// Check that expected int64 attributes are present
			for key, expectedVal := range tt.expectedInt64s {
				found := false
				for _, attr := range attrs {
					if string(attr.Key) == key {
						found = true
						if attr.Value.AsInt64() != expectedVal {
							t.Errorf("attribute %s: expected %d, got %d", key, expectedVal, attr.Value.AsInt64())
						}
						break
					}
				}
				if !found {
					t.Errorf("expected attribute %s not found", key)
				}
			}
		})
	}
}

func TestResponseAttributes(t *testing.T) {
	tests := []struct {
		name          string
		statusCode    int
		contentLength int64
		expectedCount int
	}{
		{
			name:          "success response without content length",
			statusCode:    200,
			contentLength: 0,
			expectedCount: 1,
		},
		{
			name:          "success response with content length",
			statusCode:    200,
			contentLength: 2048,
			expectedCount: 2,
		},
		{
			name:          "error response",
			statusCode:    500,
			contentLength: 100,
			expectedCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := ResponseAttributes(tt.statusCode, tt.contentLength)

			if len(attrs) != tt.expectedCount {
				t.Errorf("expected %d attributes, got %d", tt.expectedCount, len(attrs))
			}

			// Check status code is always present
			hasStatusCode := false
			for _, attr := range attrs {
				if string(attr.Key) == "http.status_code" {
					hasStatusCode = true
					if attr.Value.AsInt64() != int64(tt.statusCode) {
						t.Errorf("expected status_code %d, got %d", tt.statusCode, attr.Value.AsInt64())
					}
				}
			}
			if !hasStatusCode {
				t.Error("expected http.status_code attribute")
			}

			// Check content length if expected
			if tt.contentLength > 0 {
				hasContentLength := false
				for _, attr := range attrs {
					if string(attr.Key) == "http.response_content_length" {
						hasContentLength = true
						if attr.Value.AsInt64() != tt.contentLength {
							t.Errorf("expected content_length %d, got %d", tt.contentLength, attr.Value.AsInt64())
						}
					}
				}
				if !hasContentLength {
					t.Error("expected http.response_content_length attribute")
				}
			}
		})
	}
}

func TestRequestAttributes_URLIncluded(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/path?query=value", nil)
	attrs := RequestAttributes(req)

	var urlAttr attribute.KeyValue
	for _, attr := range attrs {
		if string(attr.Key) == "http.url" {
			urlAttr = attr
			break
		}
	}

	if urlAttr.Key == "" {
		t.Fatal("expected http.url attribute")
	}

	// URL should include path and query
	url := urlAttr.Value.AsString()
	if url != "http://example.com/path?query=value" {
		t.Errorf("expected full URL, got %q", url)
	}
}
