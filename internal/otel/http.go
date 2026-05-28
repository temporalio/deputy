package otel

import (
	"net/http"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
)

// InstrumentedTransport wraps an http.RoundTripper with OpenTelemetry tracing.
// Creates client spans for outgoing HTTP requests with proper context propagation.
func InstrumentedTransport(base http.RoundTripper, opts ...otelhttp.Option) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return otelhttp.NewTransport(base, opts...)
}

// InstrumentedHandler wraps an http.Handler with OpenTelemetry tracing.
// Creates server spans for incoming HTTP requests.
func InstrumentedHandler(handler http.Handler, operation string, opts ...otelhttp.Option) http.Handler {
	return otelhttp.NewHandler(handler, operation, opts...)
}

// InstrumentedMiddleware returns middleware that wraps handlers with OTel tracing.
func InstrumentedMiddleware(operation string, opts ...otelhttp.Option) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return InstrumentedHandler(next, operation, opts...)
	}
}

// WithServiceName returns an option that sets the service name for spans.
func WithServiceName(name string) otelhttp.Option {
	return otelhttp.WithServerName(name)
}

// WithSpanNameFormatter returns an option that customizes span names.
func WithSpanNameFormatter(fn func(operation string, r *http.Request) string) otelhttp.Option {
	return otelhttp.WithSpanNameFormatter(fn)
}

// WithPropagators returns an option that sets custom propagators.
func WithPropagators(p propagation.TextMapPropagator) otelhttp.Option {
	return otelhttp.WithPropagators(p)
}

// WithPublicEndpoint returns an option that marks the endpoint as public.
// Public endpoints always start a new trace rather than continuing an existing one.
func WithPublicEndpoint() otelhttp.Option {
	return otelhttp.WithPublicEndpointFn(func(*http.Request) bool { return true })
}

// WithPublicEndpointFn returns an option with a function to determine if an endpoint is public.
func WithPublicEndpointFn(fn func(r *http.Request) bool) otelhttp.Option {
	return otelhttp.WithPublicEndpointFn(fn)
}

// ProxySpanNameFormatter returns a span name formatter suitable for proxy requests.
func ProxySpanNameFormatter(ecosystem string) func(string, *http.Request) string {
	return func(operation string, r *http.Request) string {
		return "deputy.proxy." + ecosystem + " " + r.Method + " " + r.URL.Path
	}
}

// ClientSpanNameFormatter returns a span name formatter for outgoing HTTP client requests.
func ClientSpanNameFormatter(service string) func(string, *http.Request) string {
	return func(operation string, r *http.Request) string {
		return "HTTP " + r.Method + " " + service
	}
}

// RequestAttributes returns common attributes for HTTP request spans.
func RequestAttributes(r *http.Request) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.String("http.method", r.Method),
		attribute.String("http.url", r.URL.String()),
		attribute.String("http.host", r.Host),
	}
	if r.ContentLength > 0 {
		attrs = append(attrs, attribute.Int64("http.request_content_length", r.ContentLength))
	}
	if ua := r.UserAgent(); ua != "" {
		attrs = append(attrs, attribute.String("http.user_agent", ua))
	}
	return attrs
}

// ResponseAttributes returns common attributes for HTTP response spans.
func ResponseAttributes(statusCode int, contentLength int64) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.Int("http.status_code", statusCode),
	}
	if contentLength > 0 {
		attrs = append(attrs, attribute.Int64("http.response_content_length", contentLength))
	}
	return attrs
}
