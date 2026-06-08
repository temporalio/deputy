package releases

import (
	"context"
	"net/http"
)

// Lister is the common surface every release source implements: fetch the
// source's published versions as a list of [Release]. Consumers depend on this
// interface rather than the concrete client types.
type Lister interface {
	List(ctx context.Context) ([]Release, error)
}

// base holds the HTTP configuration shared by every release client. Each client
// embeds it so configuration and option handling are defined once.
type base struct {
	endpoint   string
	httpClient *http.Client
	maxBytes   int64
}

// Option configures the shared HTTP behavior of any release client. The same
// option set applies to every client, so callers use, e.g.,
// releases.WithHTTPClient with any New*Client constructor.
type Option func(*base)

// WithEndpoint overrides the upstream metadata endpoint. Empty is ignored so
// the source's default endpoint is preserved. Primarily used in tests to point
// a client at an httptest server.
func WithEndpoint(endpoint string) Option {
	return func(b *base) {
		if endpoint != "" {
			b.endpoint = endpoint
		}
	}
}

// WithHTTPClient sets the HTTP client used for metadata requests. Nil is
// ignored so the default SSRF-safe retrying client is preserved.
func WithHTTPClient(client *http.Client) Option {
	return func(b *base) {
		if client != nil {
			b.httpClient = client
		}
	}
}

// WithMaxBytes bounds the metadata response size read before decoding.
// Non-positive values are ignored so the default bound is preserved.
func WithMaxBytes(n int64) Option {
	return func(b *base) {
		if n > 0 {
			b.maxBytes = n
		}
	}
}

// newBase returns a base seeded with endpoint and Deputy's defaults, then
// applies opts. After construction every field is non-zero, so List methods can
// read them directly without re-defaulting.
func newBase(endpoint string, opts ...Option) base {
	b := base{
		endpoint:   endpoint,
		httpClient: defaultHTTPClient(),
		maxBytes:   defaultJSONMaxBytes,
	}
	for _, opt := range opts {
		opt(&b)
	}
	return b
}

// fetch fetches b.endpoint, decodes the JSON body into T, and maps it to
// releases via decode. It centralizes the fetch+decode+map plumbing every
// client would otherwise repeat.
func fetch[T any](ctx context.Context, b base, decode func(T) []Release) ([]Release, error) {
	return fetchURL(ctx, b, b.endpoint, decode)
}

// fetchURL is like [fetch] but fetches an explicit URL, for sources that derive
// their request URL from the configured endpoint (e.g. adding query params).
func fetchURL[T any](ctx context.Context, b base, endpoint string, decode func(T) []Release) ([]Release, error) {
	var payload T
	if err := decodeJSON(ctx, b.httpClient, endpoint, b.maxBytes, &payload); err != nil {
		return nil, err
	}
	return decode(payload), nil
}
