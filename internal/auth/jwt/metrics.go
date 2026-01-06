package jwt

// MetricsRecorder defines the interface for recording authentication metrics.
// Implement this interface to integrate with your preferred metrics system
// (expvar, Prometheus, OpenTelemetry, etc.).
type MetricsRecorder interface {
	// RecordSuccess records a successful authentication.
	RecordSuccess()
	// RecordAnonymous records an anonymous request (no token, allowed).
	RecordAnonymous()
	// RecordError records an authentication error by error code.
	RecordError(code string)
	// RecordJWKSRefresh records a JWKS refresh attempt result.
	RecordJWKSRefresh(success bool)
	// RecordJWKSKeyLookup records a JWKS key lookup attempt.
	RecordJWKSKeyLookup(found bool)
}

// NoopMetrics is a no-op implementation of MetricsRecorder.
// Use this as a default when metrics are not needed.
type NoopMetrics struct{}

func (NoopMetrics) RecordSuccess()              {}
func (NoopMetrics) RecordAnonymous()            {}
func (NoopMetrics) RecordError(string)          {}
func (NoopMetrics) RecordJWKSRefresh(bool)      {}
func (NoopMetrics) RecordJWKSKeyLookup(bool)    {}

// Ensure NoopMetrics implements MetricsRecorder.
var _ MetricsRecorder = NoopMetrics{}
