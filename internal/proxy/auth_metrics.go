package proxy

import (
	"expvar"
	"sync"
	"sync/atomic"

	"github.com/picatz/deputy/internal/auth/jwt"
)

// Verify AuthMetrics implements jwt.MetricsRecorder.
var _ jwt.MetricsRecorder = (*AuthMetrics)(nil)

// AuthMetrics tracks authentication statistics for observability.
type AuthMetrics struct {
	// Total authentication attempts
	TotalRequests atomic.Int64
	// Successful authentications (valid token)
	Authenticated atomic.Int64
	// Anonymous requests (no token, mode=optional)
	Anonymous atomic.Int64
	// Rejected requests by error code
	Rejected struct {
		MissingToken     atomic.Int64
		InvalidToken     atomic.Int64
		ExpiredToken     atomic.Int64
		SignatureInvalid atomic.Int64
		KeyNotFound      atomic.Int64
		InvalidIssuer    atomic.Int64
		InvalidAudience  atomic.Int64
		MissingClaim     atomic.Int64
		Other            atomic.Int64
	}
	// JWKS cache health metrics
	JWKS struct {
		RefreshSuccess atomic.Int64
		RefreshFailure atomic.Int64
		KeyLookups     atomic.Int64
		KeyMisses      atomic.Int64
	}
}

// Stats returns a snapshot of the current metrics.
func (m *AuthMetrics) Stats() map[string]any {
	return map[string]any{
		"total_requests": m.TotalRequests.Load(),
		"authenticated":  m.Authenticated.Load(),
		"anonymous":      m.Anonymous.Load(),
		"rejected": map[string]int64{
			"missing_token":     m.Rejected.MissingToken.Load(),
			"invalid_token":     m.Rejected.InvalidToken.Load(),
			"expired_token":     m.Rejected.ExpiredToken.Load(),
			"signature_invalid": m.Rejected.SignatureInvalid.Load(),
			"key_not_found":     m.Rejected.KeyNotFound.Load(),
			"invalid_issuer":    m.Rejected.InvalidIssuer.Load(),
			"invalid_audience":  m.Rejected.InvalidAudience.Load(),
			"missing_claim":     m.Rejected.MissingClaim.Load(),
			"other":             m.Rejected.Other.Load(),
		},
		"jwks": map[string]int64{
			"refresh_success": m.JWKS.RefreshSuccess.Load(),
			"refresh_failure": m.JWKS.RefreshFailure.Load(),
			"key_lookups":     m.JWKS.KeyLookups.Load(),
			"key_misses":      m.JWKS.KeyMisses.Load(),
		},
	}
}

// RecordSuccess records a successful authentication.
func (m *AuthMetrics) RecordSuccess() {
	m.TotalRequests.Add(1)
	m.Authenticated.Add(1)
}

// RecordAnonymous records an anonymous request (no token, allowed).
func (m *AuthMetrics) RecordAnonymous() {
	m.TotalRequests.Add(1)
	m.Anonymous.Add(1)
}

// RecordError records an authentication error by code.
func (m *AuthMetrics) RecordError(code string) {
	m.TotalRequests.Add(1)
	switch code {
	case AuthCodeMissingToken:
		m.Rejected.MissingToken.Add(1)
	case AuthCodeInvalidToken:
		m.Rejected.InvalidToken.Add(1)
	case AuthCodeExpiredToken:
		m.Rejected.ExpiredToken.Add(1)
	case AuthCodeSignatureInvalid:
		m.Rejected.SignatureInvalid.Add(1)
	case AuthCodeKeyNotFound:
		m.Rejected.KeyNotFound.Add(1)
	case AuthCodeInvalidIssuer:
		m.Rejected.InvalidIssuer.Add(1)
	case AuthCodeInvalidAudience:
		m.Rejected.InvalidAudience.Add(1)
	case AuthCodeMissingClaim:
		m.Rejected.MissingClaim.Add(1)
	default:
		m.Rejected.Other.Add(1)
	}
}

// RecordJWKSRefresh records a JWKS refresh attempt result.
func (m *AuthMetrics) RecordJWKSRefresh(success bool) {
	if success {
		m.JWKS.RefreshSuccess.Add(1)
	} else {
		m.JWKS.RefreshFailure.Add(1)
	}
}

// RecordJWKSKeyLookup records a JWKS key lookup attempt.
func (m *AuthMetrics) RecordJWKSKeyLookup(found bool) {
	m.JWKS.KeyLookups.Add(1)
	if !found {
		m.JWKS.KeyMisses.Add(1)
	}
}

// Global auth metrics instance
var authMetrics = &AuthMetrics{}

var registerAuthMetricsOnce sync.Once

// registerAuthMetrics registers auth metrics with expvar.
func registerAuthMetrics() {
	registerAuthMetricsOnce.Do(func() {
		expvar.Publish("deputy_proxy_auth", expvar.Func(func() any {
			return authMetrics.Stats()
		}))
	})
}

// GetAuthMetrics returns the global auth metrics instance.
// This is useful for testing and debugging.
func GetAuthMetrics() *AuthMetrics {
	return authMetrics
}
