package mcp

import (
	"expvar"
	"sync"
	"sync/atomic"

	"github.com/temporalio/deputy/internal/auth/jwt"
)

// Verify mcpAuthMetrics implements jwt.MetricsRecorder.
var _ jwt.MetricsRecorder = (*mcpAuthMetrics)(nil)

// mcpAuthMetrics tracks authentication statistics for the MCP server.
type mcpAuthMetrics struct {
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
func (m *mcpAuthMetrics) Stats() map[string]any {
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
func (m *mcpAuthMetrics) RecordSuccess() {
	m.TotalRequests.Add(1)
	m.Authenticated.Add(1)
}

// RecordAnonymous records an anonymous request (no token, allowed).
func (m *mcpAuthMetrics) RecordAnonymous() {
	m.TotalRequests.Add(1)
	m.Anonymous.Add(1)
}

// RecordError records an authentication error by code.
func (m *mcpAuthMetrics) RecordError(code string) {
	m.TotalRequests.Add(1)
	switch code {
	case jwt.CodeMissingToken:
		m.Rejected.MissingToken.Add(1)
	case jwt.CodeInvalidToken:
		m.Rejected.InvalidToken.Add(1)
	case jwt.CodeExpiredToken:
		m.Rejected.ExpiredToken.Add(1)
	case jwt.CodeSignatureInvalid:
		m.Rejected.SignatureInvalid.Add(1)
	case jwt.CodeKeyNotFound:
		m.Rejected.KeyNotFound.Add(1)
	case jwt.CodeInvalidIssuer:
		m.Rejected.InvalidIssuer.Add(1)
	case jwt.CodeInvalidAudience:
		m.Rejected.InvalidAudience.Add(1)
	case jwt.CodeMissingClaim:
		m.Rejected.MissingClaim.Add(1)
	default:
		m.Rejected.Other.Add(1)
	}
}

// RecordJWKSRefresh records a JWKS refresh attempt result.
func (m *mcpAuthMetrics) RecordJWKSRefresh(success bool) {
	if success {
		m.JWKS.RefreshSuccess.Add(1)
	} else {
		m.JWKS.RefreshFailure.Add(1)
	}
}

// RecordJWKSKeyLookup records a JWKS key lookup attempt.
func (m *mcpAuthMetrics) RecordJWKSKeyLookup(found bool) {
	m.JWKS.KeyLookups.Add(1)
	if !found {
		m.JWKS.KeyMisses.Add(1)
	}
}

// Global MCP auth metrics instance
var mcpMetrics = &mcpAuthMetrics{}

var registerMCPAuthMetricsOnce sync.Once

// registerMCPAuthMetrics registers MCP auth metrics with expvar.
func registerMCPAuthMetrics() {
	registerMCPAuthMetricsOnce.Do(func() {
		expvar.Publish("deputy_mcp_auth", expvar.Func(func() any {
			return mcpMetrics.Stats()
		}))
	})
}

// GetMCPAuthMetrics returns the global MCP auth metrics instance.
// This is useful for testing and observability.
func GetMCPAuthMetrics() *mcpAuthMetrics {
	return mcpMetrics
}
