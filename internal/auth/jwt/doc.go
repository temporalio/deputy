// Package jwt provides reusable JWT authentication middleware for HTTP services.
//
// This package offers a composable authentication system that supports:
//   - JWT validation with JWKS (JSON Web Key Set) or static keys
//   - Multiple authentication modes (disabled, optional, required)
//   - OIDC discovery for automatic key endpoint resolution
//   - Background key refresh with configurable intervals
//   - Pluggable metrics and observability hooks
//   - Integration with connectrpc/authn-go for idiomatic Connect authentication
//
// # Basic Usage
//
// Create an authenticator with configuration:
//
//	cfg := &jwt.Config{
//		Mode: "required",
//		JWKS: &jwt.JWKSConfig{
//			URL: "https://auth.example.com/.well-known/jwks.json",
//		},
//		Issuers:   []string{"https://auth.example.com"},
//		Audiences: []string{"my-service"},
//	}
//
//	authenticator, err := jwt.NewAuthenticator(cfg)
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer authenticator.Close()
//
// Use the middleware to protect HTTP handlers:
//
//	handler := jwt.Middleware(authenticator, jwt.MiddlewareConfig{
//		Mode: jwt.ModeRequired,
//	})(yourHandler)
//
// # ConnectRPC Integration (authn-go)
//
// For ConnectRPC services, use [AuthnFunc] to create an [authn.AuthFunc] that wraps
// the JWT authenticator. This enables idiomatic authentication at the HTTP layer
// before request deserialization:
//
//	authenticator, _ := jwt.NewAuthenticator(cfg)
//	authFunc := jwt.AuthnFunc(authenticator, jwt.ModeRequired)
//	middleware := authn.NewMiddleware(authFunc)
//	handler := middleware.Wrap(mux)
//
// Retrieve claims in handlers or interceptors:
//
//	claims := jwt.ClaimsFromAuthn(ctx)
//	if claims != nil {
//		fmt.Println("User:", claims.Subject)
//	}
//
// Check for anonymous access:
//
//	if jwt.IsAnonymousAuthn(ctx) {
//		// Handle anonymous request
//	}
//
// Benefits of authn-go integration:
//   - Authentication before request deserialization (more efficient rejections)
//   - Proper Connect error format with metadata (WWW-Authenticate, X-Auth-Error)
//   - Context propagation via authn.GetInfo/SetInfo
//   - Consistent with ConnectRPC ecosystem patterns
//
// # Static Keys (Development/Testing)
//
// For development or air-gapped environments, use static keys:
//
//	cfg := &jwt.Config{
//		Mode: "required",
//		StaticKeys: []jwt.StaticKeyConfig{{
//			KeyID:     "dev-key",
//			Algorithm: "RS256",
//			PublicKey: "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
//		}},
//	}
//
// # Metrics Integration
//
// Provide custom metrics recording via options:
//
//	authenticator, err := jwt.NewAuthenticator(cfg,
//		jwt.WithMetrics(myMetricsRecorder),
//	)
//
// # OIDC Discovery
//
// Auto-discover JWKS endpoint from issuer:
//
//	cfg := &jwt.Config{
//		JWKS: &jwt.JWKSConfig{
//			URL:           "https://auth.example.com",
//			OIDCDiscovery: true,
//		},
//	}
//
// # Security
//
// This package enforces security-first defaults:
//   - Only asymmetric algorithms are supported (RS256, ES256, EdDSA, PS256, etc.)
//   - Symmetric algorithms (HS256, etc.) are intentionally rejected
//   - Maximum token size is enforced (default 16KB) to prevent DoS
//   - Clock skew is limited to 5 minutes maximum
//   - JWKS refresh is rate-limited (minimum 5 minutes between refreshes)
//
// Always use HTTPS in production to protect tokens in transit.
//
// This package is used by Deputy's proxy server, gRPC server, and MCP server
// for consistent authentication across all HTTP-based services.
package jwt
