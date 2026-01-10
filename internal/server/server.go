package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/authn"
	"connectrpc.com/connect"
	"connectrpc.com/cors"
	"connectrpc.com/otelconnect"
	"connectrpc.com/validate"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"golang.org/x/time/rate"

	"github.com/picatz/deputy/gen/deputy/diff/v1/diffv1connect"
	"github.com/picatz/deputy/gen/deputy/graph/v1/graphv1connect"
	"github.com/picatz/deputy/gen/deputy/list/v1/listv1connect"
	"github.com/picatz/deputy/gen/deputy/remediation/v1/remediationv1connect"
	"github.com/picatz/deputy/gen/deputy/sbom/v1/sbomv1connect"
	"github.com/picatz/deputy/gen/deputy/scan/v1/scanv1connect"
	"github.com/picatz/deputy/gen/deputy/secrets/v1/secretsv1connect"
	"github.com/picatz/deputy/internal/auth/jwt"
	"github.com/picatz/deputy/internal/cache/memory"
	"github.com/picatz/deputy/internal/logs"
	"github.com/picatz/deputy/internal/otel"
	"github.com/picatz/deputy/internal/policy"
)

// Config configures the Deputy server.
type Config struct {
	// Addr is the address to listen on (e.g., ":8090", "localhost:8090").
	Addr string

	// ReadTimeout is the maximum duration for reading the request.
	ReadTimeout time.Duration

	// WriteTimeout is the maximum duration for writing the response.
	WriteTimeout time.Duration

	// IdleTimeout is the maximum duration to wait for the next request.
	IdleTimeout time.Duration

	// TLS configuration for production deployments.
	TLS *TLSConfig

	// CORS configuration for web clients.
	CORS *CORSConfig

	// Auth configuration for JWT authentication.
	Auth *AuthConfig

	// RateLimit configuration for rate limiting.
	RateLimit *RateLimitConfig

	// MaxRequestBodyBytes limits request body size (default: 10MB).
	MaxRequestBodyBytes int64

	// Policies lists paths to policy files for service-level authorization.
	// These policies are evaluated at service_* entrypoints to control
	// which users/services can perform which operations on which targets.
	Policies []string
}

// TLSConfig configures TLS for the server.
type TLSConfig struct {
	// CertFile is the path to the TLS certificate file.
	CertFile string

	// KeyFile is the path to the TLS private key file.
	KeyFile string

	// MinVersion is the minimum TLS version (default: TLS 1.2).
	MinVersion uint16

	// ClientAuth specifies the policy for client certificate authentication.
	ClientAuth tls.ClientAuthType

	// ClientCAFile is the path to the CA certificate for client verification.
	ClientCAFile string
}

// CORSConfig configures Cross-Origin Resource Sharing.
type CORSConfig struct {
	// AllowedOrigins is a list of allowed origins (* for all).
	AllowedOrigins []string

	// AllowedMethods is a list of allowed HTTP methods.
	AllowedMethods []string

	// AllowedHeaders is a list of allowed headers.
	AllowedHeaders []string

	// ExposedHeaders is a list of headers exposed to the client.
	ExposedHeaders []string

	// AllowCredentials indicates whether credentials are allowed.
	AllowCredentials bool

	// MaxAge is the max age for preflight cache in seconds.
	MaxAge int
}

// AuthConfig configures authentication for the server.
// This uses the same JWT infrastructure as the proxy (internal/auth/jwt).
type AuthConfig struct {
	// Mode determines how authentication is enforced.
	// - "required": requests without valid tokens are rejected (401)
	// - "optional": tokens are validated if present, anonymous access allowed
	// - "disabled": no authentication (default for backward compatibility)
	Mode string

	// JWKS configures JSON Web Key Set endpoints for key discovery.
	JWKS *JWKSConfig

	// StaticKeys provides inline public keys for validation.
	// Useful for development, testing, or air-gapped environments.
	StaticKeys []StaticKeyConfig

	// Issuers lists trusted token issuers (iss claim).
	// If empty, issuer validation is skipped.
	Issuers []string

	// Audiences lists expected audiences (aud claim).
	// If empty, audience validation is skipped.
	Audiences []string

	// RequiredClaims specifies claims that must be present in tokens.
	RequiredClaims []string

	// ClockSkew allows for clock drift when validating exp/nbf/iat.
	// Defaults to 0 (no skew allowed). Maximum 5 minutes.
	ClockSkew time.Duration

	// Deprecated: Use Mode="required" or Mode="optional" instead.
	// Enabled turns authentication on/off.
	Enabled bool

	// Deprecated: Use JWKS.URL instead.
	// JWKSURL is the URL to fetch JSON Web Key Sets.
	JWKSURL string
}

// JWKSConfig configures JWKS endpoint discovery.
type JWKSConfig struct {
	// URL is the JWKS endpoint (e.g., https://issuer/.well-known/jwks.json).
	URL string

	// OIDCDiscovery enables OIDC discovery from issuer URL.
	// When true, URL should be the issuer URL; JWKS URI is auto-discovered.
	OIDCDiscovery bool

	// RefreshInterval controls background JWKS refresh (default: 1h).
	RefreshInterval time.Duration
}

// StaticKeyConfig defines an inline public key.
type StaticKeyConfig struct {
	// KeyID is the key identifier (matches JWT header "kid").
	KeyID string

	// Algorithm specifies the signing algorithm (e.g., RS256, ES256, EdDSA).
	Algorithm string

	// PublicKey is the PEM-encoded public key.
	PublicKey string
}

// RateLimitConfig configures rate limiting.
type RateLimitConfig struct {
	// Enabled turns rate limiting on/off.
	Enabled bool

	// RequestsPerSecond is the maximum requests per second per client.
	RequestsPerSecond float64

	// Burst is the maximum burst size.
	Burst int
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Addr:                ":8090",
		ReadTimeout:         30 * time.Second,
		WriteTimeout:        5 * time.Minute, // Scans can take a while
		IdleTimeout:         2 * time.Minute,
		MaxRequestBodyBytes: 10 * 1024 * 1024, // 10MB
	}
}

// Server is the Deputy gRPC/Connect server.
type Server struct {
	config        Config
	httpServer    *http.Server
	handler       http.Handler       // The fully wrapped handler with all middleware
	authenticator jwt.Authenticator  // JWT authenticator (nil if auth disabled)
	policies      []policy.Source    // Loaded policy sources (nil if no policies)
}

// New creates a new Deputy server with the given configuration.
func New(cfg Config) *Server {
	applyDefaults(&cfg)

	mux := http.NewServeMux()

	// Initialize JWT authenticator if auth is configured
	var authenticator jwt.Authenticator
	var authnMiddleware *authn.Middleware
	authMode := getAuthMode(cfg.Auth)

	if authMode != jwt.ModeDisabled {
		jwtConfig := buildJWTConfig(cfg.Auth)
		if jwtConfig != nil {
			auth, err := jwt.NewAuthenticator(jwtConfig)
			if err != nil {
				logs.Error(context.Background(), "failed to create JWT authenticator", "error", err)
			} else {
				authenticator = auth
				// Create authn middleware using our JWT authenticator
				// This validates tokens at the HTTP layer before request deserialization
				authFunc := jwt.AuthnFunc(authenticator, authMode)
				authnMiddleware = authn.NewMiddleware(authFunc)
			}
		}
	}

	// Build middleware chain
	var handler http.Handler = mux

	// Add CORS middleware if configured
	if cfg.CORS != nil {
		handler = corsMiddleware(cfg.CORS)(handler)
	}

	// Add authn middleware if configured (before rate limiting for efficiency)
	// This uses connectrpc/authn-go for idiomatic Connect authentication
	// Health endpoints are exempt from authentication
	if authnMiddleware != nil {
		handler = skipAuthForHealth(authnMiddleware.Wrap(handler), mux)
	}

	// Add rate limiting middleware if configured
	if cfg.RateLimit != nil && cfg.RateLimit.Enabled {
		handler = rateLimitMiddleware(cfg.RateLimit)(handler)
	}

	// Add request size limiting
	if cfg.MaxRequestBodyBytes > 0 {
		handler = maxBytesMiddleware(cfg.MaxRequestBodyBytes)(handler)
	}

	// Add OpenTelemetry tracing middleware
	handler = otel.InstrumentedMiddleware("deputy.server")(handler)

	// Load policies if configured
	var policies []policy.Source
	if len(cfg.Policies) > 0 {
		var err error
		policies, err = policy.LoadSources(cfg.Policies)
		if err != nil {
			logs.Error(context.Background(), "failed to load policies", "error", err, "paths", cfg.Policies)
		} else {
			logs.Info(context.Background(), "loaded server policies",
				"count", len(policies),
				"paths", cfg.Policies,
			)
		}
	}

	// Create Connect interceptors
	otelInterceptor, _ := otelconnect.NewInterceptor()
	validateInterceptor := validate.NewInterceptor()
	interceptors := []connect.Interceptor{
		otelInterceptor,
		validateInterceptor, // Validates requests against protovalidate constraints
		loggingInterceptor(),
		recoveryInterceptor(),
	}

	// Note: Authentication is now handled at the HTTP layer via authn middleware.
	// Claims are accessible via jwt.ClaimsFromAuthn(ctx) in handlers and interceptors.

	// Add policy interceptor if policies are configured
	if len(policies) > 0 {
		interceptors = append(interceptors, policyInterceptor(policies))
	}

	// Create service handlers
	scanHandler := NewScanHandler()
	sbomHandler := NewSBOMHandler()
	listHandler := NewListHandler()
	remediationHandler := NewRemediationHandler()
	secretsHandler, _ := NewSecretsHandler()
	diffHandler := NewDiffHandler()
	graphHandler := NewGraphHandler()

	// Register ConnectRPC handlers
	scanPath, scanConnectHandler := scanv1connect.NewScanServiceHandler(
		scanHandler,
		connect.WithInterceptors(interceptors...),
	)
	mux.Handle(scanPath, scanConnectHandler)

	sbomPath, sbomConnectHandler := sbomv1connect.NewSBOMServiceHandler(
		sbomHandler,
		connect.WithInterceptors(interceptors...),
	)
	mux.Handle(sbomPath, sbomConnectHandler)

	listPath, listConnectHandler := listv1connect.NewListServiceHandler(
		listHandler,
		connect.WithInterceptors(interceptors...),
	)
	mux.Handle(listPath, listConnectHandler)

	remediationPath, remediationConnectHandler := remediationv1connect.NewRemediationServiceHandler(
		remediationHandler,
		connect.WithInterceptors(interceptors...),
	)
	mux.Handle(remediationPath, remediationConnectHandler)

	secretsPath, secretsConnectHandler := secretsv1connect.NewSecretsServiceHandler(
		secretsHandler,
		connect.WithInterceptors(interceptors...),
	)
	mux.Handle(secretsPath, secretsConnectHandler)

	diffPath, diffConnectHandler := diffv1connect.NewDiffServiceHandler(
		diffHandler,
		connect.WithInterceptors(interceptors...),
	)
	mux.Handle(diffPath, diffConnectHandler)

	graphPath, graphConnectHandler := graphv1connect.NewGraphServiceHandler(
		graphHandler,
		connect.WithInterceptors(interceptors...),
	)
	mux.Handle(graphPath, graphConnectHandler)

	// Health check endpoint
	mux.HandleFunc("/health", healthHandler)

	// Ready check endpoint
	mux.HandleFunc("/ready", readyHandler)

	// Version endpoint
	mux.HandleFunc("/version", versionHandler)

	// Determine handler based on TLS config
	var finalHandler http.Handler
	if cfg.TLS != nil {
		// With TLS, use standard handler (HTTP/2 is automatic)
		finalHandler = handler
	} else {
		// Without TLS, use h2c for HTTP/2 cleartext support
		finalHandler = h2c.NewHandler(handler, &http2.Server{})
	}

	httpServer := &http.Server{
		Addr:         cfg.Addr,
		Handler:      finalHandler,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
	}

	// Configure TLS if provided
	if cfg.TLS != nil {
		tlsConfig, err := buildTLSConfig(cfg.TLS)
		if err != nil {
			logs.Error(context.Background(), "failed to build TLS config", "error", err)
		} else {
			httpServer.TLSConfig = tlsConfig
		}
	}

	return &Server{
		config:        cfg,
		httpServer:    httpServer,
		handler:       handler, // The wrapped handler with all middleware
		authenticator: authenticator,
		policies:      policies,
	}
}

// applyDefaults fills in default values for missing config fields.
func applyDefaults(cfg *Config) {
	defaults := DefaultConfig()
	if cfg.Addr == "" {
		cfg.Addr = defaults.Addr
	}
	if cfg.ReadTimeout == 0 {
		cfg.ReadTimeout = defaults.ReadTimeout
	}
	if cfg.WriteTimeout == 0 {
		cfg.WriteTimeout = defaults.WriteTimeout
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = defaults.IdleTimeout
	}
	if cfg.MaxRequestBodyBytes == 0 {
		cfg.MaxRequestBodyBytes = defaults.MaxRequestBodyBytes
	}
}

// buildTLSConfig creates a tls.Config from TLSConfig.
func buildTLSConfig(cfg *TLSConfig) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if cfg.MinVersion != 0 {
		tlsConfig.MinVersion = cfg.MinVersion
	}

	if cfg.ClientAuth != 0 {
		tlsConfig.ClientAuth = cfg.ClientAuth
	}

	return tlsConfig, nil
}

// getAuthMode returns the effective auth mode from config.
// For servers, we only support "required" or "disabled" (not "optional").
func getAuthMode(cfg *AuthConfig) jwt.Mode {
	if cfg == nil {
		return jwt.ModeDisabled
	}

	// Handle deprecated Enabled field for backward compatibility
	if cfg.Enabled && cfg.Mode == "" {
		return jwt.ModeRequired
	}

	switch strings.ToLower(cfg.Mode) {
	case "required":
		return jwt.ModeRequired
	case "disabled", "":
		return jwt.ModeDisabled
	default:
		// For server mode, treat unknown modes as disabled
		logs.Warn(context.Background(), "unknown auth mode, defaulting to disabled",
			"mode", cfg.Mode,
			"hint", "server supports 'required' or 'disabled'")
		return jwt.ModeDisabled
	}
}

// buildJWTConfig converts server AuthConfig to the jwt.Config used by internal/auth/jwt.
func buildJWTConfig(cfg *AuthConfig) *jwt.Config {
	if cfg == nil {
		return nil
	}

	jwtCfg := &jwt.Config{
		Mode:           cfg.Mode,
		Issuers:        cfg.Issuers,
		Audiences:      cfg.Audiences,
		RequiredClaims: cfg.RequiredClaims,
		ClockSkew:      cfg.ClockSkew,
	}

	// Handle deprecated JWKSURL field
	if cfg.JWKSURL != "" && cfg.JWKS == nil {
		jwtCfg.JWKS = &jwt.JWKSConfig{
			URL: cfg.JWKSURL,
		}
	}

	// Copy JWKS config if present
	if cfg.JWKS != nil {
		jwtCfg.JWKS = &jwt.JWKSConfig{
			URL:             cfg.JWKS.URL,
			OIDCDiscovery:   cfg.JWKS.OIDCDiscovery,
			RefreshInterval: cfg.JWKS.RefreshInterval,
		}
	}

	// Copy static keys if present
	for _, sk := range cfg.StaticKeys {
		jwtCfg.StaticKeys = append(jwtCfg.StaticKeys, jwt.StaticKeyConfig{
			KeyID:     sk.KeyID,
			Algorithm: sk.Algorithm,
			PublicKey: sk.PublicKey,
		})
	}

	return jwtCfg
}

// ListenAndServe starts the server and blocks until it stops.
func (s *Server) ListenAndServe() error {
	ctx := context.Background()
	if s.config.TLS != nil {
		logs.Info(ctx, "starting Deputy server with TLS", "addr", s.config.Addr)
		return s.httpServer.ListenAndServeTLS(s.config.TLS.CertFile, s.config.TLS.KeyFile)
	}
	logs.Info(ctx, "starting Deputy server", "addr", s.config.Addr)
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(ctx context.Context) error {
	logs.Info(ctx, "shutting down Deputy server")
	return s.httpServer.Shutdown(ctx)
}

// Addr returns the server address.
func (s *Server) Addr() string {
	return s.config.Addr
}

// Handler returns the HTTP handler for testing.
// This returns the fully wrapped handler including all middleware (auth, CORS, rate limiting, etc.).
func (s *Server) Handler() http.Handler {
	return s.handler
}

// IsTLS returns true if TLS is configured.
func (s *Server) IsTLS() bool {
	return s.config.TLS != nil
}

// HTTP Handlers

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"status":"ok"}`)
}

func readyHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"status":"ready"}`)
}

func versionHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"version":"v1","api":"deputy.v1"}`)
}

// Middleware

// corsMiddleware adds CORS headers to responses.
// Uses connectrpc.com/cors for ConnectRPC-compatible headers.
func corsMiddleware(cfg *CORSConfig) func(http.Handler) http.Handler {
	// Merge user-configured headers with ConnectRPC required headers
	allowedMethods := cfg.AllowedMethods
	if len(allowedMethods) == 0 {
		allowedMethods = cors.AllowedMethods()
	}

	allowedHeaders := cfg.AllowedHeaders
	if len(allowedHeaders) == 0 {
		allowedHeaders = cors.AllowedHeaders()
	}

	exposedHeaders := cfg.ExposedHeaders
	if len(exposedHeaders) == 0 {
		exposedHeaders = cors.ExposedHeaders()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			// Check if origin is allowed
			allowed := false
			for _, o := range cfg.AllowedOrigins {
				if o == "*" || o == origin {
					allowed = true
					break
				}
			}

			if allowed && origin != "" {
				w.Header().Set("Access-Control-Allow-Origin", origin)

				if cfg.AllowCredentials {
					w.Header().Set("Access-Control-Allow-Credentials", "true")
				}

				if len(exposedHeaders) > 0 {
					w.Header().Set("Access-Control-Expose-Headers", strings.Join(exposedHeaders, ", "))
				}
			}

			// Handle preflight requests
			if r.Method == http.MethodOptions {
				w.Header().Set("Access-Control-Allow-Methods", strings.Join(allowedMethods, ", "))
				w.Header().Set("Access-Control-Allow-Headers", strings.Join(allowedHeaders, ", "))
				if cfg.MaxAge > 0 {
					w.Header().Set("Access-Control-Max-Age", fmt.Sprintf("%d", cfg.MaxAge))
				}
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// rateLimitMiddleware implements per-client rate limiting using token bucket.
// Uses a bounded LRU cache to prevent memory exhaustion from many unique IPs.
func rateLimitMiddleware(cfg *RateLimitConfig) func(http.Handler) http.Handler {
	// Per-client rate limiters with bounded size and TTL.
	// Max 10,000 entries with 1 hour TTL prevents memory exhaustion from
	// attackers using many unique IP addresses.
	const (
		maxLimiters = 10000
		limiterTTL  = 1 * time.Hour
	)
	limiters := memory.NewTTLCache[string, *rate.Limiter](maxLimiters, limiterTTL)

	getLimiter := func(key string) *rate.Limiter {
		if limiter, ok := limiters.Get(key); ok {
			return limiter
		}
		// Create new limiter and cache it
		limiter := rate.NewLimiter(rate.Limit(cfg.RequestsPerSecond), cfg.Burst)
		limiters.Set(key, limiter)
		return limiter
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Use client IP as rate limit key
			clientIP := r.RemoteAddr
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
				// Use first IP in X-Forwarded-For chain
				if idx := strings.Index(xff, ","); idx != -1 {
					clientIP = strings.TrimSpace(xff[:idx])
				} else {
					clientIP = strings.TrimSpace(xff)
				}
			}

			limiter := getLimiter(clientIP)
			if !limiter.Allow() {
				http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// skipAuthForHealth bypasses authentication for health check endpoints.
// Health endpoints (/health, /ready, /version) should be accessible without auth
// for load balancers and orchestration systems.
func skipAuthForHealth(authedHandler, unauthHandler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health", "/ready", "/version":
			unauthHandler.ServeHTTP(w, r)
		default:
			authedHandler.ServeHTTP(w, r)
		}
	})
}

// maxBytesMiddleware limits request body size.
func maxBytesMiddleware(maxBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			next.ServeHTTP(w, r)
		})
	}
}

// Connect Interceptors

// loggingInterceptor returns a Connect interceptor that logs requests.
func loggingInterceptor() connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			start := time.Now()
			procedure := req.Spec().Procedure

			logs.Debug(ctx, "rpc request started", "procedure", procedure)

			resp, err := next(ctx, req)

			duration := time.Since(start)
			if err != nil {
				logs.Error(ctx, "rpc request failed",
					"procedure", procedure,
					"duration_ms", duration.Milliseconds(),
					"error", err,
				)
			} else {
				logs.Info(ctx, "rpc request completed",
					"procedure", procedure,
					"duration_ms", duration.Milliseconds(),
				)
			}

			return resp, err
		}
	}
}

// recoveryInterceptor catches panics and converts them to errors.
func recoveryInterceptor() connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (resp connect.AnyResponse, err error) {
			defer func() {
				if r := recover(); r != nil {
					logs.Error(ctx, "panic recovered in RPC handler",
						"procedure", req.Spec().Procedure,
						"panic", r,
					)
					err = connect.NewError(connect.CodeInternal, fmt.Errorf("internal server error"))
				}
			}()
			return next(ctx, req)
		}
	}
}

// policyInterceptor evaluates service-level policies for authorization.
// It maps RPC procedures to policy entrypoints and evaluates policies with
// JWT claims (jwt.*), request metadata, and target information.
func policyInterceptor(policies []policy.Source) connect.UnaryInterceptorFunc {
	// Map RPC procedures to policy entrypoints
	procedureToEntrypoint := map[string]policy.Entrypoint{
		"/deputy.scan.v1.ScanService/Scan":           policy.EntrypointServiceScanRequest,
		"/deputy.scan.v1.ScanService/StreamScan":     policy.EntrypointServiceScanRequest,
		"/deputy.list.v1.ListService/ListPackages":   policy.EntrypointServiceListRequest,
		"/deputy.list.v1.ListService/ListEcosystems": policy.EntrypointServiceListRequest,
		"/deputy.sbom.v1.SBOMService/Generate":       policy.EntrypointServiceSBOMRequest,
		"/deputy.sbom.v1.SBOMService/Diff":           policy.EntrypointServiceSBOMRequest,
		"/deputy.diff.v1.DiffService/Diff":           policy.EntrypointServiceDiffRequest,
		"/deputy.secrets.v1.SecretsService/Scan":     policy.EntrypointServiceSecretsRequest,
		"/deputy.graph.v1.GraphService/Resolve":      policy.EntrypointServiceGraphRequest,
		"/deputy.graph.v1.GraphService/Why":          policy.EntrypointServiceGraphRequest,
	}

	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			procedure := req.Spec().Procedure

			// Get the entrypoint for this procedure
			entrypoint, ok := procedureToEntrypoint[procedure]
			if !ok {
				// No policy entrypoint for this procedure, allow by default
				return next(ctx, req)
			}

			// Build the policy payload
			payload := buildPolicyPayload(ctx, req, entrypoint)

			// Evaluate policies
			actions, err := policy.EvaluateAll(ctx, policies, payload)
			if err != nil {
				logs.Error(ctx, "policy evaluation failed",
					"procedure", procedure,
					"entrypoint", entrypoint,
					"error", err,
				)
				// On policy error, fail closed (deny)
				return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("policy evaluation error"))
			}

			// Check for deny actions
			for _, action := range actions {
				if policy.ActionTypeIs(action.Type, policy.ActionDeny) {
					logs.Warn(ctx, "request denied by policy",
						"procedure", procedure,
						"entrypoint", entrypoint,
						"policy", action.Source,
						"reason", action.Reason,
					)
					code := connect.CodePermissionDenied
					if action.Status != nil {
						switch *action.Status {
						case 401:
							code = connect.CodeUnauthenticated
						case 403:
							code = connect.CodePermissionDenied
						case 400:
							code = connect.CodeInvalidArgument
						}
					}
					msg := action.Reason
					if msg == "" {
						msg = "denied by policy"
					}
					return nil, connect.NewError(code, fmt.Errorf("%s", msg))
				}
			}

			// Log warnings but allow the request
			for _, action := range actions {
				if policy.ActionTypeIs(action.Type, policy.ActionWarn) {
					logs.Warn(ctx, "policy warning",
						"procedure", procedure,
						"entrypoint", entrypoint,
						"policy", action.Source,
						"reason", action.Reason,
					)
				}
			}

			return next(ctx, req)
		}
	}
}

// buildPolicyPayload constructs the payload map for policy evaluation.
// It includes JWT claims, request metadata, target info, and env context.
func buildPolicyPayload(ctx context.Context, req connect.AnyRequest, entrypoint policy.Entrypoint) map[string]any {
	payload := make(map[string]any)

	// Add env context
	payload["env"] = map[string]any{
		"command":    "server",
		"entrypoint": entrypoint.String(),
	}

	// Add JWT claims if present (from authn middleware)
	if claims := jwt.ClaimsFromAuthn(ctx); claims != nil {
		payload["jwt"] = claims.ToMap()
	} else {
		payload["jwt"] = jwt.AnonymousClaims()
	}

	// Add request metadata
	// The request object contains information about what operation is being requested
	requestInfo := map[string]any{
		"procedure": req.Spec().Procedure,
	}

	// Try to extract target from the request message
	// This is a best-effort extraction from protobuf messages
	if msg := req.Any(); msg != nil {
		if target := extractTargetFromMessage(msg); target != "" {
			requestInfo["target"] = target
			payload["target"] = map[string]any{
				"display": target,
			}
		}
	}

	payload["request"] = requestInfo

	return payload
}

// extractTargetFromMessage attempts to extract the target field from request messages.
// This uses type assertions for known request types with GetTarget/GetPath methods.
func extractTargetFromMessage(msg any) string {
	// Check for Target field (most scan/list/sbom requests)
	if m, ok := msg.(interface{ GetTarget() string }); ok {
		return m.GetTarget()
	}

	// Check for BaseTarget (diff requests)
	if m, ok := msg.(interface{ GetBaseTarget() string }); ok {
		if base := m.GetBaseTarget(); base != "" {
			return base
		}
	}

	// Check for Path (secrets requests)
	if m, ok := msg.(interface{ GetPath() string }); ok {
		return m.GetPath()
	}

	return ""
}

