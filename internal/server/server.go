package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"connectrpc.com/authn"
	"connectrpc.com/connect"
	"connectrpc.com/cors"
	"connectrpc.com/otelconnect"
	"connectrpc.com/validate"
	"golang.org/x/time/rate"

	"github.com/temporalio/deputy/gen/deputy/diff/v1/diffv1connect"
	"github.com/temporalio/deputy/gen/deputy/graph/v1/graphv1connect"
	"github.com/temporalio/deputy/gen/deputy/list/v1/listv1connect"
	policyv1 "github.com/temporalio/deputy/gen/deputy/policy/v1"
	"github.com/temporalio/deputy/gen/deputy/remediation/v1/remediationv1connect"
	"github.com/temporalio/deputy/gen/deputy/sbom/v1/sbomv1connect"
	"github.com/temporalio/deputy/gen/deputy/scan/v1/scanv1connect"
	"github.com/temporalio/deputy/gen/deputy/secrets/v1/secretsv1connect"
	targetv1 "github.com/temporalio/deputy/gen/deputy/target/v1"
	"github.com/temporalio/deputy/internal/auth/jwt"
	"github.com/temporalio/deputy/internal/cache/memory"
	"github.com/temporalio/deputy/internal/gitutil"
	"github.com/temporalio/deputy/internal/logs"
	"github.com/temporalio/deputy/internal/network"
	"github.com/temporalio/deputy/internal/otel"
	"github.com/temporalio/deputy/internal/policy"
	"github.com/temporalio/deputy/internal/targets"
	"google.golang.org/protobuf/proto"
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

	// Security configures explicit security overrides and public binding behavior.
	Security *SecurityConfig

	// Egress configures outbound network allowlists for remote server mode.
	Egress *EgressConfig
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

	// Deprecated: Use Mode="required" or Mode="disabled" instead.
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

	// TrustXFF enables trusting X-Forwarded-For header from all sources.
	// WARNING: Only enable this if ALL traffic goes through a trusted proxy.
	// Default: false (XFF headers are ignored to prevent spoofing).
	TrustXFF bool

	// TrustedProxies is a list of IP addresses or CIDR ranges that are trusted
	// to provide accurate X-Forwarded-For headers.
	// Example: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.1"]
	// If empty and TrustXFF is false, X-Forwarded-For is never trusted.
	TrustedProxies []string
}

// SecurityConfig controls explicit opt-ins for unsafe server modes.
type SecurityConfig struct {
	// AllowPublic permits binding to non-loopback addresses (e.g., 0.0.0.0).
	// This must be explicitly enabled for remote server deployments.
	AllowPublic bool

	// AllowInsecure permits starting the server without TLS/auth safeguards
	// or when configuration validation fails (e.g., policy load errors).
	// This should only be used for local development.
	AllowInsecure bool
}

// EgressConfig restricts outbound access for remote server mode.
// Use allowlists to permit internal registries or SCM safely.
type EgressConfig struct {
	// AllowedHosts is a list of hostnames allowed to resolve to private IPs.
	// Entries may be exact hosts or suffixes prefixed with a dot (e.g., ".corp.local").
	AllowedHosts []string

	// AllowedCIDRs is a list of CIDR ranges allowed for outbound connections.
	AllowedCIDRs []string

	// AllowSSH permits SSH-style git targets (ssh://, git@host:repo).
	AllowSSH bool

	// AllowLoopback permits loopback targets (127.0.0.1, ::1) for remote server mode.
	AllowLoopback bool

	// AllowLinkLocal permits link-local targets (169.254.0.0/16, fe80::/10).
	AllowLinkLocal bool
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Addr:                "127.0.0.1:8090",
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
	handler       http.Handler      // The fully wrapped handler with all middleware
	authenticator jwt.Authenticator // JWT authenticator (nil if auth disabled)
	policies      []policy.Source   // Loaded policy sources (nil if no policies)
	egressOptions []network.Option
}

// New creates a new Deputy server with the given configuration.
func New(cfg Config) (*Server, error) {
	applyDefaults(&cfg)
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	mux := http.NewServeMux()

	// Initialize JWT authenticator if auth is configured
	var authenticator jwt.Authenticator
	var authnMiddleware *authn.Middleware
	authMode, err := getAuthMode(cfg.Auth)
	if err != nil {
		return nil, err
	}

	if authMode != jwt.ModeDisabled {
		jwtConfig := buildJWTConfig(cfg.Auth)
		if jwtConfig != nil {
			auth, err := jwt.NewAuthenticator(jwtConfig)
			if err != nil {
				if allowInsecure(cfg) {
					logs.Warn(context.Background(), "authenticator setup failed; continuing without auth (insecure override)",
						"error", err,
					)
					authMode = jwt.ModeDisabled
				} else {
					return nil, fmt.Errorf("authenticator setup failed: %w", err)
				}
			}
			if authMode != jwt.ModeDisabled {
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
			if allowInsecure(cfg) {
				logs.Warn(context.Background(), "policy load failed; continuing without policies (insecure override)",
					"error", err,
					"paths", cfg.Policies,
				)
				policies = nil
			} else {
				return nil, fmt.Errorf("load policies: %w", err)
			}
		}
		if len(policies) > 0 {
			logs.Info(context.Background(), "loaded server policies",
				"count", len(policies),
				"paths", cfg.Policies,
			)
		}
	}

	targetPolicy, egressOptions, err := buildTargetPolicy(cfg)
	if err != nil {
		if allowInsecure(cfg) {
			logs.Warn(context.Background(), "egress policy configuration failed; continuing with defaults (insecure override)",
				"error", err,
			)
			targetPolicy = nil
			egressOptions = nil
		} else {
			return nil, err
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
	scanHandler := NewScanHandler(WithScanTargetPolicy(targetPolicy))
	sbomHandler := NewSBOMHandler(WithSBOMTargetPolicy(targetPolicy))
	listHandler := NewListHandler(WithListTargetPolicy(targetPolicy))
	remediationHandler := NewRemediationHandler()
	secretsHandler, _ := NewSecretsHandler(WithSecretsTargetPolicy(targetPolicy))
	diffHandler := NewDiffHandler(WithDiffTargetPolicy(targetPolicy))
	graphHandler := NewGraphHandler(WithGraphTargetPolicy(targetPolicy))

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

	httpServer := &http.Server{
		Addr:         cfg.Addr,
		Handler:      handler,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
	}

	// Configure TLS if provided
	if cfg.TLS != nil {
		tlsConfig, err := buildTLSConfig(cfg.TLS)
		if err != nil {
			return nil, err
		}
		httpServer.TLSConfig = tlsConfig
	} else {
		// Without TLS, enable HTTP/2 cleartext (h2c) natively via the
		// Protocols field rather than wrapping the handler in h2c.NewHandler.
		var protocols http.Protocols
		protocols.SetHTTP1(true)
		protocols.SetUnencryptedHTTP2(true)
		httpServer.Protocols = &protocols
	}

	return &Server{
		config:        cfg,
		httpServer:    httpServer,
		handler:       handler, // The wrapped handler with all middleware
		authenticator: authenticator,
		policies:      policies,
		egressOptions: egressOptions,
	}, nil
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

func allowInsecure(cfg Config) bool {
	if cfg.Security == nil {
		return false
	}
	return cfg.Security.AllowInsecure
}

func validateConfig(cfg Config) error {
	security := SecurityConfig{}
	if cfg.Security != nil {
		security = *cfg.Security
	}

	host, _, err := net.SplitHostPort(cfg.Addr)
	if err != nil {
		return fmt.Errorf("invalid server address %q: %w", cfg.Addr, err)
	}

	authMode, err := getAuthMode(cfg.Auth)
	if err != nil {
		return err
	}

	if !isLoopbackHost(host) {
		if !security.AllowPublic && !security.AllowInsecure {
			return fmt.Errorf("public bind %q requires security.allow_public or security.allow_insecure", cfg.Addr)
		}
		if !security.AllowInsecure {
			if cfg.TLS == nil {
				return fmt.Errorf("public bind %q requires TLS configuration", cfg.Addr)
			}
			if authMode != jwt.ModeRequired {
				return fmt.Errorf("public bind %q requires auth mode 'required'", cfg.Addr)
			}
		}
	}

	return nil
}

func buildTargetPolicy(cfg Config) (*targets.RemoteTargetPolicy, []network.Option, error) {
	if cfg.Egress == nil {
		return nil, nil, nil
	}

	allowedCIDRs, err := targets.ParseCIDRs(cfg.Egress.AllowedCIDRs)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid egress CIDR: %w", err)
	}

	policy := &targets.RemoteTargetPolicy{
		AllowedHosts:   cfg.Egress.AllowedHosts,
		AllowedCIDRs:   allowedCIDRs,
		AllowSSH:       cfg.Egress.AllowSSH,
		AllowLoopback:  cfg.Egress.AllowLoopback,
		AllowLinkLocal: cfg.Egress.AllowLinkLocal,
	}

	var opts []network.Option
	if len(cfg.Egress.AllowedHosts) > 0 {
		opts = append(opts, network.WithAllowedHosts(cfg.Egress.AllowedHosts...))
	}
	if len(allowedCIDRs) > 0 {
		opts = append(opts, network.WithAllowedCIDRs(allowedCIDRs...))
	}
	if cfg.Egress.AllowLoopback {
		opts = append(opts, network.WithAllowLoopback())
	}
	if cfg.Egress.AllowLinkLocal {
		opts = append(opts, network.WithAllowLinkLocal())
	}

	return policy, opts, nil
}

func isLoopbackHost(host string) bool {
	host = strings.TrimSpace(host)
	if host == "" {
		return false
	}
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
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

	// Load client CA certificate pool for mTLS
	if cfg.ClientCAFile != "" {
		caCert, err := os.ReadFile(cfg.ClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("reading client CA file: %w", err)
		}
		tlsConfig.ClientCAs = x509.NewCertPool()
		if !tlsConfig.ClientCAs.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse client CA certificate")
		}
	}

	return tlsConfig, nil
}

// getAuthMode returns the effective auth mode from config.
// For servers, we only support "required" or "disabled" (not "optional").
func getAuthMode(cfg *AuthConfig) (jwt.Mode, error) {
	if cfg == nil {
		return jwt.ModeDisabled, nil
	}

	// Handle deprecated Enabled field for backward compatibility
	if cfg.Enabled && cfg.Mode == "" {
		return jwt.ModeRequired, nil
	}

	switch strings.ToLower(cfg.Mode) {
	case "required":
		return jwt.ModeRequired, nil
	case "disabled", "":
		return jwt.ModeDisabled, nil
	default:
		return jwt.ModeDisabled, fmt.Errorf("unsupported auth mode %q (server supports 'required' or 'disabled')", cfg.Mode)
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
	s.applyEgressOptions()
	if s.config.TLS != nil {
		logs.Info(ctx, "starting Deputy server with TLS", "addr", s.config.Addr)
		return s.httpServer.ListenAndServeTLS(s.config.TLS.CertFile, s.config.TLS.KeyFile)
	}
	logs.Info(ctx, "starting Deputy server", "addr", s.config.Addr)
	return s.httpServer.ListenAndServe()
}

func (s *Server) applyEgressOptions() {
	network.SetDefaultSafeDialerOptions(s.egressOptions...)
	gitutil.InstallSafeGitTransport()
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

	// Parse trusted proxies once at middleware creation time
	trustedChecker := newTrustedProxyChecker(cfg.TrustedProxies)

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

			// Only trust X-Forwarded-For if:
			// 1. TrustXFF is explicitly enabled (trust all sources), OR
			// 2. The request comes from a trusted proxy IP
			if cfg.TrustXFF || trustedChecker.isTrusted(r.RemoteAddr) {
				if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
					// Use first IP in X-Forwarded-For chain (original client)
					if before, _, ok := strings.Cut(xff, ","); ok {
						clientIP = strings.TrimSpace(before)
					} else {
						clientIP = strings.TrimSpace(xff)
					}
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

// trustedProxyChecker validates whether a remote address is from a trusted proxy.
type trustedProxyChecker struct {
	ips   map[string]struct{}
	cidrs []*net.IPNet
}

// newTrustedProxyChecker creates a checker from a list of IP addresses and CIDR ranges.
// Invalid entries are logged and skipped.
func newTrustedProxyChecker(proxies []string) *trustedProxyChecker {
	checker := &trustedProxyChecker{
		ips:   make(map[string]struct{}),
		cidrs: make([]*net.IPNet, 0),
	}

	for _, proxy := range proxies {
		proxy = strings.TrimSpace(proxy)
		if proxy == "" {
			continue
		}

		// Try to parse as CIDR first
		if strings.Contains(proxy, "/") {
			_, ipNet, err := net.ParseCIDR(proxy)
			if err != nil {
				logs.Warn(context.Background(), "invalid trusted proxy CIDR, skipping",
					"cidr", proxy, "error", err)
				continue
			}
			checker.cidrs = append(checker.cidrs, ipNet)
		} else {
			// Parse as plain IP address
			ip := net.ParseIP(proxy)
			if ip == nil {
				logs.Warn(context.Background(), "invalid trusted proxy IP, skipping",
					"ip", proxy)
				continue
			}
			// Normalize IPv4-mapped IPv6 to IPv4
			if v4 := ip.To4(); v4 != nil {
				checker.ips[v4.String()] = struct{}{}
			} else {
				checker.ips[ip.String()] = struct{}{}
			}
		}
	}

	return checker
}

// isTrusted checks if the given remote address is from a trusted proxy.
// The remoteAddr is expected to be in "ip:port" or "[ip]:port" format.
func (c *trustedProxyChecker) isTrusted(remoteAddr string) bool {
	if len(c.ips) == 0 && len(c.cidrs) == 0 {
		return false
	}

	// Extract IP from "ip:port" or "[ip]:port" format
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		// Try parsing as plain IP (in case there's no port)
		host = remoteAddr
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	// Normalize IPv4-mapped IPv6 to IPv4
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}

	// Check exact IP match
	if _, ok := c.ips[ip.String()]; ok {
		return true
	}

	// Check CIDR ranges
	for _, cidr := range c.cidrs {
		if cidr.Contains(ip) {
			return true
		}
	}

	return false
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
func buildPolicyPayload(ctx context.Context, req connect.AnyRequest, entrypoint policy.Entrypoint) proto.Message {
	// Build common fields
	env := &policyv1.Environment{
		Command:    "server",
		Entrypoint: entrypoint.String(),
	}

	// Build JWT claims proto
	var jwtClaims *policyv1.JWTClaims
	if claims := jwt.ClaimsFromAuthn(ctx); claims != nil {
		jwtClaims = &policyv1.JWTClaims{
			Anonymous: false,
			Sub:       claims.Subject,
			Iss:       claims.Issuer,
			Aud:       claims.Audience,
			Exp:       claims.ExpiresAt,
			Iat:       claims.IssuedAt,
			Nbf:       claims.NotBefore,
			Jti:       claims.JWTID,
		}
		if len(claims.Custom) > 0 {
			jwtClaims.CustomClaims = make(map[string]string, len(claims.Custom))
			for k, v := range claims.Custom {
				jwtClaims.CustomClaims[k] = fmt.Sprint(v)
			}
		}
	} else {
		jwtClaims = &policyv1.JWTClaims{Anonymous: true}
	}

	// Build service request
	svcReq := &policyv1.ServiceRequest{
		Procedure: req.Spec().Procedure,
	}

	// Build target if extractable
	var target *targetv1.Target
	if msg := req.Any(); msg != nil {
		if targetStr := extractTargetFromMessage(msg); targetStr != "" {
			svcReq.Target = targetStr
			target = &targetv1.Target{
				DisplayPath: targetStr,
			}
		}
	}

	// Return the appropriate typed input based on entrypoint
	switch entrypoint {
	case policy.EntrypointServiceScanRequest:
		return &policyv1.ServiceScanRequestPolicyInput{
			Jwt:     jwtClaims,
			Request: svcReq,
			Target:  target,
			Env:     env,
		}
	case policy.EntrypointServiceListRequest:
		return &policyv1.ServiceListRequestPolicyInput{
			Jwt:     jwtClaims,
			Request: svcReq,
			Target:  target,
			Env:     env,
		}
	case policy.EntrypointServiceSBOMRequest:
		return &policyv1.ServiceSbomRequestPolicyInput{
			Jwt:     jwtClaims,
			Request: svcReq,
			Target:  target,
			Env:     env,
		}
	case policy.EntrypointServiceDiffRequest:
		// Diff has base_target and target_target instead of target
		return &policyv1.ServiceDiffRequestPolicyInput{
			Jwt:          jwtClaims,
			Request:      svcReq,
			BaseTarget:   target,
			TargetTarget: target,
			Env:          env,
		}
	case policy.EntrypointServiceSecretsRequest:
		return &policyv1.ServiceSecretsRequestPolicyInput{
			Jwt:     jwtClaims,
			Request: svcReq,
			Target:  target,
			Env:     env,
		}
	case policy.EntrypointServiceGraphRequest:
		return &policyv1.ServiceGraphRequestPolicyInput{
			Jwt:     jwtClaims,
			Request: svcReq,
			Target:  target,
			Env:     env,
		}
	default:
		// Fallback to scan request for unknown entrypoints
		return &policyv1.ServiceScanRequestPolicyInput{
			Jwt:     jwtClaims,
			Request: svcReq,
			Target:  target,
			Env:     env,
		}
	}
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
