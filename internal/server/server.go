package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"connectrpc.com/otelconnect"
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
	"github.com/picatz/deputy/internal/logs"
	"github.com/picatz/deputy/internal/otel"
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

// AuthConfig configures authentication.
type AuthConfig struct {
	// Enabled turns authentication on/off.
	Enabled bool

	// JWKSURL is the URL to fetch JSON Web Key Sets.
	JWKSURL string

	// Issuers is a list of allowed token issuers.
	Issuers []string

	// Audiences is a list of allowed token audiences.
	Audiences []string
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
	config     Config
	httpServer *http.Server
	mux        *http.ServeMux
}

// New creates a new Deputy server with the given configuration.
func New(cfg Config) *Server {
	applyDefaults(&cfg)

	mux := http.NewServeMux()

	// Build middleware chain
	var handler http.Handler = mux

	// Add CORS middleware if configured
	if cfg.CORS != nil {
		handler = corsMiddleware(cfg.CORS)(handler)
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

	// Create Connect interceptors
	otelInterceptor, _ := otelconnect.NewInterceptor()
	interceptors := []connect.Interceptor{
		otelInterceptor,
		loggingInterceptor(),
		recoveryInterceptor(),
	}

	// Add auth interceptor if configured
	if cfg.Auth != nil && cfg.Auth.Enabled {
		interceptors = append(interceptors, authInterceptor(cfg.Auth))
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
		config:     cfg,
		httpServer: httpServer,
		mux:        mux,
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
func (s *Server) Handler() http.Handler {
	return s.mux
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
func corsMiddleware(cfg *CORSConfig) func(http.Handler) http.Handler {
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

				if len(cfg.ExposedHeaders) > 0 {
					w.Header().Set("Access-Control-Expose-Headers", strings.Join(cfg.ExposedHeaders, ", "))
				}
			}

			// Handle preflight requests
			if r.Method == http.MethodOptions {
				if len(cfg.AllowedMethods) > 0 {
					w.Header().Set("Access-Control-Allow-Methods", strings.Join(cfg.AllowedMethods, ", "))
				}
				if len(cfg.AllowedHeaders) > 0 {
					w.Header().Set("Access-Control-Allow-Headers", strings.Join(cfg.AllowedHeaders, ", "))
				}
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
func rateLimitMiddleware(cfg *RateLimitConfig) func(http.Handler) http.Handler {
	// Per-client rate limiters
	var (
		mu       sync.Mutex
		limiters = make(map[string]*rate.Limiter)
	)

	getLimiter := func(key string) *rate.Limiter {
		mu.Lock()
		defer mu.Unlock()

		limiter, exists := limiters[key]
		if !exists {
			limiter = rate.NewLimiter(rate.Limit(cfg.RequestsPerSecond), cfg.Burst)
			limiters[key] = limiter
		}
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

// authInterceptor validates JWT tokens.
func authInterceptor(cfg *AuthConfig) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			// Skip auth for health endpoints (handled at HTTP level)
			procedure := req.Spec().Procedure

			// Get authorization header
			authHeader := req.Header().Get("Authorization")
			if authHeader == "" {
				return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("missing authorization header"))
			}

			// Extract token
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
				return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("invalid authorization header format"))
			}
			token := parts[1]

			// TODO: Validate JWT token against JWKS
			// For now, just check that a token exists
			if token == "" {
				return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("empty token"))
			}

			logs.Debug(ctx, "request authenticated", "procedure", procedure)

			return next(ctx, req)
		}
	}
}
