package proxy

import (
	"context"
	"errors"
	"expvar"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"
)

const (
	proxyReadHeaderTimeout = 10 * time.Second
	proxyWriteTimeout      = 5 * time.Minute
	proxyIdleTimeout       = 2 * time.Minute
	proxyShutdownTimeout   = 10 * time.Second
	proxyMaxHeaderBytes    = 1 << 20 // 1 MiB
	proxyMaxRequestBody    = 1 << 20 // 1 MiB
)

// Options customize server behavior from CLI flags.
type Options struct {
	PolicyPaths  []string
	EnableReadyz bool
	EnablePprof  bool
	EnableVars   bool
}

// Server manages one or more listeners defined in the configuration.
type Server struct {
	cfg  Config
	opts Options
}

// NewServer creates a new proxy server instance with the provided configuration
// and options. It prepares the server to handle requests for configured listeners.
func NewServer(cfg Config, opts Options) *Server {
	return &Server{cfg: cfg, opts: opts}
}

// Serve starts all configured listeners and blocks until all of them exit or
// the context is canceled. It returns the first error encountered by any listener.
func (s *Server) Serve(ctx context.Context) error {
	group, ctx := errgroup.WithContext(ctx)
	for _, lst := range s.cfg.Listeners {
		listener := lst
		group.Go(func() error {
			return s.serveListener(ctx, listener)
		})
	}
	return group.Wait()
}

// serveListener initializes and runs a single listener for a specific ecosystem.
// It sets up the policy engine and HTTP handler for the listener.
func (s *Server) serveListener(ctx context.Context, cfg ListenerConfig) error {
	if len(cfg.Ecosystems) == 0 {
		return fmt.Errorf("listener %q has no ecosystems configured", cfg.Name)
	}
	ecos := strings.ToLower(cfg.Ecosystems[0])
	policyPaths := slices.Concat(cfg.Policies, s.opts.PolicyPaths)
	engine, err := NewPolicyEngine(policyPaths)
	if err != nil {
		return fmt.Errorf("listener %s: %w", cfg.Name, err)
	}

	var handler http.Handler
	switch ecos {
	case "go":
		h, err := newGoModuleHandler(cfg.Upstream, engine)
		if err != nil {
			return fmt.Errorf("listener %s: %w", cfg.Name, err)
		}
		handler = h
	case "pypi":
		h, err := newPyPIHandler(cfg.Upstream, engine)
		if err != nil {
			return fmt.Errorf("listener %s: %w", cfg.Name, err)
		}
		handler = h
	case "npm":
		h, err := newNPMHandler(cfg.Upstream, engine)
		if err != nil {
			return fmt.Errorf("listener %s: %w", cfg.Name, err)
		}
		handler = h
	case "rubygems":
		h, err := newRubyGemsHandler(cfg.Upstream, engine)
		if err != nil {
			return fmt.Errorf("listener %s: %w", cfg.Name, err)
		}
		handler = h
	default:
		return fmt.Errorf("listener %s: unsupported ecosystem %q", cfg.Name, ecos)
	}

	var ready atomic.Bool
	rootHandler := newListenerMux(cfg, s.opts, slog.Default(), cfg.Name, ecos, &ready, handler)

	ln, err := net.Listen("tcp", cfg.Bind)
	if err != nil {
		return err
	}
	addr := ln.Addr().String()

	slog.Info("proxy listener starting", "name", cfg.Name, "addr", addr, "ecosystem", ecos, "upstream", cfg.Upstream)

	readHeaderTimeout := cfg.ReadHeaderTimeout
	if readHeaderTimeout == 0 {
		readHeaderTimeout = proxyReadHeaderTimeout
	}
	writeTimeout := cfg.WriteTimeout
	if writeTimeout == 0 {
		writeTimeout = proxyWriteTimeout
	}
	idleTimeout := cfg.IdleTimeout
	if idleTimeout == 0 {
		idleTimeout = proxyIdleTimeout
	}

	server := &http.Server{
		Addr:              addr,
		Handler:           rootHandler,
		ReadHeaderTimeout: readHeaderTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    proxyMaxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(slog.Default().Handler(), slog.LevelError),
		BaseContext: func(_ net.Listener) context.Context {
			return ctx
		},
	}

	errCh := make(chan error, 1)
	go func() {
		ready.Store(true)
		errCh <- server.Serve(ln)
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), proxyShutdownTimeout)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
		err = <-errCh
	case err = <-errCh:
	}

	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func newListenerMux(cfg ListenerConfig, opts Options, logger *slog.Logger, name, ecosystem string, ready *atomic.Bool, handler http.Handler) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	skipLogPaths := map[string]bool{"/healthz": true}
	if opts.EnableReadyz {
		skipLogPaths["/readyz"] = true
	}
	if opts.EnablePprof || opts.EnableVars {
		skipLogPaths["/debug/vars"] = true
		skipLogPaths["/debug/pprof/"] = true
		skipLogPaths["/debug/pprof/cmdline"] = true
		skipLogPaths["/debug/pprof/profile"] = true
		skipLogPaths["/debug/pprof/symbol"] = true
		skipLogPaths["/debug/pprof/trace"] = true
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	if opts.EnableReadyz {
		mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
			if ready == nil || !ready.Load() {
				http.Error(w, "not ready", http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok\n"))
		})
	} else {
		mux.Handle("/readyz", http.NotFoundHandler())
	}
	if opts.EnableVars {
		registerProxyCacheVars()
		mux.Handle("/debug/vars", expvar.Handler())
	} else {
		mux.Handle("/debug/vars", http.NotFoundHandler())
	}
	if opts.EnablePprof {
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	} else {
		mux.Handle("/debug/pprof/", http.NotFoundHandler())
	}

	wrapped := handler
	wrapped = withConcurrencyLimit(cfg.MaxConcurrentRequests)(wrapped)
	wrapped = withRequestID("X-Request-ID")(wrapped)
	wrapped = withRequestLogging(logger, name, ecosystem, cfg.Upstream, skipLogPaths)(wrapped)
	mux.Handle("/", wrapped)

	rootHandler := http.Handler(mux)
	maxBody := cfg.MaxRequestBodyBytes
	if maxBody == 0 {
		maxBody = proxyMaxRequestBody
	}
	return withMaxRequestBodyBytes(maxBody)(rootHandler)
}
