package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"
)

// Options customize server behavior from CLI flags.
type Options struct {
	PolicyPaths []string
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

	server := &http.Server{
		Addr:    cfg.Bind,
		Handler: handler,
	}
	shutdownErr := make(chan error, 1)
	var once sync.Once
	go func() {
		<-ctx.Done()
		once.Do(func() {
			shutdownErr <- server.Shutdown(context.Background())
		})
	}()

	slog.Info("proxy listener starting", "name", cfg.Name, "addr", cfg.Bind, "ecosystem", ecos, "upstream", cfg.Upstream)
	err = server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	once.Do(func() {
		shutdownErr <- err
	})
	return <-shutdownErr
}
