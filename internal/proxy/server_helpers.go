package proxy

import (
	"fmt"
	"net/http"
	"time"
)

// resolveTimeout returns the configured timeout or the default if not set.
func resolveTimeout(configured, defaultVal time.Duration) time.Duration {
	if configured > 0 {
		return configured
	}
	return defaultVal
}

// listenerTimeouts holds resolved timeout values for an HTTP server.
type listenerTimeouts struct {
	ReadHeader time.Duration
	Write      time.Duration
	Idle       time.Duration
}

// resolveListenerTimeouts extracts and resolves timeouts from listener config.
func resolveListenerTimeouts(cfg ListenerConfig) listenerTimeouts {
	return listenerTimeouts{
		ReadHeader: resolveTimeout(cfg.ReadHeaderTimeout, proxyReadHeaderTimeout),
		Write:      resolveTimeout(cfg.WriteTimeout, proxyWriteTimeout),
		Idle:       resolveTimeout(cfg.IdleTimeout, proxyIdleTimeout),
	}
}

// createEcosystemHandler creates a handler for the specified ecosystem.
// Returns an error with consistent context including the listener name.
func createEcosystemHandler(listenerName, ecoName, upstream string, policies PolicyEvaluator) (http.Handler, error) {
	handler, err := NewHandlerFromString(ecoName, upstream, policies)
	if err != nil {
		return nil, fmt.Errorf("listener %s: %w", listenerName, err)
	}
	return handler, nil
}
