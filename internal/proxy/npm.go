package proxy

import (
	"net/http"
	"path"
	"strings"
)

// npmHandler proxies requests to an npm registry (e.g., registry.npmjs.org)
// while evaluating policy rules and enriching requests with vulnerability data.
type npmHandler struct {
	*baseHandler
}

// newNPMHandler creates a handler for proxying npm registry requests.
// It configures vulnerability lookups against the "npm" ecosystem in OSV.
func newNPMHandler(upstream string, policies PolicyEvaluator) (*npmHandler, error) {
	base, err := newBaseHandler(handlerConfig{
		ecosystem:    "npm",
		osvEcosystem: "npm",
		upstream:     upstream,
		policies:     policies,
		wantLicenses: false,
	})
	if err != nil {
		return nil, err
	}
	return &npmHandler{baseHandler: base}, nil
}

// ServeHTTP handles incoming npm registry requests, parsing the path to extract
// package name, version, and operation type, then evaluating policies before proxying.
func (h *npmHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	pkg, version, operation := parseNPMPath(r.URL.Path)

	h.serveRequest(w, r, "npm_artifact_request", requestInfo{
		Name:       pkg,
		Version:    version,
		HasVersion: hasVersion(version),
		Operation:  operation,
		Ecosystem:  "npm",
	})
}

// parseNPMPath extracts package name, version, and operation from an npm registry
// URL path. Supported path formats include:
//   - /<package>                  - package metadata
//   - /<package>/-/<package>-<version>.tgz - tarball download
//   - -/package/<package>/dist-tags - dist-tags lookup
//   - -/<service>                 - registry service endpoints
func parseNPMPath(p string) (pkg string, version string, operation string) {
	trimmed := strings.Trim(p, "/")
	if trimmed == "" {
		return "", "", "metadata"
	}
	if strings.HasPrefix(trimmed, "-/package/") {
		rem := strings.TrimPrefix(trimmed, "-/package/")
		if strings.HasSuffix(rem, "/dist-tags") {
			pkg = strings.TrimSuffix(rem, "/dist-tags")
			operation = "dist-tags"
			return
		}
		parts := strings.Split(rem, "/")
		if len(parts) > 0 {
			pkg = parts[0]
		}
		operation = "metadata"
		return
	}
	if strings.HasSuffix(trimmed, ".tgz") {
		operation = "download"
		segments := strings.Split(trimmed, "/-/")
		if len(segments) >= 2 {
			pkg = segments[0]
			file := segments[1]
			base := strings.TrimSuffix(path.Base(file), ".tgz")
			if idx := strings.LastIndex(base, "-"); idx > 0 {
				version = base[idx+1:]
			}
		}
		return
	}
	if strings.HasPrefix(trimmed, "-/") {
		operation = "service"
		return "", "", operation
	}
	operation = "metadata"
	return trimmed, "", operation
}

// NewNPMHandler exposes the npm proxy handler for embedding in other servers.
func NewNPMHandler(upstream string, policies PolicyEvaluator) (http.Handler, error) {
	return newNPMHandler(upstream, policies)
}
