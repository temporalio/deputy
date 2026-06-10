package proxy

import (
	"net/http"
	"path"
	"strings"

	"github.com/temporalio/deputy/internal/ecosystem"
)

// NewNPMHandler creates an npm proxy handler using the unified handler factory.
// It proxies requests to an npm registry (e.g., registry.npmjs.org) while
// evaluating policy rules and enriching requests with vulnerability data.
func NewNPMHandler(upstream string, policies PolicyEvaluator) (http.Handler, error) {
	return DefaultFactory.CreateHandler(ecosystem.NPM, upstream, policies)
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
	if after, ok := strings.CutPrefix(trimmed, "-/package/"); ok {
		rem := after
		if before, ok := strings.CutSuffix(rem, "/dist-tags"); ok {
			pkg = before
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
