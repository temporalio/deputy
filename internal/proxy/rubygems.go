package proxy

import (
	"net/http"
	"path"
	"strings"

	"github.com/temporalio/deputy/internal/ecosystem"
)

// NewRubyGemsHandler creates a RubyGems proxy handler using the unified handler factory.
// It proxies requests to a RubyGems registry (e.g., rubygems.org) while evaluating
// policy rules and enriching requests with vulnerability data.
func NewRubyGemsHandler(upstream string, policies PolicyEvaluator) (http.Handler, error) {
	return DefaultFactory.CreateHandler(ecosystem.RubyGems, upstream, policies)
}

// parseRubyGemsPath extracts gem name, version, and operation from a RubyGems
// registry URL path. Supported path formats include:
//   - /gems/<name>-<version>.gem  - gem download
//   - /api/v1/gems/<name>.json    - gem metadata API
//   - /<path>                     - other metadata requests
func parseRubyGemsPath(p string) (name string, version string, operation string) {
	trim := strings.Trim(p, "/")
	if trim == "" {
		return "", "", "metadata"
	}
	if strings.HasSuffix(trim, ".gem") {
		operation = "download"
		file := path.Base(trim)
		base := strings.TrimSuffix(file, ".gem")
		if idx := strings.LastIndex(base, "-"); idx > 0 {
			name = base[:idx]
			version = base[idx+1:]
		}
		return
	}
	if strings.HasPrefix(trim, "api/") {
		operation = "api"
		parts := strings.Split(trim, "/")
		if len(parts) >= 4 && parts[2] == "gems" {
			name = strings.TrimSuffix(parts[3], ".json")
		}
		return
	}
	operation = "metadata"
	return trim, "", operation
}
