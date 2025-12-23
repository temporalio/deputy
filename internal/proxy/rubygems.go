package proxy

import (
	"net/http"
	"path"
	"strings"
)

// rubyGemsHandler proxies requests to a RubyGems registry (e.g., rubygems.org)
// while evaluating policy rules and enriching requests with vulnerability data.
type rubyGemsHandler struct {
	*baseHandler
}

// newRubyGemsHandler creates a handler for proxying RubyGems registry requests.
// It configures vulnerability lookups against the "RubyGems" ecosystem in OSV.
func newRubyGemsHandler(upstream string, policies PolicyEvaluator) (*rubyGemsHandler, error) {
	base, err := newBaseHandler(handlerConfig{
		ecosystem:    "rubygems",
		osvEcosystem: "RubyGems",
		upstream:     upstream,
		policies:     policies,
		wantLicenses: false,
	})
	if err != nil {
		return nil, err
	}
	return &rubyGemsHandler{baseHandler: base}, nil
}

// ServeHTTP handles incoming RubyGems registry requests, parsing the path to extract
// gem name, version, and operation type, then evaluating policies before proxying.
func (h *rubyGemsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	name, version, operation := parseRubyGemsPath(r.URL.Path)

	h.serveRequest(w, r, "rubygems_artifact_request", requestInfo{
		Name:       name,
		Version:    version,
		HasVersion: hasVersion(version),
		Operation:  operation,
		Ecosystem:  "rubygems",
	})
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

// NewRubyGemsHandler exposes the RubyGems proxy handler for embedding in
// other HTTP servers.
func NewRubyGemsHandler(upstream string, policies PolicyEvaluator) (http.Handler, error) {
	return newRubyGemsHandler(upstream, policies)
}
