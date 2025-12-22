package proxy

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"

	analysis "github.com/picatz/deputy/internal/analysis"
)

// baseHandler contains the common fields and initialization logic shared by all
// ecosystem-specific proxy handlers.
type baseHandler struct {
	policies PolicyEvaluator
	proxy    *httputil.ReverseProxy
	lookups  handlerLookups
}

// handlerConfig specifies how to initialize a baseHandler for a specific ecosystem.
type handlerConfig struct {
	ecosystem     string
	osvEcosystem  string // OSV ecosystem name (e.g., "Go", "npm", "PyPI", "RubyGems")
	upstream      string
	policies      PolicyEvaluator
	wantLicenses  bool
}

// newBaseHandler creates a baseHandler with the common initialization logic.
func newBaseHandler(cfg handlerConfig) (*baseHandler, error) {
	u, err := url.Parse(cfg.upstream)
	if err != nil {
		return nil, fmt.Errorf("parse upstream %q: %w", cfg.upstream, err)
	}
	client := newUpstreamHTTPClient()
	osvClient := analysis.NewOSVClient()

	h := &baseHandler{
		policies: cfg.policies,
		proxy:    newUpstreamReverseProxy(u, cfg.ecosystem, client.Transport),
		lookups: handlerLookups{
			osvClient: osvClient,
			vulnLookup: func(ctx context.Context, name, version string) ([]analysis.Vulnerability, error) {
				return cachedOSVLookup(ctx, osvClient, cfg.osvEcosystem, name, version)
			},
		},
	}
	if cfg.wantLicenses {
		h.lookups.licenseLookup = func(ctx context.Context, name, version string) ([]string, error) {
			return cachedLicenseLookup(ctx, cfg.ecosystem, name, version)
		}
	}
	return h, nil
}

// requestInfo holds parsed information from an incoming proxy request.
type requestInfo struct {
	Name       string
	Version    string
	HasVersion bool
	Operation  string
	Ecosystem  string
	FileType   string // optional, used by Go proxy
	Filename   string // optional, used by PyPI
}

// buildPayload constructs the policy evaluation payload from request info.
// The payload includes request metadata and optionally vulnerability/license data.
func (h *baseHandler) buildPayload(ctx context.Context, info requestInfo, path string) map[string]any {
	version := info.Version
	rawVersion := info.Version
	if !info.HasVersion {
		version = unknownVersionPlaceholder
	}

	reqMap := map[string]any{
		"ecosystem":   info.Ecosystem,
		"version":     version,
		"has_version": info.HasVersion,
		"operation":   info.Operation,
		"path":        path,
	}

	// Set raw_version appropriately
	if info.HasVersion {
		reqMap["raw_version"] = rawVersion
	} else {
		reqMap["raw_version"] = ""
	}

	// Use "module" for Go, "package" for others
	if info.Ecosystem == "go" {
		reqMap["module"] = info.Name
	} else {
		reqMap["package"] = info.Name
	}

	// Add optional fields
	if info.FileType != "" {
		reqMap["fileType"] = info.FileType
	}
	if info.Filename != "" {
		reqMap["filename"] = info.Filename
	}

	payload := map[string]any{"request": reqMap}

	// Add JWT claims to payload for policy evaluation
	if claims := JWTClaimsFromContext(ctx); claims != nil {
		payload["jwt"] = claims.ToMap()
	} else {
		payload["jwt"] = AnonymousClaims()
	}

	// Add vulnerability and license data if version is known
	if info.HasVersion {
		if vulnMaps := vulnerabilitiesToMaps(ctx, h.lookups, info.Ecosystem, info.Name, rawVersion); len(vulnMaps) > 0 {
			payload["vulnerabilities"] = vulnMaps
		}
		if licenses := lookupLicenses(ctx, h.lookups, info.Name, rawVersion); len(licenses) > 0 {
			payload["licenses"] = licenses
			reqMap["licenses"] = licenses
		}
	}

	return payload
}

// serve handles the common pattern of policy evaluation and proxying.
func (h *baseHandler) serve(w http.ResponseWriter, r *http.Request, policyName string, info requestInfo, payload map[string]any) {
	rawVersion := info.Version
	if !info.HasVersion {
		rawVersion = ""
	}
	serveWithPolicy(w, r, h.policies, policyName, payload, blockMeta{
		Ecosystem: info.Ecosystem,
		Name:      info.Name,
		Version:   rawVersion,
		Operation: info.Operation,
	}, h.proxy)
}
