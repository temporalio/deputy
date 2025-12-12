package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"

	analysis "github.com/picatz/deputy/internal/analysis"
	"github.com/picatz/deputy/internal/policy"
)

type rubyGemsHandler struct {
	policies      PolicyEvaluator
	proxy         *httputil.ReverseProxy
	osvClient     analysis.OSVClient
	vulnLookup    func(context.Context, string, string) ([]analysis.Vulnerability, error)
	licenseLookup func(context.Context, string, string) ([]string, error)
}

func newRubyGemsHandler(upstream string, policies PolicyEvaluator) (*rubyGemsHandler, error) {
	u, err := url.Parse(upstream)
	if err != nil {
		return nil, fmt.Errorf("parse upstream %q: %w", upstream, err)
	}
	client := newUpstreamHTTPClient()
	osvClient := analysis.NewOSVClient()
	return &rubyGemsHandler{
		policies:  policies,
		proxy:     newUpstreamReverseProxy(u, "rubygems", client.Transport),
		osvClient: osvClient,
		vulnLookup: func(ctx context.Context, name, version string) ([]analysis.Vulnerability, error) {
			return cachedOSVLookup(ctx, osvClient, "RubyGems", name, version)
		},
	}, nil
}

func (h *rubyGemsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name, version, operation := parseRubyGemsPath(r.URL.Path)
	hasVersion := strings.TrimSpace(version) != ""
	rawVersion := version
	if !hasVersion {
		version = unknownVersionPlaceholder
	}
	payload := map[string]any{
		"request": map[string]any{
			"ecosystem": "rubygems",
			"package":   name,
			"version":   version,
			"raw_version": func() string {
				if hasVersion {
					return rawVersion
				}
				return ""
			}(),
			"has_version": hasVersion,
			"operation":   operation,
			"path":        r.URL.Path,
		},
	}
	if hasVersion {
		if vulnMaps := h.vulnerabilityPayload(ctx, name, rawVersion); len(vulnMaps) > 0 {
			payload["vulnerabilities"] = vulnMaps
		}
		if licenses := h.licensePayload(ctx, name, rawVersion); len(licenses) > 0 {
			payload["licenses"] = licenses
			if req, ok := payload["request"].(map[string]any); ok {
				req["licenses"] = licenses
			}
		}
	}
	serveWithPolicy(w, r, h.policies, "rubygems_artifact_request", payload, blockMeta{
		Ecosystem: "rubygems",
		Name:      name,
		Version:   rawVersion,
		Operation: operation,
	}, h.proxy)
}

func (h *rubyGemsHandler) vulnerabilityPayload(ctx context.Context, name, version string) []map[string]any {
	var vulns []analysis.Vulnerability
	var err error
	switch {
	case h == nil:
		return nil
	case h.vulnLookup != nil:
		vulns, err = h.vulnLookup(ctx, name, version)
	case h.osvClient != nil:
		inputs := []analysis.PkgInput{{
			Name:      name,
			Version:   version,
			Ecosystem: "RubyGems",
		}}
		vulns, err = analysis.QueryOSVBatch(ctx, h.osvClient, inputs)
	default:
		return nil
	}
	if err != nil {
		slog.Warn("osv lookup failed", "package", name, "version", version, "error", err)
		return nil
	}
	if len(vulns) == 0 {
		return nil
	}
	var maps []map[string]any
	for _, v := range vulns {
		m, err := policy.StructToMap(v)
		if err != nil {
			slog.Debug("failed to map vulnerability", "id", v.ID, "error", err)
			continue
		}
		maps = append(maps, m)
	}
	return maps
}

func (h *rubyGemsHandler) licensePayload(ctx context.Context, name, version string) []string {
	if h == nil || h.licenseLookup == nil {
		return nil
	}
	licenses, err := h.licenseLookup(ctx, name, version)
	if err != nil {
		slog.Warn("license lookup failed", "package", name, "version", version, "error", err)
		return nil
	}
	return licenses
}

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
