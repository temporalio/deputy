package proxy

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	analysis "github.com/picatz/deputy/internal/analysis"
	"github.com/picatz/deputy/internal/policy"
	"osv.dev/bindings/go/osvdev"
)

type npmHandler struct {
	upstream      *url.URL
	policies      PolicyEvaluator
	client        *http.Client
	osvClient     analysis.OSVClient
	vulnLookup    func(context.Context, string, string) ([]analysis.Vulnerability, error)
	licenseLookup func(context.Context, string, string) ([]string, error)
}

func newNPMHandler(upstream string, policies PolicyEvaluator) (*npmHandler, error) {
	u, err := url.Parse(upstream)
	if err != nil {
		return nil, fmt.Errorf("parse upstream %q: %w", upstream, err)
	}
	return &npmHandler{
		upstream: u,
		policies: policies,
		client: &http.Client{
			Timeout: 45 * time.Second,
		},
		osvClient: osvdev.DefaultClient(),
	}, nil
}

func (h *npmHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pkg, version, operation := parseNPMPath(r.URL.Path)
	payload := map[string]any{
		"request": map[string]any{
			"ecosystem": "npm",
			"package":   pkg,
			"version":   version,
			"operation": operation,
			"path":      r.URL.Path,
		},
	}
	if version != "" {
		if vulnMaps := h.vulnerabilityPayload(ctx, pkg, version); len(vulnMaps) > 0 {
			payload["vulnerabilities"] = vulnMaps
		}
		if licenses := h.licensePayload(ctx, pkg, version); len(licenses) > 0 {
			payload["licenses"] = licenses
			if req, ok := payload["request"].(map[string]any); ok {
				req["licenses"] = licenses
			}
		}
	}

	var actions []policy.Action
	var err error
	if h.policies != nil {
		actions, err = h.policies.Evaluate(ctx, "npm_artifact_request", payload)
		if err != nil {
			http.Error(w, "policy evaluation failed", http.StatusInternalServerError)
			slog.Error("policy evaluation failed", "error", err)
			return
		}
	}
	deny, warns, hdrs := summarizeActions(actions)
	for k, v := range hdrs {
		w.Header().Set(k, v)
	}
	for _, warn := range warns {
		slog.Warn("policy warning", "source", warn.Source, "reason", warn.Reason)
	}
	if deny != nil {
		applyPolicyHeaders(w, deny, blockMeta{
			Ecosystem: "npm",
			Name:      pkg,
			Version:   version,
			Operation: operation,
		})
		status := statusFromAction(deny, http.StatusForbidden)
		http.Error(w, deny.Reason, status)
		slog.Info("request denied", "package", pkg, "version", version, "reason", deny.Reason)
		return
	}

	upstreamURL := *h.upstream
	upstreamURL.Path = strings.TrimSuffix(upstreamURL.Path, "/") + r.URL.Path
	upstreamURL.RawQuery = r.URL.RawQuery
	req, err := http.NewRequestWithContext(ctx, r.Method, upstreamURL.String(), r.Body)
	if err != nil {
		http.Error(w, "failed to build upstream request", http.StatusBadGateway)
		return
	}
	if r.ContentLength >= 0 {
		req.ContentLength = r.ContentLength
	}
	req.Header = r.Header.Clone()
	resp, err := h.client.Do(req)
	if err != nil {
		http.Error(w, "upstream fetch failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		slog.Warn("failed to stream upstream response", "error", err)
	}
}

func (h *npmHandler) vulnerabilityPayload(ctx context.Context, pkg, version string) []map[string]any {
	var vulns []analysis.Vulnerability
	var err error
	switch {
	case h == nil:
		return nil
	case h.vulnLookup != nil:
		vulns, err = h.vulnLookup(ctx, pkg, version)
	case h.osvClient != nil:
		inputs := []analysis.PkgInput{{
			Name:      pkg,
			Version:   version,
			Ecosystem: "npm",
		}}
		vulns, err = analysis.QueryOSVBatch(ctx, h.osvClient, inputs)
	default:
		return nil
	}
	if err != nil {
		slog.Warn("osv lookup failed", "package", pkg, "version", version, "error", err)
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

func (h *npmHandler) licensePayload(ctx context.Context, pkg, version string) []string {
	if h == nil || h.licenseLookup == nil {
		return nil
	}
	licenses, err := h.licenseLookup(ctx, pkg, version)
	if err != nil {
		slog.Warn("license lookup failed", "package", pkg, "version", version, "error", err)
		return nil
	}
	return licenses
}

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
