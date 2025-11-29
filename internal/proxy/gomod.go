package proxy

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	analysis "github.com/picatz/deputy/internal/analysis"
	"github.com/picatz/deputy/internal/policy"
	"osv.dev/bindings/go/osvdev"
)

type goModuleHandler struct {
	upstream      *url.URL
	policies      PolicyEvaluator
	client        *http.Client
	osvClient     analysis.OSVClient
	vulnLookup    func(context.Context, string, string) ([]analysis.Vulnerability, error)
	licenseLookup func(context.Context, string, string) ([]string, error)
}

func newGoModuleHandler(upstream string, policies PolicyEvaluator) (*goModuleHandler, error) {
	u, err := url.Parse(upstream)
	if err != nil {
		return nil, fmt.Errorf("parse upstream %q: %w", upstream, err)
	}
	return &goModuleHandler{
		upstream: u,
		policies: policies,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		osvClient: osvdev.DefaultClient(),
	}, nil
}

func (h *goModuleHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	module, version, fileType, op, err := parseGoProxyPath(r.URL.Path)
	if err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}

	payload := map[string]any{
		"request": map[string]any{
			"ecosystem": "go",
			"module":    module,
			"version":   version,
			"fileType":  fileType,
			"operation": op,
			"path":      r.URL.Path,
		},
	}
	if version != "" {
		if vulnMaps := h.vulnerabilityPayload(ctx, module, version); len(vulnMaps) > 0 {
			payload["vulnerabilities"] = vulnMaps
		}
		if licenses := h.licensePayload(ctx, module, version); len(licenses) > 0 {
			payload["licenses"] = licenses
			if req, ok := payload["request"].(map[string]any); ok {
				req["licenses"] = licenses
			}
		}
	}
	var actions []policy.Action
	if h.policies != nil {
		actions, err = h.policies.Evaluate(ctx, "go_artifact_request", payload)
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
		status := statusFromAction(deny, http.StatusForbidden)
		http.Error(w, deny.Reason, status)
		slog.Info("request denied", "module", module, "version", version, "reason", deny.Reason)
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

func copyHeaders(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func (h *goModuleHandler) vulnerabilityPayload(ctx context.Context, module, version string) []map[string]any {
	var vulns []analysis.Vulnerability
	var err error
	switch {
	case h == nil:
		return nil
	case h.vulnLookup != nil:
		vulns, err = h.vulnLookup(ctx, module, version)
	case h.osvClient != nil:
		inputs := []analysis.PkgInput{{
			Name:      module,
			Version:   version,
			Ecosystem: "Go",
		}}
		vulns, err = analysis.QueryOSVBatch(ctx, h.osvClient, inputs)
	default:
		return nil
	}
	if err != nil {
		slog.Warn("osv lookup failed", "module", module, "version", version, "error", err)
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

func (h *goModuleHandler) licensePayload(ctx context.Context, module, version string) []string {
	if h == nil || h.licenseLookup == nil {
		return nil
	}
	licenses, err := h.licenseLookup(ctx, module, version)
	if err != nil {
		slog.Warn("license lookup failed", "module", module, "version", version, "error", err)
		return nil
	}
	return licenses
}

func parseGoProxyPath(p string) (module, version, fileType, operation string, err error) {
	if !strings.HasPrefix(p, "/") {
		err = fmt.Errorf("path must start with /")
		return
	}
	parts := strings.Split(p, "/@v/")
	if len(parts) != 2 {
		err = fmt.Errorf("path missing /@v segment")
		return
	}
	module = strings.TrimPrefix(parts[0], "/")
	if module == "" {
		err = fmt.Errorf("module path empty")
		return
	}
	rem := parts[1]
	switch {
	case rem == "list":
		operation = "list"
		fileType = ".list"
	case strings.HasSuffix(rem, ".info"):
		version = strings.TrimSuffix(rem, ".info")
		fileType = ".info"
	case strings.HasSuffix(rem, ".mod"):
		version = strings.TrimSuffix(rem, ".mod")
		fileType = ".mod"
	case strings.HasSuffix(rem, ".zip"):
		version = strings.TrimSuffix(rem, ".zip")
		fileType = ".zip"
	default:
		err = fmt.Errorf("unknown go proxy suffix: %s", rem)
	}
	if operation == "" {
		operation = "fetch"
	}
	return
}

// NewGoModuleHandler exposes the Go module proxy handler for reuse outside the
// proxy server when an in-process HTTP handler is sufficient.
func NewGoModuleHandler(upstream string, policies PolicyEvaluator) (http.Handler, error) {
	return newGoModuleHandler(upstream, policies)
}
