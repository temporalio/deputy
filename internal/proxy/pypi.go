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

type pypiHandler struct {
	upstream      *url.URL
	policies      PolicyEvaluator
	client        *http.Client
	osvClient     analysis.OSVClient
	vulnLookup    func(context.Context, string, string) ([]analysis.Vulnerability, error)
	licenseLookup func(context.Context, string, string) ([]string, error)
}

func newPyPIHandler(upstream string, policies PolicyEvaluator) (*pypiHandler, error) {
	u, err := url.Parse(upstream)
	if err != nil {
		return nil, fmt.Errorf("parse upstream %q: %w", upstream, err)
	}
	return &pypiHandler{
		upstream: u,
		policies: policies,
		client: &http.Client{
			Timeout: 45 * time.Second,
		},
		osvClient: osvdev.DefaultClient(),
	}, nil
}

func (h *pypiHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pkg, version, filename, op := parsePyPIPath(r.URL.Path)
	hasVersion := strings.TrimSpace(version) != ""
	rawVersion := version
	if !hasVersion {
		version = unknownVersionPlaceholder
	}
	payload := map[string]any{
		"request": map[string]any{
			"ecosystem": "pypi",
			"package":   pkg,
			"version":   version,
			"raw_version": func() string {
				if hasVersion {
					return rawVersion
				}
				return ""
			}(),
			"has_version": hasVersion,
			"operation":   op,
			"path":        r.URL.Path,
			"filename":    filename,
		},
	}
	if hasVersion {
		if vulnMaps := h.vulnerabilityPayload(ctx, pkg, rawVersion); len(vulnMaps) > 0 {
			payload["vulnerabilities"] = vulnMaps
		}
		if licenses := h.licensePayload(ctx, pkg, rawVersion); len(licenses) > 0 {
			payload["licenses"] = licenses
			if req, ok := payload["request"].(map[string]any); ok {
				req["licenses"] = licenses
			}
		}
	}

	var actions []policy.Action
	var err error
	if h.policies != nil {
		actions, err = h.policies.Evaluate(ctx, "pypi_artifact_request", payload)
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
			Ecosystem: "pypi",
			Name:      pkg,
			Version:   rawVersion,
			Operation: op,
		})
		status := statusFromAction(deny, http.StatusForbidden)
		http.Error(w, deny.Reason, status)
		slog.Info("request denied", "package", pkg, "version", rawVersion, "reason", deny.Reason)
		return
	}

	upstreamURL := *h.upstream
	upstreamURL.Path = strings.TrimSuffix(upstreamURL.Path, "/") + r.URL.Path
	upstreamURL.RawQuery = r.URL.RawQuery
	req, err := http.NewRequestWithContext(ctx, r.Method, upstreamURL.String(), r.Body)
	if err != nil {
		http.Error(w, "failed to create upstream request", http.StatusBadGateway)
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

func (h *pypiHandler) vulnerabilityPayload(ctx context.Context, pkg, version string) []map[string]any {
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
			Ecosystem: "PyPI",
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

func (h *pypiHandler) licensePayload(ctx context.Context, pkg, version string) []string {
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

func parsePyPIPath(p string) (pkg, version, filename, operation string) {
	if strings.HasPrefix(p, "/simple/") {
		pkg = strings.Trim(strings.TrimPrefix(p, "/simple/"), "/")
		operation = "simple"
		return
	}
	if strings.HasPrefix(p, "/project/") {
		parts := strings.Split(strings.TrimPrefix(p, "/project/"), "/")
		if len(parts) > 0 {
			pkg = parts[0]
		}
		if len(parts) > 1 {
			version = parts[1]
		}
		operation = "project"
		return
	}
	filename = path.Base(p)
	if filename == "." || filename == "/" {
		return
	}
	pkg, version = parsePyPIDistributionFilename(filename)
	if pkg != "" {
		operation = "download"
	}
	return
}

func parsePyPIDistributionFilename(filename string) (string, string) {
	base := filename
	for _, ext := range []string{".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".zip", ".whl"} {
		if strings.HasSuffix(base, ext) {
			base = strings.TrimSuffix(base, ext)
			break
		}
	}
	idx := findVersionBoundary(base)
	if idx <= 0 || idx+1 >= len(base) {
		return "", ""
	}
	namePart := base[:idx]
	versionPart := base[idx+1:]
	return namePart, versionPart
}

// NewPyPIHandler exposes the PyPI proxy handler for embedding in other servers.
func NewPyPIHandler(upstream string, policies PolicyEvaluator) (http.Handler, error) {
	return newPyPIHandler(upstream, policies)
}

func findVersionBoundary(base string) int {
	for i := 0; i < len(base); i++ {
		if base[i] == '-' && i+1 < len(base) && isVersionStart(base[i+1]) {
			return i
		}
	}
	return -1
}

func isVersionStart(b byte) bool {
	return (b >= '0' && b <= '9') || b == 'v'
}
