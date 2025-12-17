package proxy

import (
	"net/http"
	"path"
	"strings"
)

// pypiHandler proxies requests to a PyPI registry (e.g., pypi.org) while
// evaluating policy rules and enriching requests with vulnerability data.
type pypiHandler struct {
	*baseHandler
}

// newPyPIHandler creates a handler for proxying PyPI registry requests.
// It configures vulnerability lookups against the "PyPI" ecosystem in OSV.
func newPyPIHandler(upstream string, policies PolicyEvaluator) (*pypiHandler, error) {
	base, err := newBaseHandler(handlerConfig{
		ecosystem:    "pypi",
		osvEcosystem: "PyPI",
		upstream:     upstream,
		policies:     policies,
		wantLicenses: false,
	})
	if err != nil {
		return nil, err
	}
	return &pypiHandler{baseHandler: base}, nil
}

// ServeHTTP handles incoming PyPI registry requests, parsing the path to extract
// package name, version, and operation type, then evaluating policies before proxying.
func (h *pypiHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	pkg, version, filename, op := parsePyPIPath(r.URL.Path)

	info := requestInfo{
		Name:       pkg,
		Version:    version,
		HasVersion: strings.TrimSpace(version) != "",
		Operation:  op,
		Ecosystem:  "pypi",
		Filename:   filename,
	}
	payload := h.buildPayload(r.Context(), info, r.URL.Path)
	h.serve(w, r, "pypi_artifact_request", info, payload)
}

// parsePyPIPath extracts package name, version, filename, and operation from a PyPI
// registry URL path. Supported path formats include:
//   - /simple/<package>/         - simple API package listing
//   - /project/<package>/<version>/ - project page
//   - /packages/.../<package>-<version>.<ext> - distribution download
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

// parsePyPIDistributionFilename extracts package name and version from a PyPI
// distribution filename (e.g., "requests-2.31.0.tar.gz" -> "requests", "2.31.0").
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

// findVersionBoundary finds the index of the hyphen separating package name from
// version in a PyPI distribution filename base (without extension).
func findVersionBoundary(base string) int {
	for i := 0; i < len(base); i++ {
		if base[i] == '-' && i+1 < len(base) && isVersionStart(base[i+1]) {
			return i
		}
	}
	return -1
}

// isVersionStart returns true if the byte could start a version string (digit or 'v').
func isVersionStart(b byte) bool {
	return (b >= '0' && b <= '9') || b == 'v'
}
