package proxy

import (
	"net/http"
	"path"
	"strings"

	"github.com/picatz/deputy/internal/ecosystem"
)

// NewPyPIHandler creates a PyPI proxy handler using the unified handler factory.
// It proxies requests to a PyPI registry (e.g., pypi.org) while evaluating
// policy rules and enriching requests with vulnerability data.
func NewPyPIHandler(upstream string, policies PolicyEvaluator) (http.Handler, error) {
	return DefaultFactory.CreateHandler(ecosystem.PyPI, upstream, policies)
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
