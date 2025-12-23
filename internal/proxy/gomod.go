package proxy

import (
	"fmt"
	"net/http"
	"strings"
)

// goModuleHandler proxies requests to a Go module proxy (e.g., proxy.golang.org)
// while evaluating policy rules and enriching requests with vulnerability and
// license data.
type goModuleHandler struct {
	*baseHandler
}

// newGoModuleHandler creates a handler for proxying Go module requests.
// It configures vulnerability lookups against the "Go" ecosystem in OSV
// and enables license lookups.
func newGoModuleHandler(upstream string, policies PolicyEvaluator) (*goModuleHandler, error) {
	base, err := newBaseHandler(handlerConfig{
		ecosystem:    "go",
		osvEcosystem: "Go",
		upstream:     upstream,
		policies:     policies,
		wantLicenses: true,
	})
	if err != nil {
		return nil, err
	}
	return &goModuleHandler{baseHandler: base}, nil
}

// ServeHTTP handles incoming Go module proxy requests, parsing the path to extract
// module name, version, and operation type, then evaluating policies before proxying.
func (h *goModuleHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	module, version, fileType, op, err := parseGoProxyPath(r.URL.Path)
	if err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}

	h.serveRequest(w, r, "go_artifact_request", requestInfo{
		Name:       module,
		Version:    version,
		HasVersion: hasVersion(version),
		Operation:  op,
		Ecosystem:  "go",
		FileType:   fileType,
	})
}

// parseGoProxyPath extracts module name, version, file type, and operation from
// a Go module proxy URL path. The path format follows the GOPROXY protocol:
//   - /<module>/@v/list           - list available versions
//   - /<module>/@v/<version>.info - version metadata
//   - /<module>/@v/<version>.mod  - go.mod file
//   - /<module>/@v/<version>.zip  - module source archive
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
