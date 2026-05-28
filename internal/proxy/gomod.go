package proxy

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/temporalio/deputy/internal/ecosystem"
)

// NewGoModuleHandler creates a Go module proxy handler using the unified handler factory.
// It proxies requests to a Go module proxy (e.g., proxy.golang.org) while evaluating
// policy rules and enriching requests with vulnerability and license data.
func NewGoModuleHandler(upstream string, policies PolicyEvaluator) (http.Handler, error) {
	return DefaultFactory.CreateHandler(ecosystem.Go, upstream, policies)
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
