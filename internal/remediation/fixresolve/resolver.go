// Package fixresolve determines whether an advisory's claimed fix is actually
// actionable for the module path a project imports.
//
// Vulnerability databases record a "fixed" version per affected package, but
// that version is not always installable on the path the project uses. Two
// common cases break a naive "upgrade to the fixed version" recommendation:
//
//   - The advisory lists a product/release version that was never published on
//     the Go module path (e.g., github.com/docker/docker "fixed: 29.3.1", but
//     that module tops out at v28.5.2+incompatible; v29 ships as
//     github.com/moby/moby/v2).
//   - The fix only exists after a Go major-version migration (foo -> foo/v2).
//
// fixresolve verifies installability against a resolver (the Go module proxy)
// and, when no in-place fix exists, looks for a migration target among the
// advisory's sibling affected modules. The result is a [vulnerability.FixVerdict]
// that downstream stats, summary, and remediation rendering consult instead of
// trusting the raw advisory string.
package fixresolve

import (
	"context"
	"errors"
	"strings"

	graph "github.com/temporalio/deputy/internal/dependency/graph"
	"golang.org/x/mod/semver"
)

// Existence is a tri-state answer to "does this module version exist?".
type Existence int

const (
	// ExistsUnknown means existence could not be determined (e.g., the resolver
	// was offline or the proxy returned a transport/server error).
	ExistsUnknown Existence = iota
	// ExistsYes means the module version is resolvable.
	ExistsYes
	// ExistsNo means the resolver definitively reported the version absent.
	ExistsNo
)

// Resolver reports whether a specific module version is installable.
// Implementations must be safe for concurrent use.
type Resolver interface {
	ModuleVersionExists(ctx context.Context, modulePath, version string) Existence
}

// goProxyResolver verifies Go module versions against a Go module proxy.
type goProxyResolver struct {
	client *graph.GoProxyClient
}

// NewGoProxyResolver returns a Resolver backed by the Go module proxy.
// An empty proxyURL uses the default (proxy.golang.org). The underlying client
// caches results, so repeated probes within a scan are cheap.
func NewGoProxyResolver(proxyURL string) Resolver {
	return &goProxyResolver{client: graph.NewGoProxyClient(proxyURL)}
}

// ModuleVersionExists probes the proxy for module@version, trying the canonical
// version forms the Go proxy understands (with and without "+incompatible"). A
// 404/410 from the proxy means the version is absent; transport/server errors
// leave existence unknown so callers degrade gracefully rather than asserting a
// fix is broken.
func (r *goProxyResolver) ModuleVersionExists(ctx context.Context, modulePath, version string) Existence {
	sawError := false
	for _, v := range goVersionForms(modulePath, version) {
		_, err := r.client.FetchGoMod(ctx, modulePath, v)
		switch {
		case err == nil:
			return ExistsYes
		case errors.Is(err, graph.ErrModuleNotFound):
			continue // try the next candidate form
		default:
			sawError = true // transport/server error: existence unknown
		}
	}
	if sawError {
		return ExistsUnknown
	}
	return ExistsNo
}

// goVersionForms returns the canonical version strings to try against the Go
// proxy for a candidate fixed version. It always tries the semver form (with a
// leading "v"); for a major version >= 2 on a module path that lacks the
// matching "/vN" suffix, it also tries the "+incompatible" form, since that is
// how Go addresses such modules.
func goVersionForms(modulePath, version string) []string {
	v := strings.TrimSpace(version)
	if v == "" {
		return nil
	}
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	forms := []string{v}
	if maj := semver.Major(v); maj != "" && maj != "v0" && maj != "v1" {
		if !strings.HasSuffix(modulePath, "/"+maj) && !strings.Contains(v, "+incompatible") {
			forms = append(forms, v+"+incompatible")
		}
	}
	return forms
}
