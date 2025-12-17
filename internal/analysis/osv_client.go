package analysis

import (
	"time"

	"github.com/picatz/deputy/internal/httputil"
	"osv.dev/bindings/go/osvdev"
)

// osvHTTPTimeout is the overall request timeout for OSV API calls.
// This is slightly longer than the GHA timeout to account for potentially
// larger batch queries.
const osvHTTPTimeout = 45 * time.Second

// NewOSVClient returns an osv.dev client configured with production-friendly HTTP timeouts.
//
// Callers should still pass a cancelable context; this function primarily protects against
// hung connections and slow/broken networks.
func NewOSVClient() *osvdev.OSVClient {
	c := osvdev.DefaultClient()
	c.HTTPClient = httputil.NewClient(osvHTTPTimeout)
	return c
}
