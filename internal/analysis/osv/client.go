package osv

import (
	"os"
	"strings"
	"time"

	"github.com/temporalio/deputy/internal/httputil"
	"osv.dev/bindings/go/osvdev"
)

// osvHTTPTimeout is the overall request timeout for OSV API calls.
// This is slightly longer than the GHA timeout to account for potentially
// larger batch queries.
const osvHTTPTimeout = 45 * time.Second

// osvBaseURLEnv overrides the OSV API base URL (useful for tests or mirrors).
const osvBaseURLEnv = "DEPUTY_OSV_BASE_URL"

// NewClient returns an osv.dev client configured with production-friendly HTTP timeouts
// and automatic retry for transient failures.
//
// Callers should still pass a cancelable context; this function primarily protects against
// hung connections and slow/broken networks. The retryable HTTP client automatically
// handles 5xx errors and connection failures with exponential backoff.
//
// Set DEPUTY_OSV_BASE_URL to point to a custom OSV API endpoint (e.g., a test server or mirror).
func NewClient() *osvdev.OSVClient {
	c := osvdev.DefaultClient()
	c.HTTPClient = httputil.NewRetryableClient(osvHTTPTimeout)
	if base := strings.TrimSpace(os.Getenv(osvBaseURLEnv)); base != "" {
		c.BaseHostURL = strings.TrimRight(base, "/")
	}
	return c
}
