package releases

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/temporalio/deputy/internal/httputil"
)

const (
	// defaultHTTPTimeout bounds release metadata requests.
	defaultHTTPTimeout = 10 * time.Second
	// defaultJSONMaxBytes bounds release metadata responses before decoding.
	defaultJSONMaxBytes = 4 << 20
)

// defaultHTTPClient returns Deputy's standard retrying HTTP client for release
// metadata lookups.
func defaultHTTPClient() *http.Client {
	return httputil.NewSafeRetryableClient(defaultHTTPTimeout)
}

// decodeJSON fetches endpoint with client and decodes a bounded JSON response
// into out.
func decodeJSON(ctx context.Context, client *http.Client, endpoint string, maxBytes int64, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("fetching %s: %w", endpoint, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetching %s: status %d", endpoint, resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBytes)).Decode(out); err != nil {
		return fmt.Errorf("decoding %s: %w", endpoint, err)
	}
	return nil
}
