package advisorysource

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"connectrpc.com/connect"

	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	pluginv1 "github.com/temporalio/deputy/gen/deputy/plugin/v1"
	"github.com/temporalio/deputy/gen/deputy/plugin/v1/pluginv1connect"
)

// connectSource adapts a remote AdvisorySourceService reachable over ConnectRPC
// to the in-process Source interface. It is the low-latency binding of the same
// proto contract the pluginrpc subprocess binding serves: a persistent local
// sidecar or shared remote service (e.g. an org-wide threat feed) answers each
// query over HTTP instead of a per-call subprocess exec, which makes it
// suitable for latency-sensitive callers like the proxy.
type connectSource struct {
	url    string
	client pluginv1connect.AdvisorySourceServiceClient
	info   *pluginv1.AdvisorySourceInfo
}

// ConnectOption configures a ConnectRPC source.
type ConnectOption func(*connectOptions)

type connectOptions struct {
	httpClient connect.HTTPClient
	clientOpts []connect.ClientOption
}

// WithConnectHTTPClient overrides the HTTP client (e.g. for TLS or auth
// transports). Defaults to http.DefaultClient.
func WithConnectHTTPClient(c connect.HTTPClient) ConnectOption {
	return func(o *connectOptions) { o.httpClient = c }
}

// WithConnectClientOptions appends ConnectRPC client options (interceptors,
// codecs, auth).
func WithConnectClientOptions(opts ...connect.ClientOption) ConnectOption {
	return func(o *connectOptions) { o.clientOpts = append(o.clientOpts, opts...) }
}

// NewConnectSource returns a Source backed by the AdvisorySourceService at
// baseURL. It calls Info once to cache the service's declared capabilities for
// routing, so a service that is down at startup fails loudly here rather than
// silently covering nothing.
func NewConnectSource(ctx context.Context, baseURL string, opts ...ConnectOption) (Source, error) {
	// Advisory queries sit on the scan critical path, so the default client
	// carries a timeout; a hung remote source must not stall the whole scan.
	// http.Client.Timeout bounds the full round trip, dial through reading
	// the response body. Callers with different needs (per-request context
	// deadlines, slow feeds) supply their own via WithConnectHTTPClient.
	options := &connectOptions{httpClient: &http.Client{Timeout: 30 * time.Second}}
	for _, opt := range opts {
		opt(options)
	}

	client := pluginv1connect.NewAdvisorySourceServiceClient(options.httpClient, baseURL, options.clientOpts...)
	resp, err := client.Info(ctx, connect.NewRequest(&pluginv1.AdvisorySourceInfoRequest{}))
	if err != nil {
		return nil, fmt.Errorf("advisory source %s Info: %w", baseURL, err)
	}
	info := resp.Msg.GetInfo()
	if info == nil {
		return nil, fmt.Errorf("advisory source %s returned no info", baseURL)
	}
	return &connectSource{url: baseURL, client: client, info: info}, nil
}

// Info returns the service's cached capability descriptor.
func (c *connectSource) Info() *pluginv1.AdvisorySourceInfo { return c.info }

// Query sends the covered packages to the remote service and returns its proto
// findings verbatim, stamping the service's name as provenance.
func (c *connectSource) Query(ctx context.Context, pkgs []*dependencyv1.Package) (*Result, error) {
	resp, err := c.client.Query(ctx, connect.NewRequest(&pluginv1.AdvisoryQueryRequest{Packages: pkgs}))
	if err != nil {
		return nil, fmt.Errorf("advisory source %s Query: %w", c.url, err)
	}
	name := c.info.GetName()
	for _, f := range resp.Msg.GetFindings() {
		if f != nil {
			f.Sources = unionStrings(f.GetSources(), []string{name})
		}
	}
	return &Result{Findings: resp.Msg.GetFindings(), Advisories: resp.Msg.GetAdvisories()}, nil
}
