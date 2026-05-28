package gitutil

import (
	"net/http"
	"time"

	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/client"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"

	"github.com/temporalio/deputy/internal/network"
)

func init() {
	// Install SSRF-protected HTTP transports globally for all go-git operations.
	// This prevents DNS rebinding attacks by validating resolved IP addresses
	// at connection time, complementing the early validation in targets.ValidateRemoteTarget().
	InstallSafeGitTransport()
}

// NewSafeGitTransport returns a go-git transport.Transport that uses
// SafeDialer for SSRF protection. This prevents DNS rebinding attacks
// by validating resolved IP addresses at connection time.
//
// Use this transport with go-git operations that handle user-controlled URLs,
// especially in server mode where targets come from untrusted sources.
//
// Note: The safe transport is installed globally via init(), so this function
// is primarily useful for explicit transport configuration in tests or when
// creating custom git clients.
func NewSafeGitTransport() transport.Transport {
	return githttp.NewClient(newSafeHTTPClient())
}

// NewSafeGitTransportWithOptions returns a go-git transport.Transport with custom SafeDialer options.
func NewSafeGitTransportWithOptions(opts ...network.Option) transport.Transport {
	return githttp.NewClient(newSafeHTTPClientWithOptions(opts...))
}

// InstallSafeGitTransport registers SSRF-protected HTTP transports
// as the default for all go-git operations.
//
// This affects the global go-git transport registry. After calling this,
// all go-git HTTP(S) operations will use SafeDialer to validate resolved
// IP addresses, preventing DNS rebinding attacks.
//
// This function is called automatically via init(), but can be called
// explicitly if needed (e.g., after tests that modify the transport registry).
func InstallSafeGitTransport() {
	httpClient := newSafeHTTPClient()
	safeGitTransport := githttp.NewClient(httpClient)

	client.InstallProtocol("http", safeGitTransport)
	client.InstallProtocol("https", safeGitTransport)
}

// InstallSafeGitTransportWithOptions registers SSRF-protected transports with custom options.
func InstallSafeGitTransportWithOptions(opts ...network.Option) {
	httpClient := newSafeHTTPClientWithOptions(opts...)
	safeGitTransport := githttp.NewClient(httpClient)

	client.InstallProtocol("http", safeGitTransport)
	client.InstallProtocol("https", safeGitTransport)
}

// newSafeHTTPClient creates an HTTP client with SSRF protection for git operations.
func newSafeHTTPClient() *http.Client {
	return newSafeHTTPClientWithOptions()
}

func newSafeHTTPClientWithOptions(opts ...network.Option) *http.Client {
	return &http.Client{
		Transport: network.SafeTransportWithOptions(opts...),
		Timeout:   5 * time.Minute, // git operations can be slow
	}
}
