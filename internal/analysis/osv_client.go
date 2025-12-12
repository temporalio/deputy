package analysis

import (
	"net"
	"net/http"
	"time"

	"osv.dev/bindings/go/osvdev"
)

const (
	osvHTTPTimeout        = 45 * time.Second
	osvIdleConnTimeout    = 90 * time.Second
	osvTLSHandshake       = 10 * time.Second
	osvResponseHeaderWait = 20 * time.Second
	osvDialTimeout        = 10 * time.Second
	osvKeepAlive          = 30 * time.Second
)

// NewOSVClient returns an osv.dev client configured with production-friendly HTTP timeouts.
//
// Callers should still pass a cancelable context; this function primarily protects against
// hung connections and slow/broken networks.
func NewOSVClient() *osvdev.OSVClient {
	c := osvdev.DefaultClient()
	c.HTTPClient = newOSVHTTPClient()
	return c
}

func newOSVHTTPClient() *http.Client {
	dialer := &net.Dialer{
		Timeout:   osvDialTimeout,
		KeepAlive: osvKeepAlive,
	}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       osvIdleConnTimeout,
		TLSHandshakeTimeout:   osvTLSHandshake,
		ResponseHeaderTimeout: osvResponseHeaderWait,
	}
	return &http.Client{
		Timeout:   osvHTTPTimeout,
		Transport: transport,
	}
}
