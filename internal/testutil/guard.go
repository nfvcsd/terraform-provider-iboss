package testutil

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/nfvcsd/iboss-terraform/internal/client"
)

// GuardTransport is a fail-closed http.RoundTripper. It only reaches the
// exact host:port pairs in its allowlist, each mapped to a local listener,
// and it ignores proxy environment variables. Anything else — including a
// production iboss host reached through an omitted override, a discovered
// host, or a redirect target — fails before any connection is attempted.
type GuardTransport struct {
	allowed map[string]string
	base    *http.Transport
}

// NewGuardTransport maps each allowed "host:port" to a local dial address.
func NewGuardTransport(allowed map[string]string, roots *x509.CertPool) *GuardTransport {
	g := &GuardTransport{allowed: map[string]string{}}
	for k, v := range allowed {
		g.allowed[strings.ToLower(k)] = v
	}
	d := &net.Dialer{Timeout: 5 * time.Second}
	g.base = &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			target, ok := g.allowed[strings.ToLower(address)]
			if !ok {
				return nil, &client.BlockedDestinationError{Host: address}
			}
			return d.DialContext(ctx, network, target)
		},
		TLSClientConfig:       &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          10,
		IdleConnTimeout:       5 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
	}
	return g
}

func (g *GuardTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" {
		return nil, &client.BlockedDestinationError{Host: req.URL.Scheme + "://" + req.URL.Host}
	}
	hp := req.URL.Host
	if req.URL.Port() == "" {
		hp = net.JoinHostPort(req.URL.Hostname(), "443")
	}
	if _, ok := g.allowed[strings.ToLower(hp)]; !ok {
		return nil, &client.BlockedDestinationError{Host: req.URL.Host}
	}
	return g.base.RoundTrip(req)
}

// CloseIdleConnections releases pooled connections.
func (g *GuardTransport) CloseIdleConnections() { g.base.CloseIdleConnections() }
