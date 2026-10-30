package client

import (
	"errors"
	"fmt"
	"net/http"
	"time"
)

// APIError is a non-2xx HTTP response. Snippet has credentials redacted.
type APIError struct {
	Method     string
	Path       string
	StatusCode int
	RetryAfter time.Duration
	Snippet    string
}

func (e *APIError) Error() string {
	msg := fmt.Sprintf("iboss API %s %s returned HTTP %d", e.Method, e.Path, e.StatusCode)
	if e.Snippet != "" {
		msg += ": " + e.Snippet
	}
	return msg
}

// IsUnauthorized reports whether err is an HTTP 401 from the API. The
// documentation states a missing, malformed, or invalid key returns 401.
func IsUnauthorized(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusUnauthorized
}

// TransportError wraps a failure before an HTTP response was received.
type TransportError struct {
	Method string
	Path   string
	Err    error
}

func (e *TransportError) Error() string {
	return fmt.Sprintf("iboss API %s %s: %v", e.Method, e.Path, e.Err)
}

func (e *TransportError) Unwrap() error { return e.Err }

// DecodeError is a 2xx response whose body did not match the documented shape.
type DecodeError struct {
	Method string
	Path   string
	Err    error
}

func (e *DecodeError) Error() string {
	return fmt.Sprintf("iboss API %s %s: unexpected response body: %v", e.Method, e.Path, e.Err)
}

func (e *DecodeError) Unwrap() error { return e.Err }

// BlockedDestinationError is returned by fail-closed transports (for example
// the test harness) when a request targets a host outside their allowlist.
// It is never retried.
type BlockedDestinationError struct {
	Host string
}

func (e *BlockedDestinationError) Error() string {
	return fmt.Sprintf("request to %q blocked: destination is not in the allowlist", e.Host)
}

// DiscoveryError reports a failure to determine the account or a node host.
type DiscoveryError struct {
	Step string
	Err  error
}

func (e *DiscoveryError) Error() string {
	return fmt.Sprintf("iboss discovery (%s): %v", e.Step, e.Err)
}
func (e *DiscoveryError) Unwrap() error { return e.Err }
