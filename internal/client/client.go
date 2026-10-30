// Package client implements a typed HTTP client for the subset of the iboss
// API used by the Terraform provider. It owns transport, authentication,
// endpoint discovery, and wire models; it knows nothing about Terraform.
//
// Source of truth: iboss Postman collection 2s93RUuXjk (see docs/api-coverage.md).
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Documented fixed hosts (Postman introduction, "API Endpoint Host").
const (
	DefaultCoreHost     = "api.ibosscloud.com"
	DefaultAccountsHost = "accounts.ibosscloud.com"

	// DefaultUserAgent is the User-Agent value sent by every documented request.
	DefaultUserAgent = "ibossAPI"

	defaultRequestTimeout = 60 * time.Second
	defaultMaxRetries     = 3
	defaultRetryWaitMin   = 1 * time.Second
	defaultRetryWaitMax   = 30 * time.Second
	maxResponseBytes      = 16 << 20
	maxErrorSnippet       = 512
)

// DefaultDiscoveredHostSuffixes restricts gateway hosts returned by discovery.
// The documented examples place every node under ibosscloud.com.
var DefaultDiscoveredHostSuffixes = []string{".ibosscloud.com"}

// Config holds client settings. Exactly one authentication mode must be set:
// APIKey, or Username+Password (legacy, optional TOTPCode).
type Config struct {
	APIKey   string
	Username string
	Password string
	TOTPCode string

	// AccountSettingsID selects the account. Zero means discover the primary
	// account (the entry whose delegatedSuperAdminId is 0).
	AccountSettingsID int64

	// CoreHost and AccountsHost default to the documented fixed hosts.
	CoreHost     string
	AccountsHost string
	// GatewayHost skips gateway discovery when set.
	GatewayHost string

	// AllowedDiscoveredHostSuffixes restricts discovered gateway hosts.
	// Nil means DefaultDiscoveredHostSuffixes.
	AllowedDiscoveredHostSuffixes []string

	HTTPClient     *http.Client
	UserAgent      string
	RequestTimeout time.Duration
	MaxRetries     int
	RetryWaitMin   time.Duration
	RetryWaitMax   time.Duration
}

// AuthMode identifies the configured authentication flow.
type AuthMode string

const (
	AuthModeAPIKey AuthMode = "api_key"
	AuthModeLegacy AuthMode = "legacy"
)

// Client is safe for concurrent use.
type Client struct {
	cfg      Config
	mode     AuthMode
	http     *http.Client
	suffixes []string

	mu       sync.Mutex
	session  *session
	listLock keyedMutex
}

type session struct {
	token             string
	cloudXSRF         string
	cloudSessionID    string
	accountSettingsID int64
	gatewayHost       string
}

// New validates cfg and returns a client. It performs no network I/O.
func New(cfg Config) (*Client, error) {
	mode, err := validateCredentials(cfg)
	if err != nil {
		return nil, err
	}
	if cfg.CoreHost == "" {
		cfg.CoreHost = DefaultCoreHost
	}
	if cfg.AccountsHost == "" {
		cfg.AccountsHost = DefaultAccountsHost
	}
	for name, h := range map[string]string{"core host": cfg.CoreHost, "accounts host": cfg.AccountsHost} {
		if err := ValidateHostname(h); err != nil {
			return nil, fmt.Errorf("invalid %s: %w", name, err)
		}
	}
	if cfg.GatewayHost != "" {
		if err := ValidateHostname(cfg.GatewayHost); err != nil {
			return nil, fmt.Errorf("invalid gateway host: %w", err)
		}
	}
	if cfg.AccountSettingsID < 0 {
		return nil, errors.New("account settings ID must not be negative")
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = DefaultUserAgent
	}
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = defaultRequestTimeout
	}
	if cfg.MaxRetries < 0 {
		cfg.MaxRetries = 0
	} else if cfg.MaxRetries == 0 {
		cfg.MaxRetries = defaultMaxRetries
	}
	if cfg.RetryWaitMin <= 0 {
		cfg.RetryWaitMin = defaultRetryWaitMin
	}
	if cfg.RetryWaitMax < cfg.RetryWaitMin {
		cfg.RetryWaitMax = defaultRetryWaitMax
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Transport: http.DefaultTransport.(*http.Transport).Clone()}
	} else {
		cp := *hc
		hc = &cp
	}
	// The documentation describes no redirects; never follow one, so
	// credentials are only ever sent to configured or validated hosts.
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	suffixes := cfg.AllowedDiscoveredHostSuffixes
	if suffixes == nil {
		suffixes = DefaultDiscoveredHostSuffixes
	}
	return &Client{cfg: cfg, mode: mode, http: hc, suffixes: suffixes}, nil
}

func validateCredentials(cfg Config) (AuthMode, error) {
	hasKey := cfg.APIKey != ""
	hasLegacy := cfg.Username != "" || cfg.Password != "" || cfg.TOTPCode != ""
	switch {
	case hasKey && hasLegacy:
		return "", errors.New("conflicting credentials: set either an API key or a username/password, not both")
	case hasKey:
		return AuthModeAPIKey, nil
	case hasLegacy:
		if cfg.Username == "" || cfg.Password == "" {
			return "", errors.New("incomplete legacy credentials: both username and password are required")
		}
		return AuthModeLegacy, nil
	default:
		return "", errors.New("no credentials: set an API key, or a username and password")
	}
}

// Mode reports the configured authentication mode.
func (c *Client) Mode() AuthMode { return c.mode }

type hostKind int

const (
	hostCore hostKind = iota
	hostAccounts
	hostGateway
)

type request struct {
	host   hostKind
	method string
	path   string
	query  url.Values
	body   any
	// auth controls which documented headers are attached.
	auth authHeaders
	// basicAuth is used only by the legacy login request.
	basicUser, basicPass string
	// noRetry disables transport retries even for GET.
	noRetry bool
}

type authHeaders int

const (
	authNone    authHeaders = iota
	authToken               // Authorization: Token <token>
	authCore                // token + cloud XSRF/session cookies
	authGateway             // token + cloud XSRF cookie, token as session cookie
)

type response struct {
	status int
	header http.Header
	body   []byte
}

// do executes r with bounded retries for idempotent reads. It never retries
// authentication failures or non-GET requests.
func (c *Client) do(ctx context.Context, s *session, r request) (*response, error) {
	attempts := 1
	if r.method == http.MethodGet && !r.noRetry {
		attempts += c.cfg.MaxRetries
	}
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			wait := c.backoff(attempt, lastErr)
			t := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				t.Stop()
				return nil, ctx.Err()
			case <-t.C:
			}
		}
		resp, err := c.once(ctx, s, r)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if !retryable(ctx, err) {
			return nil, err
		}
	}
	return nil, lastErr
}

func (c *Client) once(ctx context.Context, s *session, r request) (*response, error) {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.RequestTimeout)
	defer cancel()

	host, err := c.hostFor(s, r.host)
	if err != nil {
		return nil, err
	}
	u := url.URL{Scheme: "https", Host: host, Path: r.path}
	if len(r.query) > 0 {
		u.RawQuery = r.query.Encode()
	}
	var body io.Reader
	if r.body != nil {
		b, err := json.Marshal(r.body)
		if err != nil {
			return nil, fmt.Errorf("encoding request body: %w", err)
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, r.method, u.String(), body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.cfg.UserAgent)
	req.Header.Set("Accept", "application/json")
	if r.body != nil {
		req.Header.Set("Content-Type", "application/json;charset=UTF-8")
	}
	if r.basicUser != "" {
		req.SetBasicAuth(r.basicUser, r.basicPass)
	}
	c.attachAuth(req, s, r.auth)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, &TransportError{Method: r.method, Path: r.path, Err: c.redactErr(s, err)}
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, &TransportError{Method: r.method, Path: r.path, Err: c.redactErr(s, err)}
	}
	if len(data) > maxResponseBytes {
		return nil, fmt.Errorf("%s %s: response exceeds %d bytes", r.method, r.path, maxResponseBytes)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, &APIError{
			Method:     r.method,
			Path:       r.path,
			StatusCode: resp.StatusCode,
			RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After"), time.Now()),
			// Redact before truncating so a secret cut at the boundary cannot leak.
			Snippet: snippet(c.redact(s, string(data))),
		}
	}
	return &response{status: resp.StatusCode, header: resp.Header, body: data}, nil
}

func (c *Client) hostFor(s *session, k hostKind) (string, error) {
	switch k {
	case hostCore:
		return c.cfg.CoreHost, nil
	case hostAccounts:
		return c.cfg.AccountsHost, nil
	case hostGateway:
		if s == nil || s.gatewayHost == "" {
			return "", errors.New("gateway host is not known; discovery has not completed")
		}
		return s.gatewayHost, nil
	}
	return "", fmt.Errorf("unknown host kind %d", k)
}

// attachAuth adds the headers documented on each request in the collection.
func (c *Client) attachAuth(req *http.Request, s *session, a authHeaders) {
	if a == authNone || s == nil {
		return
	}
	req.Header.Set("Authorization", "Token "+s.token)
	switch a {
	case authCore:
		// Documented: Cookie: XSRF-TOKEN={{cloudXsrfToken}}; JESSIONID={{cloudSessionId}}
		setXSRF(req, s.cloudXSRF, s.cloudSessionID)
	case authGateway:
		// Documented: Cookie: XSRF-TOKEN={{cloudXsrfToken}}; JESSIONID={{token}}
		setXSRF(req, s.cloudXSRF, s.token)
	}
}

func setXSRF(req *http.Request, xsrf, sessionValue string) {
	var parts []string
	if xsrf != "" {
		parts = append(parts, "XSRF-TOKEN="+xsrf)
		req.Header.Set("X-XSRF-TOKEN", xsrf)
	}
	if sessionValue != "" {
		// "JESSIONID" is spelled exactly as in the documented header.
		parts = append(parts, "JESSIONID="+sessionValue)
	}
	if len(parts) > 0 {
		req.Header.Set("Cookie", strings.Join(parts, "; "))
	}
}

func (c *Client) getJSON(ctx context.Context, s *session, r request, out any) error {
	resp, err := c.do(ctx, s, r)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(resp.body, out); err != nil {
		return &DecodeError{Method: r.method, Path: r.path, Err: err}
	}
	return nil
}

func (c *Client) backoff(attempt int, lastErr error) time.Duration {
	var apiErr *APIError
	if errors.As(lastErr, &apiErr) && apiErr.RetryAfter > 0 {
		if apiErr.RetryAfter > c.cfg.RetryWaitMax {
			return c.cfg.RetryWaitMax
		}
		return apiErr.RetryAfter
	}
	wait := c.cfg.RetryWaitMin << (attempt - 1)
	if wait <= 0 || wait > c.cfg.RetryWaitMax {
		wait = c.cfg.RetryWaitMax
	}
	return wait
}

func retryable(ctx context.Context, err error) bool {
	if ctx.Err() != nil {
		return false
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		switch apiErr.StatusCode {
		case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			return true
		}
		return false
	}
	var tErr *TransportError
	if errors.As(err, &tErr) {
		var blocked *BlockedDestinationError
		if errors.As(tErr.Err, &blocked) {
			return false
		}
		var netErr net.Error
		if errors.As(tErr.Err, &netErr) {
			return true
		}
		return errors.Is(tErr.Err, io.ErrUnexpectedEOF) || errors.Is(tErr.Err, io.EOF)
	}
	return false
}

func parseRetryAfter(v string, now time.Time) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs < 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := t.Sub(now); d > 0 {
			return d
		}
	}
	return 0
}

func snippet(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > maxErrorSnippet {
		s = s[:maxErrorSnippet] + "…"
	}
	return s
}

// redact removes every credential and derived session value from s.
func (c *Client) redact(sess *session, s string) string {
	secrets := []string{c.cfg.APIKey, c.cfg.Password, c.cfg.TOTPCode}
	if sess != nil {
		secrets = append(secrets, sess.token, sess.cloudXSRF, sess.cloudSessionID)
	}
	for _, v := range secrets {
		if v != "" {
			s = strings.ReplaceAll(s, v, "[REDACTED]")
		}
	}
	return s
}

func (c *Client) redactErr(sess *session, err error) error {
	msg := c.redact(sess, err.Error())
	if msg == err.Error() {
		return err
	}
	return &redactedError{msg: msg, err: err}
}

type redactedError struct {
	msg string
	err error
}

func (e *redactedError) Error() string { return e.msg }
func (e *redactedError) Unwrap() error { return e.err }

// keyedMutex serializes mutations of one shared remote collection within this
// provider process. Terraform applies resources concurrently, and the API
// documents no concurrency contract for list modification.
type keyedMutex struct {
	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

func (k *keyedMutex) lock(key string) func() {
	k.mu.Lock()
	if k.locks == nil {
		k.locks = map[string]*sync.Mutex{}
	}
	m, ok := k.locks[key]
	if !ok {
		m = &sync.Mutex{}
		k.locks[key] = m
	}
	k.mu.Unlock()
	m.Lock()
	return m.Unlock
}
