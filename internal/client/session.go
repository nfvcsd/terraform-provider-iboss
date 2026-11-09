package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// call runs fn with an established session, discovering the gateway host
// first when needGateway is set. In legacy mode an HTTP 401 discards the
// session so the next call logs in again. Only an idempotent fn is re-run
// immediately after that fresh login, and only when no TOTP code is
// configured (a one-time code cannot be replayed). Mutations are never
// re-sent.
func (c *Client) call(ctx context.Context, needGateway, idempotent bool, fn func(s session) error) error {
	s, err := c.sessionFor(ctx, needGateway)
	if err != nil {
		return err
	}
	err = fn(s)
	if err == nil || !IsUnauthorized(err) || c.mode != AuthModeLegacy {
		return err
	}
	c.mu.Lock()
	if c.session != nil && c.session.token == s.token {
		c.session = nil
	}
	c.mu.Unlock()
	if !idempotent || c.cfg.TOTPCode != "" {
		return err
	}
	s, err2 := c.sessionFor(ctx, needGateway)
	if err2 != nil {
		return err2
	}
	return fn(s)
}

// sessionFor returns a snapshot of the shared session, establishing it once.
// The mutex is held across network I/O so concurrent Terraform operations
// share a single login and discovery.
func (c *Client) sessionFor(ctx context.Context, needGateway bool) (session, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.session == nil {
		s, err := c.establish(ctx)
		if err != nil {
			return session{}, err
		}
		c.session = s
	}
	if needGateway && c.session.gatewayHost == "" {
		host, err := c.discoverGateway(ctx, c.session)
		if err != nil {
			return session{}, err
		}
		c.session.gatewayHost = host
	}
	return *c.session, nil
}

// AccountSettingsID returns the configured or discovered account ID.
func (c *Client) AccountSettingsID(ctx context.Context) (int64, error) {
	s, err := c.sessionFor(ctx, false)
	if err != nil {
		return 0, err
	}
	return s.accountSettingsID, nil
}

// GatewayHost returns the configured or discovered gateway node host.
func (c *Client) GatewayHost(ctx context.Context) (string, error) {
	s, err := c.sessionFor(ctx, true)
	if err != nil {
		return "", err
	}
	return s.gatewayHost, nil
}

func (c *Client) establish(ctx context.Context) (*session, error) {
	s := &session{gatewayHost: c.cfg.GatewayHost}
	switch c.mode {
	case AuthModeAPIKey:
		// The documented API-key requests send "Authorization: Token {{token}}"
		// without a preceding login, so the key is the token.
		s.token = c.cfg.APIKey
	case AuthModeLegacy:
		tok, err := c.legacyLogin(ctx)
		if err != nil {
			return nil, err
		}
		s.token = tok
	}
	if err := c.loadAccount(ctx, s); err != nil {
		return nil, err
	}
	return s, nil
}

type tokenResponse struct {
	Token string `json:"token"`
}

// legacyLogin implements "Login (Legacy)":
// GET https://{{ibossAccounts}}/ibossauth/web/tokens?ignoreAuthModule=true&totpCode=…
// with HTTP Basic authentication.
func (c *Client) legacyLogin(ctx context.Context) (string, error) {
	q := url.Values{"ignoreAuthModule": {"true"}}
	if c.cfg.TOTPCode != "" {
		q.Set("totpCode", c.cfg.TOTPCode)
	}
	var out tokenResponse
	err := c.getJSON(ctx, nil, request{
		host: hostAccounts, method: http.MethodGet, path: "/ibossauth/web/tokens", query: q,
		basicUser: c.cfg.Username, basicPass: c.cfg.Password,
		// Login issues a token and may consume a one-time code: never retry it.
		noRetry: true,
	}, &out)
	if err != nil {
		return "", &DiscoveryError{Step: "legacy login", Err: err}
	}
	if out.Token == "" {
		return "", &DiscoveryError{Step: "legacy login", Err: errors.New("response did not include a token")}
	}
	return out.Token, nil
}

type accountSummary struct {
	Name                  string  `json:"name"`
	AccountSettingsID     FlexInt `json:"accountSettingsId"`
	DelegatedSuperAdminID FlexInt `json:"delegatedSuperAdminId"`
}

// loadAccount implements "Get Primary Account ID":
// GET https://{{baseApiDomain}}/ibcloud/web/users/mySettings. It records the
// XSRF-TOKEN and JSESSIONID cookies that later documented requests send.
func (c *Client) loadAccount(ctx context.Context, s *session) error {
	r := request{host: hostCore, method: http.MethodGet, path: "/ibcloud/web/users/mySettings", auth: authToken}
	resp, err := c.do(ctx, s, r)
	if err != nil {
		return &DiscoveryError{Step: "account lookup", Err: err}
	}
	for _, ck := range (&http.Response{Header: resp.header}).Cookies() {
		switch ck.Name {
		case "XSRF-TOKEN":
			s.cloudXSRF = ck.Value
		case "JSESSIONID":
			s.cloudSessionID = ck.Value
		}
	}
	if c.cfg.AccountSettingsID != 0 {
		s.accountSettingsID = c.cfg.AccountSettingsID
		return nil
	}
	var accounts []accountSummary
	if err := decode(resp.body, &accounts); err != nil {
		return &DiscoveryError{Step: "account lookup", Err: &DecodeError{Method: r.method, Path: r.path, Err: err}}
	}
	var primary []int64
	for _, a := range accounts {
		if a.DelegatedSuperAdminID.Valid && a.DelegatedSuperAdminID.Int64 == 0 && a.AccountSettingsID.Valid {
			primary = append(primary, a.AccountSettingsID.Int64)
		}
	}
	switch len(primary) {
	case 1:
		s.accountSettingsID = primary[0]
		return nil
	case 0:
		return &DiscoveryError{Step: "account lookup", Err: errors.New("no primary account (delegatedSuperAdminId 0) was returned; set account_settings_id")}
	default:
		return &DiscoveryError{Step: "account lookup", Err: fmt.Errorf("%d primary accounts were returned; set account_settings_id to choose one", len(primary))}
	}
}

type cluster struct {
	ClusterID      FlexInt         `json:"clusterId"`
	ClusterName    string          `json:"clusterName"`
	ProductFamily  string          `json:"productFamily"`
	DefaultCluster FlexInt         `json:"defaultCluster"`
	Members        []clusterMember `json:"members"`
}

type clusterMember struct {
	Primary   FlexInt `json:"primary"`
	CloudNode struct {
		MasterAdminInterfaceDNS string `json:"masterAdminInterfaceDns"`
	} `json:"cloudNode"`
}

// discoverGateway implements "Get API Base Domains":
// GET https://{{baseApiDomain}}/ibcloud/web/account/clusters?accountSettingsId=…
// The documentation says the gateway API uses "the primary gateway node of
// the default node cluster", so among "swg" clusters it prefers those with
// defaultCluster = 1 (a documented response field), then takes the
// masterAdminInterfaceDns of the primary member. If no swg cluster carries the
// flag, every swg cluster is considered. The discovered host is validated
// before any credential is sent to it.
func (c *Client) discoverGateway(ctx context.Context, s *session) (string, error) {
	var clusters []cluster
	err := c.getJSON(ctx, s, request{
		host: hostCore, method: http.MethodGet, path: "/ibcloud/web/account/clusters",
		query: url.Values{"accountSettingsId": {strconv.FormatInt(s.accountSettingsID, 10)}},
		auth:  authToken,
	}, &clusters)
	if err != nil {
		return "", &DiscoveryError{Step: "gateway discovery", Err: err}
	}
	var swg, defaults []cluster
	for _, cl := range clusters {
		if cl.ProductFamily != "swg" {
			continue
		}
		swg = append(swg, cl)
		if cl.DefaultCluster.Valid && cl.DefaultCluster.Int64 == 1 {
			defaults = append(defaults, cl)
		}
	}
	candidates := swg
	if len(defaults) > 0 {
		candidates = defaults
	}
	found := map[string]string{} // host -> cluster description
	for _, cl := range candidates {
		desc := fmt.Sprintf("cluster %q (id %d)", cl.ClusterName, cl.ClusterID.Int64)
		for _, m := range cl.Members {
			// The example returns primary as the number 1; the collection's
			// script compares it loosely with "1". FlexInt accepts both.
			if m.Primary.Valid && m.Primary.Int64 == 1 && m.CloudNode.MasterAdminInterfaceDNS != "" {
				found[strings.ToLower(m.CloudNode.MasterAdminInterfaceDNS)] = desc
			}
		}
	}
	if len(found) == 0 {
		return "", &DiscoveryError{Step: "gateway discovery", Err: errors.New(`no primary member of the "swg" product family was returned; set gateway_host`)}
	}
	if len(found) > 1 {
		hosts := make([]string, 0, len(found))
		for h, d := range found {
			hosts = append(hosts, h+" ("+d+")")
		}
		sort.Strings(hosts)
		return "", &DiscoveryError{Step: "gateway discovery", Err: fmt.Errorf(
			"%d primary gateway hosts were returned and none is uniquely marked as the default cluster; "+
				"set gateway_host (or IBOSS_GATEWAY_HOST) to one of: %s", len(found), strings.Join(hosts, ", "))}
	}
	var host string
	for h := range found {
		host = h
	}
	if err := ValidateHostname(host); err != nil {
		return "", &DiscoveryError{Step: "gateway discovery", Err: fmt.Errorf("discovered host rejected: %w", err)}
	}
	if !hasAllowedSuffix(host, c.suffixes) {
		return "", &DiscoveryError{Step: "gateway discovery", Err: fmt.Errorf("discovered host %q is outside the allowed domains %v; set gateway_host explicitly if this is expected", host, c.suffixes)}
	}
	return host, nil
}

func hasAllowedSuffix(host string, suffixes []string) bool {
	for _, sfx := range suffixes {
		sfx = strings.ToLower(sfx)
		if strings.HasSuffix(host, sfx) && len(host) > len(sfx) {
			return true
		}
	}
	return false
}

// ValidateHostname accepts a bare DNS name: no scheme, port, path, or IP literal.
func ValidateHostname(h string) error {
	if h == "" {
		return errors.New("host is empty")
	}
	if len(h) > 253 {
		return errors.New("host is longer than 253 characters")
	}
	if strings.ContainsAny(h, ":/?#@[] ") {
		return fmt.Errorf("%q must be a bare host name without scheme, port, or path", h)
	}
	labels := strings.Split(h, ".")
	if len(labels) < 2 {
		return fmt.Errorf("%q must be a fully qualified domain name", h)
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 {
			return fmt.Errorf("%q has an empty or overlong label", h)
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return fmt.Errorf("%q has a label starting or ending with '-'", h)
		}
		for _, r := range l {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return fmt.Errorf("%q contains an invalid character %q", h, r)
			}
		}
	}
	last := labels[len(labels)-1]
	if _, err := strconv.Atoi(last); err == nil {
		return fmt.Errorf("%q looks like an IP address; a host name is required", h)
	}
	return nil
}
