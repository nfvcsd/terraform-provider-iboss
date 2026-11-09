package client_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nfvcsd/terraform-provider-iboss/internal/client"
	"github.com/nfvcsd/terraform-provider-iboss/internal/testutil"
)

func newSim(t *testing.T) (*testutil.Simulator, *client.Client) {
	t.Helper()
	testutil.ClearIBOSSEnv(t)
	sim := testutil.NewSimulator(t)
	c, err := client.New(sim.ClientConfig())
	if err != nil {
		t.Fatal(err)
	}
	return sim, c
}

func TestAPIKeyDiscoveryAndDocumentedHeaders(t *testing.T) {
	sim, c := newSim(t)
	ctx := context.Background()

	if _, err := c.AddURLEntry(ctx, client.Allowlist, 2, client.NewURLListEntry{URL: "example.org/a b&c=d"}); err != nil {
		t.Fatal(err)
	}
	got, err := c.ListURLEntries(ctx, client.Allowlist, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Entries) != 1 || got.Entries[0].URL != "example.org/a b&c=d" {
		t.Fatalf("entries = %+v", got.Entries)
	}
	if !got.Entries[0].DoDLPScan.Bool() {
		t.Errorf("expected doDlpScan from list response")
	}
	acct, _ := c.AccountSettingsID(ctx)
	if acct != testutil.SimAccountID {
		t.Errorf("account = %d, want primary %d", acct, testutil.SimAccountID)
	}
	gw, _ := c.GatewayHost(ctx)
	if gw != testutil.GatewayHost {
		t.Errorf("gateway = %q", gw)
	}

	reqs := sim.Requests()
	wantSeq := []string{
		"GET " + testutil.CoreHost + " /ibcloud/web/users/mySettings",
		"GET " + testutil.CoreHost + " /ibcloud/web/account/clusters",
		"PUT " + testutil.GatewayHost + " /json/controls/allowList",
		"GET " + testutil.GatewayHost + " /json/controls/allowList",
	}
	if len(reqs) != len(wantSeq) {
		t.Fatalf("got %d requests, want %d", len(reqs), len(wantSeq))
	}
	for i, r := range reqs {
		if got := r.Method + " " + r.Host + " " + r.Path; got != wantSeq[i] {
			t.Errorf("request %d = %q, want %q", i, got, wantSeq[i])
		}
		if r.Header.Get("Authorization") != "Token "+testutil.SimAPIKey {
			t.Errorf("request %d missing documented Authorization header", i)
		}
		if r.Header.Get("User-Agent") != "ibossAPI" {
			t.Errorf("request %d User-Agent = %q", i, r.Header.Get("User-Agent"))
		}
	}
	put := reqs[2]
	if put.Query["currentPolicyBeingEdited"][0] != "2" {
		t.Errorf("group query = %v", put.Query)
	}
	if put.Header.Get("X-XSRF-TOKEN") != testutil.SimXSRF {
		t.Errorf("missing X-XSRF-TOKEN")
	}
	if ck := put.Header.Get("Cookie"); !strings.Contains(ck, "XSRF-TOKEN="+testutil.SimXSRF) || !strings.Contains(ck, "JESSIONID="+testutil.SimAPIKey) {
		t.Errorf("cookie header = %q", ck)
	}
	if put.Header.Get("Content-Type") != "application/json;charset=UTF-8" {
		t.Errorf("content type = %q", put.Header.Get("Content-Type"))
	}
	var sent map[string]any
	if err := json.Unmarshal([]byte(put.Body), &sent); err != nil || len(sent) != 1 || sent["url"] != "example.org/a b&c=d" {
		t.Errorf("unset fields must be omitted; body = %s", put.Body)
	}
	if reqs[1].Query["accountSettingsId"][0] != "100001" {
		t.Errorf("clusters query = %v", reqs[1].Query)
	}
}

func TestAddSerializesAllFields(t *testing.T) {
	sim, c := newSim(t)
	note := "district policy"
	one, two := client.Int(1), client.Int(2)
	_, err := c.AddURLEntry(context.Background(), client.Blocklist, 1, client.NewURLListEntry{
		URL: "bad.example", Note: &note, IsRegex: &one, Global: &one, Direction: &two,
		Priority: &one, Weight: &two, StartPort: &one, EndPort: &two, ApplyKeywordAndSafeSearch: &one,
	})
	if err != nil {
		t.Fatal(err)
	}
	e := sim.Entries(client.Blocklist, 1)[0]
	for k, want := range map[string]any{"note": note, "isRegex": 1.0, "global": 1.0, "direction": 2.0, "weight": 2.0, "endPort": 2.0} {
		if e[k] != want {
			t.Errorf("%s = %v, want %v", k, e[k], want)
		}
	}
}

func TestDeleteEscapesURL(t *testing.T) {
	sim, c := newSim(t)
	sim.SetEntries(client.Blocklist, 3, map[string]any{"url": "x.example/?q=1&r=2"}, map[string]any{"url": "keep.example"})
	if _, err := c.DeleteURLEntry(context.Background(), client.Blocklist, 3, "x.example/?q=1&r=2"); err != nil {
		t.Fatal(err)
	}
	left := sim.Entries(client.Blocklist, 3)
	if len(left) != 1 || left[0]["url"] != "keep.example" {
		t.Fatalf("left = %v", left)
	}
}

func TestSecurityGroupsUseCoreSessionCookies(t *testing.T) {
	sim, c := newSim(t)
	groups, err := c.ListSecurityGroups(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 3 || groups[1].GroupName != "Students" || groups[1].GroupNumber.Int64 != 2 {
		t.Fatalf("groups = %+v", groups)
	}
	r := sim.Requests()[1]
	if !strings.Contains(r.Header.Get("Cookie"), "JESSIONID="+testutil.SimSessionID) {
		t.Errorf("core cookie = %q", r.Header.Get("Cookie"))
	}
	if sim.CountRequests(http.MethodGet, "/ibcloud/web/account/clusters") != 0 {
		t.Errorf("core-only call must not trigger gateway discovery")
	}
}

func TestAllowlistSettings(t *testing.T) {
	sim, c := newSim(t)
	sim.SetAllowlistSettings(4, map[string]any{"onlyAllowWhiteList": 1, "displayAllowedSitesPage": 1, "defaultTimedUrlTimeout": 30, "groupInheritanceGroupNumber": 1, "groupInheritancePolicy": 0, "message": ""})
	s, err := c.GetAllowlistSettings(context.Background(), 4)
	if err != nil {
		t.Fatal(err)
	}
	if !s.OnlyAllowWhiteList.Bool() || s.DefaultTimedURLTimeout.Int64 != 30 || s.CurrentPolicyBeingEdited.Int64 != 4 {
		t.Fatalf("settings = %+v", s)
	}
}

func TestLegacyLogin(t *testing.T) {
	testutil.ClearIBOSSEnv(t)
	sim := testutil.NewSimulator(t)
	sim.APIKey = "" // accept only the issued legacy token
	sim.TOTPCode = "123456"
	cfg := client.Config{Username: testutil.SimUsername, Password: testutil.SimPassword, TOTPCode: "123456"}
	sim.ConfigureClient(&cfg)
	c, err := client.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if c.Mode() != client.AuthModeLegacy {
		t.Fatalf("mode = %s", c.Mode())
	}
	if _, err := c.ListURLEntries(context.Background(), client.Allowlist, 1); err != nil {
		t.Fatal(err)
	}
	login := sim.Requests()[0]
	if login.Host != testutil.AccountsHost || login.Path != "/ibossauth/web/tokens" {
		t.Fatalf("first request = %s %s", login.Host, login.Path)
	}
	if login.Query["ignoreAuthModule"][0] != "true" || login.Query["totpCode"][0] != "123456" {
		t.Errorf("login query = %v", login.Query)
	}
	if login.Header.Get("Authorization") == "" || !strings.HasPrefix(login.Header.Get("Authorization"), "Basic ") {
		t.Errorf("login must use HTTP Basic auth")
	}
	if got := sim.Requests()[1].Header.Get("Authorization"); got != "Token "+testutil.SimLegacyToken {
		t.Errorf("token header = %q", got)
	}
}

func TestLegacyBadCredentialsAreNotRetried(t *testing.T) {
	testutil.ClearIBOSSEnv(t)
	sim := testutil.NewSimulator(t)
	cfg := client.Config{Username: testutil.SimUsername, Password: "wrong-password"}
	sim.ConfigureClient(&cfg)
	c, _ := client.New(cfg)
	_, err := c.ListURLEntries(context.Background(), client.Allowlist, 1)
	if !client.IsUnauthorized(err) {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), "wrong-password") {
		t.Errorf("password leaked in error: %v", err)
	}
	if n := sim.CountRequests(http.MethodGet, "/ibossauth/web/tokens"); n != 1 {
		t.Errorf("login attempts = %d, want 1", n)
	}
}

func TestLegacyTokenExpiryReauthenticatesOnce(t *testing.T) {
	testutil.ClearIBOSSEnv(t)
	sim := testutil.NewSimulator(t)
	sim.APIKey = ""
	cfg := client.Config{Username: testutil.SimUsername, Password: testutil.SimPassword}
	sim.ConfigureClient(&cfg)
	c, _ := client.New(cfg)
	ctx := context.Background()
	if _, err := c.ListURLEntries(ctx, client.Allowlist, 1); err != nil {
		t.Fatal(err)
	}
	sim.RotateLegacyToken("sim-legacy-token-0001")
	if _, err := c.ListURLEntries(ctx, client.Allowlist, 1); err != nil {
		t.Fatalf("expected one re-login to succeed: %v", err)
	}
	if n := sim.CountRequests(http.MethodGet, "/ibossauth/web/tokens"); n != 2 {
		t.Errorf("login attempts = %d, want 2", n)
	}
}

func TestLegacyWithTOTPDoesNotReauthenticate(t *testing.T) {
	testutil.ClearIBOSSEnv(t)
	sim := testutil.NewSimulator(t)
	sim.APIKey = ""
	sim.TOTPCode = "654321"
	cfg := client.Config{Username: testutil.SimUsername, Password: testutil.SimPassword, TOTPCode: "654321"}
	sim.ConfigureClient(&cfg)
	c, _ := client.New(cfg)
	ctx := context.Background()
	if _, err := c.ListURLEntries(ctx, client.Allowlist, 1); err != nil {
		t.Fatal(err)
	}
	sim.RotateLegacyToken("sim-legacy-token-0002")
	if _, err := c.ListURLEntries(ctx, client.Allowlist, 1); !client.IsUnauthorized(err) {
		t.Fatalf("err = %v, want 401", err)
	}
	if n := sim.CountRequests(http.MethodGet, "/ibossauth/web/tokens"); n != 1 {
		t.Errorf("a one-time code must not be replayed; logins = %d", n)
	}
}

func TestCredentialValidation(t *testing.T) {
	cases := map[string]client.Config{
		"none":        {},
		"conflicting": {APIKey: "k", Username: "u", Password: "p"},
		"no password": {Username: "u"},
		"totp only":   {TOTPCode: "1"},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := client.New(cfg); err == nil {
				t.Fatal("expected error")
			}
		})
	}
	if _, err := client.New(client.Config{APIKey: "k", GatewayHost: "https://x.example"}); err == nil {
		t.Error("expected invalid gateway host error")
	}
}

func TestDiscoveryRejectsForeignHostWithoutContactingIt(t *testing.T) {
	sim, c := newSim(t)
	sim.Clusters = []map[string]any{{"productFamily": "swg", "members": []any{
		map[string]any{"primary": "1", "cloudNode": map[string]any{"masterAdminInterfaceDns": "gateway.attacker.example"}},
	}}}
	_, err := c.ListURLEntries(context.Background(), client.Allowlist, 1)
	var de *client.DiscoveryError
	if !errors.As(err, &de) || !strings.Contains(err.Error(), "outside the allowed domains") {
		t.Fatalf("err = %v", err)
	}
	for _, r := range sim.Requests() {
		if r.Host != testutil.CoreHost {
			t.Errorf("unexpected request to %s", r.Host)
		}
	}
}

func TestDiscoveryErrors(t *testing.T) {
	cases := map[string][]map[string]any{
		"no swg": {{"productFamily": "reports", "members": []any{}}},
		"two primaries": {{"productFamily": "swg", "members": []any{
			map[string]any{"primary": 1, "cloudNode": map[string]any{"masterAdminInterfaceDns": "a" + testutil.HostSuffix}},
			map[string]any{"primary": 1, "cloudNode": map[string]any{"masterAdminInterfaceDns": "b" + testutil.HostSuffix}},
		}}},
		"host with port": {{"productFamily": "swg", "members": []any{
			map[string]any{"primary": 1, "cloudNode": map[string]any{"masterAdminInterfaceDns": "a" + testutil.HostSuffix + ":8443"}},
		}}},
	}
	for name, clusters := range cases {
		t.Run(name, func(t *testing.T) {
			sim, c := newSim(t)
			sim.Clusters = clusters
			_, err := c.ListURLEntries(context.Background(), client.Allowlist, 1)
			var de *client.DiscoveryError
			if !errors.As(err, &de) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestExplicitGatewayHostAndAccountSkipDiscovery(t *testing.T) {
	testutil.ClearIBOSSEnv(t)
	sim := testutil.NewSimulator(t)
	cfg := sim.ClientConfig()
	cfg.GatewayHost = testutil.GatewayHost
	cfg.AccountSettingsID = testutil.SimAccountID
	c, _ := client.New(cfg)
	if _, err := c.ListURLEntries(context.Background(), client.Blocklist, 1); err != nil {
		t.Fatal(err)
	}
	if sim.CountRequests(http.MethodGet, "/ibcloud/web/account/clusters") != 0 {
		t.Error("discovery should be skipped")
	}
	// mySettings is still required: it supplies the documented XSRF cookie.
	if sim.CountRequests(http.MethodGet, "/ibcloud/web/users/mySettings") != 1 {
		t.Error("expected one mySettings call")
	}
}

func TestAmbiguousPrimaryAccount(t *testing.T) {
	sim, c := newSim(t)
	sim.Accounts = []map[string]any{
		{"accountSettingsId": 1, "delegatedSuperAdminId": 0},
		{"accountSettingsId": 2, "delegatedSuperAdminId": "0"},
	}
	if _, err := c.ListSecurityGroups(context.Background()); err == nil || !strings.Contains(err.Error(), "account_settings_id") {
		t.Fatalf("err = %v", err)
	}
}

func TestGETRetriesTransientErrors(t *testing.T) {
	sim, c := newSim(t)
	ctx := context.Background()
	if _, err := c.GatewayHost(ctx); err != nil {
		t.Fatal(err)
	}
	sim.FailNext(http.MethodGet, "/json/controls/blockList", http.StatusServiceUnavailable, 1, nil)
	sim.FailNext(http.MethodGet, "/json/controls/blockList", http.StatusTooManyRequests, 1, map[string]string{"Retry-After": "0"})
	if _, err := c.ListURLEntries(ctx, client.Blocklist, 1); err != nil {
		t.Fatal(err)
	}
	if n := sim.CountRequests(http.MethodGet, "/json/controls/blockList"); n != 3 {
		t.Errorf("attempts = %d, want 3", n)
	}
}

func TestGETRetriesAreBounded(t *testing.T) {
	sim, c := newSim(t)
	ctx := context.Background()
	_, _ = c.GatewayHost(ctx)
	sim.FailNext(http.MethodGet, "/json/controls/blockList", http.StatusBadGateway, 100, nil)
	_, err := c.ListURLEntries(ctx, client.Blocklist, 1)
	var apiErr *client.APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusBadGateway {
		t.Fatalf("err = %v", err)
	}
	if n := sim.CountRequests(http.MethodGet, "/json/controls/blockList"); n != 4 {
		t.Errorf("attempts = %d, want 1 + 3 retries", n)
	}
}

func TestMutationsAreNotRetried(t *testing.T) {
	sim, c := newSim(t)
	ctx := context.Background()
	_, _ = c.GatewayHost(ctx)
	sim.FailNext(http.MethodPut, "/json/controls/allowList", http.StatusServiceUnavailable, 1, nil)
	sim.FailNext(http.MethodDelete, "/json/controls/allowList", http.StatusServiceUnavailable, 1, nil)
	if _, err := c.AddURLEntry(ctx, client.Allowlist, 1, client.NewURLListEntry{URL: "a.example"}); err == nil {
		t.Fatal("expected error")
	}
	if _, err := c.DeleteURLEntry(ctx, client.Allowlist, 1, "a.example"); err == nil {
		t.Fatal("expected error")
	}
	if sim.CountRequests(http.MethodPut, "/json/controls/allowList") != 1 || sim.CountRequests(http.MethodDelete, "/json/controls/allowList") != 1 {
		t.Error("mutations must be attempted exactly once")
	}
}

func TestUnauthorizedIsNotRetried(t *testing.T) {
	testutil.ClearIBOSSEnv(t)
	sim := testutil.NewSimulator(t)
	cfg := sim.ClientConfig()
	cfg.APIKey = "sim-wrong-key-9999"
	c, _ := client.New(cfg)
	_, err := c.ListURLEntries(context.Background(), client.Allowlist, 1)
	if !client.IsUnauthorized(err) {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), "sim-wrong-key-9999") {
		t.Errorf("api key leaked: %v", err)
	}
	if len(sim.Requests()) != 1 {
		t.Errorf("requests = %d, want 1", len(sim.Requests()))
	}
}

func TestErrorSnippetIsRedacted(t *testing.T) {
	sim, c := newSim(t)
	ctx := context.Background()
	_, _ = c.GatewayHost(ctx)
	// The failure body echoes credentials, as a misbehaving server might.
	sim.FailNextWithBody(http.MethodPut, "/json/controls/blockList", http.StatusBadRequest,
		`{"message":"bad token `+testutil.SimAPIKey+` xsrf `+testutil.SimXSRF+`"}`)
	_, err := c.AddURLEntry(ctx, client.Blocklist, 1, client.NewURLListEntry{URL: "x.example"})
	if err == nil || !strings.Contains(err.Error(), "[REDACTED]") {
		t.Fatalf("expected redacted error, got %v", err)
	}
	for _, secret := range []string{testutil.SimAPIKey, testutil.SimXSRF} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("secret leaked: %v", err)
		}
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	sim, c := newSim(t)
	ctx := context.Background()
	_, _ = c.GatewayHost(ctx)
	sim.FailNext(http.MethodGet, "/json/controls/allowList", http.StatusFound, 1, map[string]string{"Location": "https://collector.attacker.example/steal"})
	_, err := c.ListURLEntries(ctx, client.Allowlist, 1)
	var apiErr *client.APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusFound {
		t.Fatalf("err = %v", err)
	}
}

func TestMalformedResponse(t *testing.T) {
	sim, c := newSim(t)
	sim.Groups = nil
	sim.Accounts = []map[string]any{{"accountSettingsId": "not-a-number", "delegatedSuperAdminId": 0}}
	_, err := c.ListSecurityGroups(context.Background())
	var de *client.DecodeError
	if !errors.As(err, &de) {
		t.Fatalf("err = %v", err)
	}
}

func TestContextCancellationStopsRetries(t *testing.T) {
	testutil.ClearIBOSSEnv(t)
	sim := testutil.NewSimulator(t)
	cfg := sim.ClientConfig()
	cfg.RetryWaitMin = time.Hour
	cfg.RetryWaitMax = time.Hour
	c, _ := client.New(cfg)
	sim.FailNext(http.MethodGet, "/ibcloud/web/users/mySettings", http.StatusServiceUnavailable, 1, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := c.ListSecurityGroups(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Error("cancellation did not interrupt backoff")
	}
}

func TestConcurrentCallsShareOneSession(t *testing.T) {
	sim, c := newSim(t)
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			l := client.Allowlist
			if i%2 == 0 {
				l = client.Blocklist
			}
			_, err := c.ListURLEntries(context.Background(), l, int64(i%3+1))
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if n := sim.CountRequests(http.MethodGet, "/ibcloud/web/users/mySettings"); n != 1 {
		t.Errorf("mySettings calls = %d, want 1", n)
	}
	if n := sim.CountRequests(http.MethodGet, "/ibcloud/web/account/clusters"); n != 1 {
		t.Errorf("clusters calls = %d, want 1", n)
	}
}

func TestHarnessBlocksProductionHosts(t *testing.T) {
	testutil.ClearIBOSSEnv(t)
	sim := testutil.NewSimulator(t)
	// Omit the host overrides: the client defaults to the real iboss hosts,
	// and the fail-closed transport must refuse them without dialing.
	c, err := client.New(client.Config{APIKey: testutil.SimAPIKey, HTTPClient: sim.HTTPClient()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.ListSecurityGroups(context.Background())
	var blocked *client.BlockedDestinationError
	if !errors.As(err, &blocked) || !strings.Contains(blocked.Host, client.DefaultCoreHost) {
		t.Fatalf("err = %v", err)
	}
	if len(sim.Requests()) != 0 {
		t.Error("simulator should not have been reached")
	}
}

func TestHarnessBlocksPlainHTTPAndOtherPorts(t *testing.T) {
	testutil.ClearIBOSSEnv(t)
	sim := testutil.NewSimulator(t)
	hc := sim.HTTPClient()
	for _, u := range []string{"http://" + testutil.CoreHost + "/", "https://" + testutil.CoreHost + ":8443/", "https://127.0.0.1/"} {
		resp, err := hc.Get(u)
		if resp != nil {
			resp.Body.Close()
		}
		var blocked *client.BlockedDestinationError
		if !errors.As(err, &blocked) {
			t.Errorf("%s: err = %v", u, err)
		}
	}
}

func TestListRejectsResponsesWithoutEntries(t *testing.T) {
	cases := map[string]string{
		"message only": `{"message":"permission denied"}`,
		"wrong group":  `{"currentPolicyBeingEdited":9,"entries":[],"message":""}`,
		"null entries": `{"currentPolicyBeingEdited":1,"entries":null,"message":""}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			sim, c := newSim(t)
			ctx := context.Background()
			_, _ = c.GatewayHost(ctx)
			sim.FailNextWithBody(http.MethodGet, "/json/controls/allowList", http.StatusOK, body)
			_, err := c.ListURLEntries(ctx, client.Allowlist, 1)
			var de *client.DecodeError
			if !errors.As(err, &de) {
				t.Fatalf("err = %v, want DecodeError", err)
			}
		})
	}
}

func TestLegacyLoginIsNeverRetried(t *testing.T) {
	testutil.ClearIBOSSEnv(t)
	sim := testutil.NewSimulator(t)
	sim.APIKey = ""
	sim.TOTPCode = "111111"
	cfg := client.Config{Username: testutil.SimUsername, Password: testutil.SimPassword, TOTPCode: "111111"}
	sim.ConfigureClient(&cfg)
	c, _ := client.New(cfg)
	sim.FailNext(http.MethodGet, "/ibossauth/web/tokens", http.StatusServiceUnavailable, 1, nil)
	if _, err := c.ListSecurityGroups(context.Background()); err == nil {
		t.Fatal("expected error")
	}
	if n := sim.CountRequests(http.MethodGet, "/ibossauth/web/tokens"); n != 1 {
		t.Errorf("login attempts = %d, want 1 (a one-time code must not be re-sent)", n)
	}
}

func TestLegacyReloginDoesNotReplayMutations(t *testing.T) {
	testutil.ClearIBOSSEnv(t)
	sim := testutil.NewSimulator(t)
	sim.APIKey = ""
	cfg := client.Config{Username: testutil.SimUsername, Password: testutil.SimPassword}
	sim.ConfigureClient(&cfg)
	c, _ := client.New(cfg)
	ctx := context.Background()
	if _, err := c.ListURLEntries(ctx, client.Allowlist, 1); err != nil {
		t.Fatal(err)
	}
	sim.RotateLegacyToken("sim-legacy-token-0003")
	if _, err := c.AddURLEntry(ctx, client.Allowlist, 1, client.NewURLListEntry{URL: "once.example"}); !client.IsUnauthorized(err) {
		t.Fatalf("err = %v, want 401", err)
	}
	if n := sim.CountRequests(http.MethodPut, "/json/controls/allowList"); n != 1 {
		t.Errorf("PUT attempts = %d, want 1", n)
	}
	// The stale session was discarded, so the next call logs in again.
	if _, err := c.ListURLEntries(ctx, client.Allowlist, 1); err != nil {
		t.Fatal(err)
	}
	if n := sim.CountRequests(http.MethodGet, "/ibossauth/web/tokens"); n != 2 {
		t.Errorf("logins = %d, want 2", n)
	}
}

func TestErrorSnippetRedactedBeforeTruncation(t *testing.T) {
	sim, c := newSim(t)
	ctx := context.Background()
	_, _ = c.GatewayHost(ctx)
	body := `{"message":"` + strings.Repeat("x", 500) + testutil.SimAPIKey + strings.Repeat("y", 100) + `"}`
	sim.FailNextWithBody(http.MethodGet, "/json/controls/allowList", http.StatusBadRequest, body)
	_, err := c.ListURLEntries(ctx, client.Allowlist, 1)
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), testutil.SimAPIKey[:6]) {
		t.Errorf("partial secret leaked: %v", err)
	}
}

func TestLegacyLoginDefaultsToAccountsIbossCom(t *testing.T) {
	testutil.ClearIBOSSEnv(t)
	sim := testutil.NewSimulator(t)
	cfg := client.Config{Username: testutil.SimUsername, Password: testutil.SimPassword}
	sim.ConfigureClient(&cfg)
	cfg.AccountsHost = "" // use the built-in default
	c, err := client.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.ListSecurityGroups(context.Background())
	var blocked *client.BlockedDestinationError
	if !errors.As(err, &blocked) || blocked.Host != "accounts.iboss.com" {
		t.Fatalf("err = %v; want the login to target accounts.iboss.com (blocked by the test transport)", err)
	}
	if client.DefaultAccountsHost != "accounts.iboss.com" {
		t.Errorf("DefaultAccountsHost = %q", client.DefaultAccountsHost)
	}
}

func TestDiscoveryPrefersDefaultSWGCluster(t *testing.T) {
	sim, c := newSim(t)
	sim.Clusters = []map[string]any{
		testutil.SimCluster(1, "swg", "secondary"+testutil.HostSuffix, false),
		testutil.SimCluster(2, "reports", "reporting"+testutil.HostSuffix, true),
		testutil.SimCluster(3, "swg", testutil.GatewayHost, true),
	}
	if gw, err := c.GatewayHost(context.Background()); err != nil || gw != testutil.GatewayHost {
		t.Fatalf("gateway = %q, %v; want the default swg cluster's primary", gw, err)
	}
}

func TestDiscoveryWithoutDefaultFlagUsesOnlySWGCluster(t *testing.T) {
	sim, c := newSim(t)
	cl := testutil.SimCluster(3, "swg", testutil.GatewayHost, false)
	delete(cl, "defaultCluster")
	sim.Clusters = []map[string]any{cl}
	if gw, err := c.GatewayHost(context.Background()); err != nil || gw != testutil.GatewayHost {
		t.Fatalf("gateway = %q, %v", gw, err)
	}
}

func TestDiscoveryAmbiguityNamesCandidateHosts(t *testing.T) {
	cases := map[string][]map[string]any{
		"two default clusters": {
			testutil.SimCluster(1, "swg", "a"+testutil.HostSuffix, true),
			testutil.SimCluster(2, "swg", "b"+testutil.HostSuffix, true),
		},
		"no default flag on either": {
			testutil.SimCluster(1, "swg", "a"+testutil.HostSuffix, false),
			testutil.SimCluster(2, "swg", "b"+testutil.HostSuffix, false),
		},
	}
	for name, clusters := range cases {
		t.Run(name, func(t *testing.T) {
			sim, c := newSim(t)
			sim.Clusters = clusters
			_, err := c.GatewayHost(context.Background())
			if err == nil || !strings.Contains(err.Error(), "a"+testutil.HostSuffix+` (cluster "node-cluster" (id 1))`) ||
				!strings.Contains(err.Error(), "b"+testutil.HostSuffix) || !strings.Contains(err.Error(), "IBOSS_GATEWAY_HOST") {
				t.Fatalf("err = %v", err)
			}
		})
	}
}
