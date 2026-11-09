// Package testutil provides a deterministic local iboss simulator and a
// fail-closed test harness. Nothing here ever contacts a real iboss service.
//
// The simulator models only documented behavior (Postman collection
// 2s93RUuXjk). Where the documentation is silent — server defaults, duplicate
// adds, deleting absent entries — it makes a conservative, explicit choice
// noted inline. Passing tests against it are not proof of live compatibility.
package testutil

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nfvcsd/iboss-terraform/internal/client"
)

// Synthetic hosts. ".iboss.test" is a reserved test TLD; none resolve.
const (
	CoreHost     = "core.sim.iboss.test"
	AccountsHost = "accounts.sim.iboss.test"
	GatewayHost  = "gateway.sim.iboss.test"
	HostSuffix   = ".sim.iboss.test"

	SimAPIKey      = "sim-api-key-0000"
	SimUsername    = "sim-admin@example.invalid"
	SimPassword    = "sim-password-0000"
	SimLegacyToken = "sim-legacy-token-0000"
	SimXSRF        = "sim-xsrf-0000"
	SimSessionID   = "sim-session-0000"
	SimAccountID   = int64(100001)
)

// Request records one request received by the simulator.
type Request struct {
	Host   string
	Method string
	Path   string
	Query  map[string][]string
	Header http.Header
	Body   string
}

type failure struct {
	method, path string
	status       int
	header       map[string]string
	body         string
	remaining    int
}

// Simulator is an in-process iboss API double served over TLS.
type Simulator struct {
	t      testing.TB
	server *httptest.Server
	guard  *GuardTransport

	mu sync.Mutex
	// Credentials accepted by the simulator.
	APIKey      string
	Username    string
	Password    string
	TOTPCode    string
	LegacyToken string
	// Accounts is the mySettings response; Clusters the clusters response.
	Accounts []map[string]any
	Clusters []map[string]any
	Groups   []map[string]any

	lists      map[client.URLList]map[int64][]map[string]any
	settings   map[int64]map[string]any
	failures   []*failure
	requests   []Request
	unexpected []string
	// AllowUnexpected disables the cleanup assertion for tests that probe
	// rejection paths on purpose.
	AllowUnexpected bool
	// OnAdd, when set, may rewrite an entry before it is stored (simulating
	// undocumented server-side normalization). Called with the lock held.
	OnAdd func(l client.URLList, group int64, entry map[string]any)
}

// NewSimulator starts a simulator answering for CoreHost, AccountsHost, and
// GatewayHost, and registers cleanup that fails the test on any unexpected
// request.
func NewSimulator(t testing.TB) *Simulator {
	t.Helper()
	return newSimulatorWithCleanup(t, t.Cleanup)
}

func newSimulatorWithCleanup(t testing.TB, cleanup func(func())) *Simulator {
	t.Helper()
	s := &Simulator{
		t:           t,
		APIKey:      SimAPIKey,
		Username:    SimUsername,
		Password:    SimPassword,
		LegacyToken: SimLegacyToken,
		Accounts: []map[string]any{
			{"name": "Delegated", "accountSettingsId": SimAccountID + 1, "delegatedSuperAdminId": 7},
			{"name": "Primary", "accountSettingsId": SimAccountID, "delegatedSuperAdminId": 0},
		},
		Clusters: []map[string]any{
			simCluster("reports", "reporting.sim.iboss.test"),
			simCluster("swg", GatewayHost),
		},
		Groups: []map[string]any{
			simGroup(1, "Default", 0),
			simGroup(2, "Students", 0),
			simGroup(3, "Staff", 1),
		},
		lists: map[client.URLList]map[int64][]map[string]any{
			client.Allowlist: {}, client.Blocklist: {},
		},
		settings: map[int64]map[string]any{},
	}
	cert, pool := selfSignedCert(t, []string{CoreHost, AccountsHost, GatewayHost})
	s.server = httptest.NewUnstartedServer(http.HandlerFunc(s.handle))
	s.server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	s.server.Config.ErrorLog = nil
	s.server.StartTLS()
	addr := s.server.Listener.Addr().String()
	s.guard = NewGuardTransport(map[string]string{
		net.JoinHostPort(CoreHost, "443"):     addr,
		net.JoinHostPort(AccountsHost, "443"): addr,
		net.JoinHostPort(GatewayHost, "443"):  addr,
	}, pool)
	cleanup(func() {
		s.guard.CloseIdleConnections()
		s.server.Close()
		s.mu.Lock()
		defer s.mu.Unlock()
		if len(s.unexpected) > 0 && !s.AllowUnexpected {
			t.Errorf("simulator received unexpected requests:\n  %s", strings.Join(s.unexpected, "\n  "))
		}
	})
	return s
}

func simCluster(family, host string) map[string]any {
	return map[string]any{
		"productFamily": family,
		"clusterType":   "multivalue",
		"members": []any{
			map[string]any{"primary": 1, "cloudNode": map[string]any{"masterAdminInterfaceDns": host}},
		},
	}
}

func simGroup(n int64, name string, reserved int64) map[string]any {
	return map[string]any{
		"type":                 "com.phantom.common.ibcloud.data.AccountSettingsFilteringGroup",
		"accountSettingsId":    SimAccountID,
		"groupNumber":          n,
		"groupName":            name,
		"note":                 "",
		"priority":             0,
		"parentGroupNumber":    0,
		"reportingGroupNumber": 0,
		"reservedGroup":        reserved,
		"itemId":               n,
	}
}

// HTTPClient returns a client whose transport can only reach this simulator.
func (s *Simulator) HTTPClient() *http.Client {
	return &http.Client{Transport: s.guard, Timeout: 30 * time.Second}
}

// ClientConfig returns an API-key client configuration aimed at the simulator.
func (s *Simulator) ClientConfig() client.Config {
	return client.Config{
		APIKey:                        s.APIKey,
		CoreHost:                      CoreHost,
		AccountsHost:                  AccountsHost,
		AllowedDiscoveredHostSuffixes: []string{HostSuffix},
		HTTPClient:                    s.HTTPClient(),
		RequestTimeout:                10 * time.Second,
		RetryWaitMin:                  time.Millisecond,
		RetryWaitMax:                  5 * time.Millisecond,
	}
}

// ConfigureClient points cfg at the simulator without changing credentials.
func (s *Simulator) ConfigureClient(cfg *client.Config) {
	cfg.CoreHost = CoreHost
	cfg.AccountsHost = AccountsHost
	cfg.AllowedDiscoveredHostSuffixes = []string{HostSuffix}
	cfg.HTTPClient = s.HTTPClient()
	cfg.RequestTimeout = 10 * time.Second
	cfg.RetryWaitMin = time.Millisecond
	cfg.RetryWaitMax = 5 * time.Millisecond
}

// FailNext makes the next n matching requests return status with optional headers.
func (s *Simulator) FailNext(method, path string, status, n int, header map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failures = append(s.failures, &failure{method: method, path: path, status: status, header: header, remaining: n, body: `{"message":"simulated failure"}`})
}

// RenameGroup changes a security group's name (simulating a console edit).
func (s *Simulator) RenameGroup(number int64, name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, g := range s.Groups {
		if fmt.Sprint(g["groupNumber"]) == strconv.FormatInt(number, 10) {
			g["groupName"] = name
			return true
		}
	}
	return false
}

// FailNextWithBody is FailNext with a custom response body.
func (s *Simulator) FailNextWithBody(method, path string, status int, body string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failures = append(s.failures, &failure{method: method, path: path, status: status, remaining: 1, body: body})
}

// SetEntries replaces a list's entries (simulating out-of-band changes).
func (s *Simulator) SetEntries(l client.URLList, group int64, entries ...map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		cp = append(cp, s.withDefaults(l, e))
	}
	s.lists[l][group] = cp
}

// Entries returns a copy of a list's entries.
func (s *Simulator) Entries(l client.URLList, group int64) []map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []map[string]any
	for _, e := range s.lists[l][group] {
		cp := map[string]any{}
		for k, v := range e {
			cp[k] = v
		}
		out = append(out, cp)
	}
	return out
}

// UpdateEntry mutates one stored entry in place (simulating drift).
func (s *Simulator) UpdateEntry(l client.URLList, group int64, url string, changes map[string]any) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.lists[l][group] {
		if e["url"] == url {
			for k, v := range changes {
				e[k] = v
			}
			return true
		}
	}
	return false
}

// SetAllowlistSettings sets the settings returned for a group.
func (s *Simulator) SetAllowlistSettings(group int64, v map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.settings[group] = v
}

// RotateLegacyToken invalidates the current legacy token (simulating expiry).
func (s *Simulator) RotateLegacyToken(next string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LegacyToken = next
}

// Requests returns the requests received so far.
func (s *Simulator) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.requests...)
}

// CountRequests counts received requests matching method and path.
func (s *Simulator) CountRequests(method, path string) int {
	n := 0
	for _, r := range s.Requests() {
		if r.Method == method && r.Path == path {
			n++
		}
	}
	return n
}

// Unexpected returns descriptions of rejected requests.
func (s *Simulator) Unexpected() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.unexpected...)
}

func (s *Simulator) handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	host := strings.ToLower(r.Host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, Request{Host: host, Method: r.Method, Path: r.URL.Path, Query: r.URL.Query(), Header: r.Header.Clone(), Body: string(body)})

	for i, f := range s.failures {
		if f.method == r.Method && f.path == r.URL.Path && f.remaining > 0 {
			f.remaining--
			if f.remaining == 0 {
				s.failures = append(s.failures[:i], s.failures[i+1:]...)
			}
			for k, v := range f.header {
				w.Header().Set(k, v)
			}
			writeJSONRaw(w, f.status, f.body)
			return
		}
	}

	if r.Header.Get("User-Agent") != client.DefaultUserAgent {
		s.reject(w, r, http.StatusBadRequest, "missing documented User-Agent")
		return
	}
	key := r.Method + " " + host + r.URL.Path
	switch key {
	case "GET " + AccountsHost + "/ibossauth/web/tokens":
		s.handleLogin(w, r)
	case "GET " + CoreHost + "/ibcloud/web/users/mySettings":
		if !s.tokenOK(w, r) {
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "XSRF-TOKEN", Value: SimXSRF, Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: "JSESSIONID", Value: SimSessionID, Path: "/", HttpOnly: true})
		writeJSON(w, http.StatusOK, s.Accounts)
	case "GET " + CoreHost + "/ibcloud/web/account/clusters":
		if !s.tokenOK(w, r) || !s.accountOK(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, s.Clusters)
	case "GET " + CoreHost + "/ibcloud/web/groups/filtering":
		if !s.tokenOK(w, r) || !s.xsrfOK(w, r) || !s.accountOK(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, s.Groups)
	case "GET " + GatewayHost + "/json/controls/allowList/settings":
		group, ok := s.gatewayOK(w, r)
		if !ok {
			return
		}
		v, found := s.settings[group]
		if !found {
			v = map[string]any{"defaultTimedUrlTimeout": 0, "displayAllowedSitesPage": 0, "groupInheritanceGroupNumber": group, "groupInheritancePolicy": 0, "message": "", "onlyAllowWhiteList": 0}
		}
		v["currentPolicyBeingEdited"] = group
		writeJSON(w, http.StatusOK, v)
	default:
		if host == GatewayHost && (r.URL.Path == "/json/controls/allowList" || r.URL.Path == "/json/controls/blockList") {
			s.handleList(w, r, client.URLList(strings.TrimPrefix(r.URL.Path, "/json/controls/")), body)
			return
		}
		s.reject(w, r, http.StatusNotImplemented, "no simulated endpoint")
	}
}

func (s *Simulator) reject(w http.ResponseWriter, r *http.Request, status int, why string) {
	s.unexpected = append(s.unexpected, fmt.Sprintf("%s https://%s%s (%s)", r.Method, r.Host, r.URL.Path, why))
	writeJSON(w, status, map[string]string{"message": "simulator: " + why})
}

func (s *Simulator) handleLogin(w http.ResponseWriter, r *http.Request) {
	u, p, ok := r.BasicAuth()
	q := r.URL.Query()
	if q.Get("ignoreAuthModule") != "true" {
		s.reject(w, r, http.StatusBadRequest, "ignoreAuthModule=true is documented")
		return
	}
	if !ok || u != s.Username || p != s.Password || (s.TOTPCode != "" && q.Get("totpCode") != s.TOTPCode) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"message": "invalid credentials"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"token": s.LegacyToken})
}

func (s *Simulator) tokenOK(w http.ResponseWriter, r *http.Request) bool {
	got := r.Header.Get("Authorization")
	if got == "Token "+s.APIKey || (s.LegacyToken != "" && got == "Token "+s.LegacyToken) {
		return true
	}
	writeJSON(w, http.StatusUnauthorized, map[string]string{"message": "unauthorized"})
	return false
}

func (s *Simulator) xsrfOK(w http.ResponseWriter, r *http.Request) bool {
	ck, err := r.Cookie("XSRF-TOKEN")
	if r.Header.Get("X-XSRF-TOKEN") != SimXSRF || err != nil || ck.Value != SimXSRF {
		s.reject(w, r, http.StatusForbidden, "documented XSRF header/cookie missing")
		return false
	}
	return true
}

func (s *Simulator) accountOK(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Query().Get("accountSettingsId") != strconv.FormatInt(SimAccountID, 10) {
		s.reject(w, r, http.StatusBadRequest, "wrong accountSettingsId")
		return false
	}
	return true
}

func (s *Simulator) gatewayOK(w http.ResponseWriter, r *http.Request) (int64, bool) {
	if !s.tokenOK(w, r) || !s.xsrfOK(w, r) {
		return 0, false
	}
	g, err := strconv.ParseInt(r.URL.Query().Get("currentPolicyBeingEdited"), 10, 64)
	if err != nil {
		s.reject(w, r, http.StatusBadRequest, "currentPolicyBeingEdited is required")
		return 0, false
	}
	return g, true
}

// Fields documented in the add-entry example bodies.
var addFields = map[string]bool{
	"url": true, "applyKeywordAndSafeSearch": true, "direction": true, "endPort": true,
	"global": true, "isRegex": true, "isTimedUrl": true, "note": true, "priority": true,
	"startPort": true, "timedUrl": true, "weight": true,
}

func (s *Simulator) handleList(w http.ResponseWriter, r *http.Request, l client.URLList, body []byte) {
	group, ok := s.gatewayOK(w, r)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		entries := s.lists[l][group]
		if entries == nil {
			entries = []map[string]any{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"currentPolicyBeingEdited": group, "entries": entries, "message": ""})
	case http.MethodPut:
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			s.reject(w, r, http.StatusUnsupportedMediaType, "documented Content-Type missing")
			return
		}
		var in map[string]any
		if err := json.Unmarshal(body, &in); err != nil {
			s.reject(w, r, http.StatusBadRequest, "body is not a JSON object")
			return
		}
		var unknown []string
		for k := range in {
			if !addFields[k] {
				unknown = append(unknown, k)
			}
		}
		sort.Strings(unknown)
		if len(unknown) > 0 {
			s.reject(w, r, http.StatusBadRequest, "undocumented fields "+strings.Join(unknown, ","))
			return
		}
		u, _ := in["url"].(string)
		if u == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "url is required"})
			return
		}
		delete(in, "timedUrl")
		stored := s.withDefaults(l, in)
		if s.OnAdd != nil {
			s.OnAdd(l, group, stored)
		}
		// Undocumented: behavior when the URL already exists. The simulator
		// appends, which is the worst case for a client that does not check.
		s.lists[l][group] = append(s.lists[l][group], stored)
		writeJSON(w, http.StatusOK, map[string]any{"message": ""})
	case http.MethodDelete:
		u := r.URL.Query().Get("url")
		kept := s.lists[l][group][:0]
		for _, e := range s.lists[l][group] {
			if e["url"] != u {
				kept = append(kept, e)
			}
		}
		s.lists[l][group] = kept
		writeJSON(w, http.StatusOK, map[string]any{"message": ""})
	default:
		s.reject(w, r, http.StatusMethodNotAllowed, "method not documented")
	}
}

// withDefaults fills fields the documented list responses always include.
// Values for omitted fields are simulator choices, not documented defaults.
func (s *Simulator) withDefaults(l client.URLList, in map[string]any) map[string]any {
	out := map[string]any{
		"applyKeywordAndSafeSearch": 0, "direction": 0, "endPort": 0, "global": 0,
		"isRegex": 0, "isTimedUrl": 0, "note": "", "priority": 0, "resourceId": "",
		"startPort": 0, "timedUrlExpiresInMinutes": 0, "weight": 0,
	}
	if l == client.Allowlist {
		out["doDlpScan"] = 1
		out["doMalwareScan"] = 1
	} else {
		out["type"] = 1
	}
	for k, v := range in {
		out[k] = v
	}
	return out
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, _ := json.Marshal(v)
	writeJSONRaw(w, status, string(b))
}

func writeJSONRaw(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

// ClearIBOSSEnv removes every inherited IBOSS_ variable for the test's duration.
func ClearIBOSSEnv(t testing.TB) {
	t.Helper()
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(k, "IBOSS_") {
			if tt, ok := t.(*testing.T); ok {
				tt.Setenv(k, "")
			}
			_ = os.Unsetenv(k)
		}
	}
}
