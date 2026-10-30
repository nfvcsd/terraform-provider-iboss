package testutil

import (
	"net/http"
	"strings"
	"testing"
)

// fakeT captures cleanup errors so a test can assert the simulator flags them.
type fakeT struct {
	testing.TB
	errors []string
}

func (f *fakeT) Errorf(format string, args ...any) { f.errors = append(f.errors, format) }

func TestSimulatorRejectsUndocumentedRequests(t *testing.T) {
	sim := NewSimulator(t)
	sim.AllowUnexpected = true
	hc := sim.HTTPClient()

	do := func(method, url string, hdr map[string]string) int {
		req, _ := http.NewRequest(method, url, nil)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, url, err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	ua := map[string]string{"User-Agent": "ibossAPI", "Authorization": "Token " + SimAPIKey}

	if got := do(http.MethodGet, "https://"+GatewayHost+"/json/controls/firewallRules/all", ua); got != http.StatusNotImplemented {
		t.Errorf("unknown endpoint status = %d", got)
	}
	if got := do(http.MethodGet, "https://"+CoreHost+"/ibcloud/web/users/mySettings", nil); got != http.StatusBadRequest {
		t.Errorf("missing User-Agent status = %d", got)
	}
	if got := do(http.MethodGet, "https://"+GatewayHost+"/json/controls/allowList?currentPolicyBeingEdited=1", ua); got != http.StatusForbidden {
		t.Errorf("missing XSRF status = %d", got)
	}
	if got := do(http.MethodPatch, "https://"+GatewayHost+"/json/controls/allowList?currentPolicyBeingEdited=1",
		map[string]string{"User-Agent": "ibossAPI", "Authorization": "Token " + SimAPIKey, "X-XSRF-TOKEN": SimXSRF, "Cookie": "XSRF-TOKEN=" + SimXSRF}); got != http.StatusMethodNotAllowed {
		t.Errorf("undocumented method status = %d", got)
	}
	if n := len(sim.Unexpected()); n != 4 {
		t.Errorf("recorded unexpected = %d, want 4: %v", n, sim.Unexpected())
	}
}

func TestSimulatorCleanupFailsOnUnexpectedRequests(t *testing.T) {
	ft := &fakeT{TB: t}
	var cleanups []func()
	sim := newSimulatorWithCleanup(ft, func(f func()) { cleanups = append(cleanups, f) })
	resp, err := sim.HTTPClient().Get("https://" + CoreHost + "/not/documented")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	for i := len(cleanups) - 1; i >= 0; i-- {
		cleanups[i]()
	}
	if len(ft.errors) != 1 || !strings.Contains(ft.errors[0], "unexpected requests") {
		t.Fatalf("cleanup errors = %v", ft.errors)
	}
}
