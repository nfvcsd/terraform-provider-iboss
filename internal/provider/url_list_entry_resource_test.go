package provider_test

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/nfvcsd/iboss-terraform/internal/client"
	"github.com/nfvcsd/iboss-terraform/internal/testutil"
)

func entryConfig(kind string, group int, url, extra string) string {
	return providerAPIKey + fmt.Sprintf(`
resource "iboss_%s_entry" "test" {
  group_number = %d
  url          = %q
  %s
}
`, kind, group, url, extra)
}

func checkSimEntry(sim *testutil.Simulator, l client.URLList, group int64, url string, want map[string]any) resource.TestCheckFunc {
	return func(*terraform.State) error {
		var n int
		var got map[string]any
		for _, e := range sim.Entries(l, group) {
			if e["url"] == url {
				n++
				got = e
			}
		}
		if n != 1 {
			return fmt.Errorf("simulator has %d entries for %q, want 1", n, url)
		}
		for k, v := range want {
			if fmt.Sprint(got[k]) != fmt.Sprint(v) {
				return fmt.Errorf("simulator entry %s = %v, want %v", k, got[k], v)
			}
		}
		return nil
	}
}

func checkSimEmpty(sim *testutil.Simulator, l client.URLList, group int64) resource.TestCheckFunc {
	return func(*terraform.State) error {
		if e := sim.Entries(l, group); len(e) != 0 {
			return fmt.Errorf("simulator still has entries: %v", e)
		}
		return nil
	}
}

func TestAccAllowlistEntry_lifecycle(t *testing.T) {
	sim := newAcc(t)
	addr := "iboss_allowlist_entry.test"
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(sim),
		CheckDestroy:             checkSimEmpty(sim, client.Allowlist, 2),
		Steps: []resource.TestStep{
			{
				Config: entryConfig("allowlist", 2, "example.com", `note = "first"
  is_regex = false
  priority = 0`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(addr, "id", "2/example.com"),
					resource.TestCheckResourceAttr(addr, "note", "first"),
					resource.TestCheckResourceAttr(addr, "is_regex", "false"),
					resource.TestCheckResourceAttr(addr, "do_dlp_scan", "true"),
					resource.TestCheckResourceAttr(addr, "do_malware_scan", "true"),
					resource.TestCheckResourceAttr(addr, "global", "false"),
					checkSimEntry(sim, client.Allowlist, 2, "example.com", map[string]any{"note": "first", "isRegex": 0}),
				),
			},
			{
				ResourceName:      addr,
				ImportState:       true,
				ImportStateId:     "2/example.com",
				ImportStateVerify: true,
			},
			{
				Config: entryConfig("allowlist", 2, "example.com", `note = "second"
  is_regex = false
  priority = 0`),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(addr, plancheck.ResourceActionReplace)},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(addr, "note", "second"),
					checkSimEntry(sim, client.Allowlist, 2, "example.com", map[string]any{"note": "second"}),
				),
			},
		},
	})
}

func TestAccBlocklistEntry_serverDefaultsAndNoopPlan(t *testing.T) {
	sim := newAcc(t)
	addr := "iboss_blocklist_entry.test"
	cfg := entryConfig("blocklist", 3, "games.example", "")
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(sim),
		CheckDestroy:             checkSimEmpty(sim, client.Blocklist, 3),
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(addr, "type", "1"),
					resource.TestCheckResourceAttr(addr, "note", ""),
					resource.TestCheckResourceAttr(addr, "is_regex", "false"),
					resource.TestCheckResourceAttr(addr, "start_port", "0"),
					resource.TestCheckNoResourceAttr(addr, "do_dlp_scan"),
					func(*terraform.State) error {
						// Only the configured url may be sent; omitted
						// arguments must leave server defaults alone.
						for _, r := range sim.Requests() {
							if r.Method == http.MethodPut && r.Body != `{"url":"games.example"}` {
								return fmt.Errorf("unexpected add body %s", r.Body)
							}
						}
						return nil
					},
				),
			},
			{
				Config: cfg,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
			{
				ResourceName:      addr,
				ImportState:       true,
				ImportStateId:     "3/games.example",
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccEntry_driftAndExternalDeletion(t *testing.T) {
	sim := newAcc(t)
	addr := "iboss_blocklist_entry.test"
	cfg := entryConfig("blocklist", 1, "drift.example", `note = "managed"`)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(sim),
		CheckDestroy:             checkSimEmpty(sim, client.Blocklist, 1),
		Steps: []resource.TestStep{
			{Config: cfg},
			{
				PreConfig: func() {
					if !sim.UpdateEntry(client.Blocklist, 1, "drift.example", map[string]any{"note": "changed in console"}) {
						t.Fatal("entry missing from simulator")
					}
				},
				Config: cfg,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(addr, plancheck.ResourceActionReplace)},
				},
				Check: checkSimEntry(sim, client.Blocklist, 1, "drift.example", map[string]any{"note": "managed"}),
			},
			{
				PreConfig: func() { sim.SetEntries(client.Blocklist, 1) },
				Config:    cfg,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(addr, plancheck.ResourceActionCreate)},
				},
				Check: checkSimEntry(sim, client.Blocklist, 1, "drift.example", nil),
			},
		},
	})
}

func TestAccEntry_equivalentServerSpelling(t *testing.T) {
	sim := newAcc(t)
	addr := "iboss_allowlist_entry.test"
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(sim),
		CheckDestroy:             checkSimEmpty(sim, client.Allowlist, 1),
		Steps: []resource.TestStep{
			{
				Config: entryConfig("allowlist", 1, "dropbox.com", ""),
				// Simulate the server storing a normalized spelling (the
				// documented example shows "dropbox.com/").
				Check: func(*terraform.State) error {
					if !sim.UpdateEntry(client.Allowlist, 1, "dropbox.com", map[string]any{"url": "dropbox.com/"}) {
						return fmt.Errorf("entry missing")
					}
					return nil
				},
			},
			{
				Config: entryConfig("allowlist", 1, "dropbox.com", ""),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
				Check: resource.TestCheckResourceAttr(addr, "url", "dropbox.com"),
			},
		},
	})
}

func TestAccEntry_existingEntryIsNotAdopted(t *testing.T) {
	sim := newAcc(t)
	sim.SetEntries(client.Allowlist, 2, map[string]any{"url": "already.example", "note": "manual"})
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(sim),
		Steps: []resource.TestStep{{
			Config:      entryConfig("allowlist", 2, "already.example", ""),
			ExpectError: regexp.MustCompile(`(?s)already contains.*terraform import`),
		}},
	})
	if n := sim.CountRequests(http.MethodPut, "/json/controls/allowList"); n != 0 {
		t.Errorf("add requests = %d, want 0", n)
	}
}

func TestAccEntry_readErrorKeepsState(t *testing.T) {
	sim := newAcc(t)
	cfg := entryConfig("allowlist", 2, "keep.example", "")
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(sim),
		CheckDestroy:             checkSimEmpty(sim, client.Allowlist, 2),
		Steps: []resource.TestStep{
			{Config: cfg},
			{
				PreConfig:    func() { sim.FailNext(http.MethodGet, "/json/controls/allowList", http.StatusForbidden, 1, nil) },
				RefreshState: true,
				ExpectError:  regexp.MustCompile(`HTTP 403`),
			},
			{
				Config: cfg,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
		},
	})
	if n := sim.CountRequests(http.MethodPut, "/json/controls/allowList"); n != 1 {
		t.Errorf("add requests = %d, want 1 (a read error must not cause re-creation)", n)
	}
}

func TestAccEntry_concurrentEntriesInOneGroup(t *testing.T) {
	sim := newAcc(t)
	cfg := providerAPIKey + `
locals {
  urls = ["a.example", "b.example", "c.example", "d.example", "e.example", "f.example"]
}
resource "iboss_blocklist_entry" "many" {
  count        = length(local.urls)
  group_number = 4
  url          = local.urls[count.index]
}
`
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(sim),
		CheckDestroy:             checkSimEmpty(sim, client.Blocklist, 4),
		Steps: []resource.TestStep{{
			Config: cfg,
			Check: func(*terraform.State) error {
				if n := len(sim.Entries(client.Blocklist, 4)); n != 6 {
					return fmt.Errorf("entries = %d, want 6", n)
				}
				return nil
			},
		}},
	})
}

func TestAccEntry_invalidImportID(t *testing.T) {
	sim := newAcc(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(sim),
		Steps: []resource.TestStep{{
			Config:        entryConfig("allowlist", 1, "x.example", ""),
			ResourceName:  "iboss_allowlist_entry.test",
			ImportState:   true,
			ImportStateId: "not-a-group",
			ExpectError:   regexp.MustCompile(`Invalid import ID`),
		}},
	})
}

func TestAccEntry_invalidArguments(t *testing.T) {
	sim := newAcc(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(sim),
		Steps: []resource.TestStep{
			{
				Config:      entryConfig("blocklist", 1, "", ""),
				ExpectError: regexp.MustCompile(`string length must be at least 1`),
			},
			{
				Config:      entryConfig("blocklist", 1, "p.example", `end_port = 70000`),
				ExpectError: regexp.MustCompile(`must be between 0 and 65535`),
			},
		},
	})
	if len(sim.Requests()) != 0 {
		t.Errorf("validation must not reach the API; got %d requests", len(sim.Requests()))
	}
}

func TestAccEntry_messageResponseKeepsState(t *testing.T) {
	sim := newAcc(t)
	cfg := entryConfig("blocklist", 2, "msg.example", "")
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(sim),
		CheckDestroy:             checkSimEmpty(sim, client.Blocklist, 2),
		Steps: []resource.TestStep{
			{Config: cfg},
			{
				// HTTP 200 with only a message must not be read as "entry gone".
				PreConfig: func() {
					sim.FailNextWithBody(http.MethodGet, "/json/controls/blockList", http.StatusOK, `{"message":"permission denied"}`)
				},
				RefreshState: true,
				ExpectError:  regexp.MustCompile(`no entries field`),
			},
			{
				// A message alongside entries is also not trusted for state decisions.
				PreConfig: func() {
					sim.FailNextWithBody(http.MethodGet, "/json/controls/blockList", http.StatusOK,
						`{"currentPolicyBeingEdited":2,"entries":[],"message":"partial result"}`)
				},
				RefreshState: true,
				ExpectError:  regexp.MustCompile(`partial result`),
			},
			{
				Config: cfg,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
		},
	})
}

func TestAccEntry_serverNormalizedURLIsRolledBack(t *testing.T) {
	sim := newAcc(t)
	sim.OnAdd = func(_ client.URLList, _ int64, e map[string]any) {
		e["url"] = strings.TrimPrefix(e["url"].(string), "https://")
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(sim),
		Steps: []resource.TestStep{{
			Config:      entryConfig("allowlist", 1, "https://norm.example", ""),
			ExpectError: regexp.MustCompile(`iboss changed the URL`),
		}},
	})
	if e := sim.Entries(client.Allowlist, 1); len(e) != 0 {
		t.Errorf("rolled-back entry left behind: %v", e)
	}
	if n := sim.CountRequests(http.MethodDelete, "/json/controls/allowList"); n != 1 {
		t.Errorf("DELETE requests = %d, want 1", n)
	}
}

func TestAccEntry_serverAdjustedValueIsReported(t *testing.T) {
	sim := newAcc(t)
	sim.OnAdd = func(_ client.URLList, _ int64, e map[string]any) {
		if n, ok := e["note"].(string); ok {
			e["note"] = strings.TrimSpace(n)
		}
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(sim),
		CheckDestroy:             checkSimEmpty(sim, client.Blocklist, 1),
		Steps: []resource.TestStep{
			{
				Config:      entryConfig("blocklist", 1, "trim.example", `note = "trimmed "`),
				ExpectError: regexp.MustCompile(`(?s)stored different values.*note: configured "trimmed ", stored "trimmed"`),
			},
			{
				// After correcting the configuration, the tainted entry is replaced.
				Config: entryConfig("blocklist", 1, "trim.example", `note = "trimmed"`),
				Check:  checkSimEntry(sim, client.Blocklist, 1, "trim.example", map[string]any{"note": "trimmed"}),
			},
		},
	})
}
