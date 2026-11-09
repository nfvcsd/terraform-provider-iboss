package provider_test

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/nfvcsd/terraform-provider-iboss/internal/client"
	"github.com/nfvcsd/terraform-provider-iboss/internal/provider"
	"github.com/nfvcsd/terraform-provider-iboss/internal/testutil"
)

func TestAccDataSources(t *testing.T) {
	sim := newAcc(t)
	sim.SetEntries(client.Allowlist, 2,
		map[string]any{"url": "google.com", "weight": 501, "applyKeywordAndSafeSearch": 1},
		map[string]any{"url": "dropbox.com/", "doDlpScan": 0},
	)
	sim.SetEntries(client.Blocklist, 2, map[string]any{"url": "weather.com/", "isTimedUrl": 1, "timedUrlExpiresInMinutes": 15})
	sim.SetAllowlistSettings(2, map[string]any{"onlyAllowWhiteList": 1, "displayAllowedSitesPage": 0, "defaultTimedUrlTimeout": 0, "groupInheritanceGroupNumber": 1, "groupInheritancePolicy": 0, "message": ""})

	cfg := providerAPIKey + `
data "iboss_security_group" "students" {
  name = "Students"
}
data "iboss_allowlist" "students" {
  group_number = data.iboss_security_group.students.group_number
}
data "iboss_blocklist" "students" {
  group_number = data.iboss_security_group.students.group_number
}
data "iboss_allowlist_settings" "students" {
  group_number = data.iboss_security_group.students.group_number
}
data "iboss_blocklist" "empty" {
  group_number = 9
}
`
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(sim),
		Steps: []resource.TestStep{{
			Config: cfg,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr("data.iboss_security_group.students", "group_number", "2"),
				resource.TestCheckResourceAttr("data.iboss_security_group.students", "reserved", "false"),
				resource.TestCheckResourceAttr("data.iboss_allowlist.students", "entries.#", "2"),
				resource.TestCheckResourceAttr("data.iboss_allowlist.students", "entries.0.url", "google.com"),
				resource.TestCheckResourceAttr("data.iboss_allowlist.students", "entries.0.weight", "501"),
				resource.TestCheckResourceAttr("data.iboss_allowlist.students", "entries.0.apply_keyword_and_safe_search", "true"),
				resource.TestCheckResourceAttr("data.iboss_allowlist.students", "entries.1.url", "dropbox.com/"),
				resource.TestCheckResourceAttr("data.iboss_allowlist.students", "entries.1.do_dlp_scan", "false"),
				resource.TestCheckResourceAttr("data.iboss_blocklist.students", "entries.#", "1"),
				resource.TestCheckResourceAttr("data.iboss_blocklist.students", "entries.0.is_timed_url", "true"),
				resource.TestCheckResourceAttr("data.iboss_blocklist.students", "entries.0.timed_url_expires_in_minutes", "15"),
				resource.TestCheckResourceAttr("data.iboss_blocklist.students", "entries.0.type", "1"),
				resource.TestCheckResourceAttr("data.iboss_allowlist_settings.students", "only_allow_allowlist", "true"),
				resource.TestCheckResourceAttr("data.iboss_allowlist_settings.students", "group_inheritance_group_number", "1"),
				resource.TestCheckResourceAttr("data.iboss_blocklist.empty", "entries.#", "0"),
			),
		}},
	})
}

func TestAccSecurityGroupLookup(t *testing.T) {
	sim := newAcc(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(sim),
		Steps: []resource.TestStep{
			{
				Config: providerAPIKey + `data "iboss_security_group" "g" { group_number = 3 }`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.iboss_security_group.g", "name", "Staff"),
					resource.TestCheckResourceAttr("data.iboss_security_group.g", "reserved", "true"),
					resource.TestCheckResourceAttr("data.iboss_security_group.g", "id", "3"),
				),
			},
			{
				Config:      providerAPIKey + `data "iboss_security_group" "g" { name = "students" }`,
				ExpectError: regexp.MustCompile(`Security group not found`),
			},
			{
				Config:      providerAPIKey + `data "iboss_security_group" "g" {}`,
				ExpectError: regexp.MustCompile(`Invalid Attribute Combination`),
			},
			{
				Config: providerAPIKey + `data "iboss_security_group" "g" {
  name         = "Staff"
  group_number = 3
}`,
				ExpectError: regexp.MustCompile(`Invalid Attribute Combination`),
			},
			{
				// End on a valid configuration so the post-test destroy can run.
				Config: providerAPIKey + `data "iboss_security_group" "g" { name = "Default" }`,
				Check:  resource.TestCheckResourceAttr("data.iboss_security_group.g", "group_number", "1"),
			},
		},
	})
}

func TestAccSecurityGroupDuplicateNames(t *testing.T) {
	sim := newAcc(t)
	sim.Groups = append(sim.Groups, map[string]any{"groupNumber": 8, "groupName": "Staff", "reservedGroup": 0})
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(sim),
		Steps: []resource.TestStep{{
			Config:      providerAPIKey + `data "iboss_security_group" "g" { name = "Staff" }`,
			ExpectError: regexp.MustCompile(`Multiple security groups found`),
		}},
	})
}

const dsOnly = `
data "iboss_security_group" "g" {
  group_number = 1
}
`

func TestAccProvider_envFallback(t *testing.T) {
	sim := newAcc(t)
	t.Setenv(provider.EnvAPIKey, testutil.SimAPIKey)
	t.Setenv(provider.EnvAccountSettingsID, "100001")
	t.Setenv(provider.EnvGatewayHost, testutil.GatewayHost)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(sim),
		Steps: []resource.TestStep{{
			Config: `provider "iboss" {}` + dsOnly + `
data "iboss_blocklist" "b" {
  group_number = 1
}`,
			Check: resource.TestCheckResourceAttr("data.iboss_security_group.g", "name", "Default"),
		}},
	})
	if sim.CountRequests("GET", "/ibcloud/web/account/clusters") != 0 {
		t.Error("IBOSS_GATEWAY_HOST should skip discovery")
	}
}

func TestAccProvider_configCredentialsIgnoreEnv(t *testing.T) {
	sim := newAcc(t)
	t.Setenv(provider.EnvUsername, "someone-else")
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(sim),
		Steps:                    []resource.TestStep{{Config: providerAPIKey + dsOnly}},
	})
}

func TestAccProvider_legacyLogin(t *testing.T) {
	sim := newAcc(t)
	sim.APIKey = "" // accept only the issued legacy token
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(sim),
		Steps: []resource.TestStep{{
			Config: `
provider "iboss" {
  username = "` + testutil.SimUsername + `"
  password = "` + testutil.SimPassword + `"
}` + dsOnly,
			Check: resource.TestCheckResourceAttr("data.iboss_security_group.g", "name", "Default"),
		}},
	})
}

func TestAccProvider_configurationErrors(t *testing.T) {
	sim := newAcc(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(sim),
		Steps: []resource.TestStep{
			{
				Config: `
provider "iboss" {
  api_key  = "k"
  username = "u"
  password = "p"
}` + dsOnly,
				ExpectError: regexp.MustCompile(`conflicting credentials`),
			},
			{
				Config:      `provider "iboss" {}` + dsOnly,
				ExpectError: regexp.MustCompile(`no credentials`),
			},
			{
				Config:      `provider "iboss" { username = "u" }` + dsOnly,
				ExpectError: regexp.MustCompile(`incomplete legacy credentials`),
			},
			{
				Config:      `provider "iboss" { api_key = "sim-wrong-key-1234" }` + dsOnly,
				ExpectError: regexp.MustCompile(`HTTP 401`),
			},
			{
				Config:      `provider "iboss" { account_settings_id = 0 }` + dsOnly,
				ExpectError: regexp.MustCompile(`must be at least 1`),
			},
		},
	})
}

func TestAccProvider_invalidEnvAccount(t *testing.T) {
	sim := newAcc(t)
	t.Setenv(provider.EnvAccountSettingsID, "abc")
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(sim),
		Steps: []resource.TestStep{{
			Config:      providerAPIKey + dsOnly,
			ExpectError: regexp.MustCompile(`IBOSS_ACCOUNT_SETTINGS_ID must be a positive integer`),
		}},
	})
}

func TestAccSecurityGroupsList(t *testing.T) {
	sim := newAcc(t)
	// Out of order on purpose: the data source sorts by group number.
	sim.Groups = []map[string]any{
		{"groupNumber": 32, "groupName": "NFVMBL_HS", "reservedGroup": 1, "note": "high school"},
		{"groupNumber": 10, "groupName": "NFVMBL_ValElem", "reservedGroup": 1},
		{"groupNumber": "20", "groupName": "NFVMBL_Staff", "reservedGroup": 0},
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(sim),
		Steps: []resource.TestStep{{
			Config: providerAPIKey + `data "iboss_security_groups" "all" {}`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr("data.iboss_security_groups.all", "id", "100001"),
				resource.TestCheckResourceAttr("data.iboss_security_groups.all", "groups.#", "3"),
				resource.TestCheckResourceAttr("data.iboss_security_groups.all", "groups.0.group_number", "10"),
				resource.TestCheckResourceAttr("data.iboss_security_groups.all", "groups.1.name", "NFVMBL_Staff"),
				resource.TestCheckResourceAttr("data.iboss_security_groups.all", "groups.2.name", "NFVMBL_HS"),
				resource.TestCheckResourceAttr("data.iboss_security_groups.all", "groups.2.note", "high school"),
				resource.TestCheckResourceAttr("data.iboss_security_groups.all", "groups.2.reserved", "true"),
			),
		}},
	})
}

func TestAccSecurityGroupsListRejectsDuplicateNumbers(t *testing.T) {
	sim := newAcc(t)
	sim.Groups = []map[string]any{{"groupNumber": 5, "groupName": "A"}, {"groupNumber": 5, "groupName": "B"}}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(sim),
		Steps: []resource.TestStep{{
			Config:      providerAPIKey + `data "iboss_security_groups" "all" {}`,
			ExpectError: regexp.MustCompile(`appears more than once`),
		}},
	})
}

// keepAccountsHost points the client at the simulator but keeps the
// accounts host the provider resolved from configuration.
func keepAccountsHost(sim *testutil.Simulator) map[string]func() (tfprotov6.ProviderServer, error) {
	hook := func(c *client.Config) {
		acct := c.AccountsHost
		sim.ConfigureClient(c)
		c.AccountsHost = acct
	}
	return map[string]func() (tfprotov6.ProviderServer, error){
		"iboss": providerserver.NewProtocol6WithError(provider.New("test", provider.WithClientConfig(hook))()),
	}
}

func TestAccProvider_accountsHost(t *testing.T) {
	sim := newAcc(t)
	sim.APIKey = ""
	legacy := `
provider "iboss" {
  username      = "` + testutil.SimUsername + `"
  password      = "` + testutil.SimPassword + `"
  accounts_host = "` + testutil.AccountsHost + `"
}` + dsOnly
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: keepAccountsHost(sim),
		Steps: []resource.TestStep{
			{
				Config: legacy,
				Check:  resource.TestCheckResourceAttr("data.iboss_security_group.g", "name", "Default"),
			},
			{
				Config: `
provider "iboss" {
  username      = "u"
  password      = "p"
  accounts_host = "https://accounts.example.com"
}` + dsOnly,
				ExpectError: regexp.MustCompile(`invalid accounts host`),
			},
			{Config: legacy},
		},
	})
	if n := sim.CountRequests("GET", "/ibossauth/web/tokens"); n == 0 {
		t.Error("login never reached the configured accounts host")
	}
}

func TestAccProvider_accountsHostFromEnv(t *testing.T) {
	sim := newAcc(t)
	sim.APIKey = ""
	t.Setenv(provider.EnvUsername, testutil.SimUsername)
	t.Setenv(provider.EnvPassword, testutil.SimPassword)
	t.Setenv(provider.EnvAccountsHost, testutil.AccountsHost)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: keepAccountsHost(sim),
		Steps: []resource.TestStep{{
			Config: `provider "iboss" {}` + dsOnly,
			Check:  resource.TestCheckResourceAttr("data.iboss_security_group.g", "name", "Default"),
		}},
	})
}
