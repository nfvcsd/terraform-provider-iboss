package provider_test

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	fwprovider "github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"

	"github.com/nfvcsd/iboss-terraform/internal/provider"
	"github.com/nfvcsd/iboss-terraform/internal/testutil"
)

const providerAPIKey = `
provider "iboss" {
  api_key = "` + testutil.SimAPIKey + `"
}
`

// factories returns provider factories wired to sim. Every client the
// provider builds uses the fail-closed simulator transport.
func factories(sim *testutil.Simulator) map[string]func() (tfprotov6.ProviderServer, error) {
	return map[string]func() (tfprotov6.ProviderServer, error){
		"iboss": providerserver.NewProtocol6WithError(provider.New("test", provider.WithClientConfig(sim.ConfigureClient))()),
	}
}

// newAcc clears inherited IBOSS_ variables and starts a simulator.
func newAcc(t *testing.T) *testutil.Simulator {
	t.Helper()
	testutil.ClearIBOSSEnv(t)
	return testutil.NewSimulator(t)
}

func TestSchemasAreValid(t *testing.T) {
	ctx := context.Background()
	p := provider.New("test")()

	var ps fwprovider.SchemaResponse
	p.Schema(ctx, fwprovider.SchemaRequest{}, &ps)
	if ps.Diagnostics.HasError() {
		t.Fatalf("provider schema: %v", ps.Diagnostics)
	}
	if d := ps.Schema.ValidateImplementation(ctx); d.HasError() {
		t.Fatalf("provider schema: %v", d)
	}
	for _, f := range p.Resources(ctx) {
		r := f()
		var md resource.MetadataResponse
		r.Metadata(ctx, resource.MetadataRequest{ProviderTypeName: "iboss"}, &md)
		var sr resource.SchemaResponse
		r.Schema(ctx, resource.SchemaRequest{}, &sr)
		if d := sr.Schema.ValidateImplementation(ctx); d.HasError() || sr.Diagnostics.HasError() {
			t.Errorf("%s: %v %v", md.TypeName, sr.Diagnostics, d)
		}
		for name, a := range sr.Schema.Attributes {
			if a.GetMarkdownDescription() == "" {
				t.Errorf("%s.%s has no description", md.TypeName, name)
			}
		}
	}
	for _, f := range p.DataSources(ctx) {
		ds := f()
		var md datasource.MetadataResponse
		ds.Metadata(ctx, datasource.MetadataRequest{ProviderTypeName: "iboss"}, &md)
		var sr datasource.SchemaResponse
		ds.Schema(ctx, datasource.SchemaRequest{}, &sr)
		if d := sr.Schema.ValidateImplementation(ctx); d.HasError() || sr.Diagnostics.HasError() {
			t.Errorf("%s: %v %v", md.TypeName, sr.Diagnostics, d)
		}
	}
}

func TestTypeNames(t *testing.T) {
	ctx := context.Background()
	p := provider.New("test")()
	want := map[string]bool{
		"iboss_allowlist_entry": true, "iboss_blocklist_entry": true,
		"iboss_allowlist": true, "iboss_blocklist": true, "iboss_allowlist_settings": true, "iboss_security_group": true, "iboss_security_groups": true,
	}
	for _, f := range p.Resources(ctx) {
		var md resource.MetadataResponse
		f().Metadata(ctx, resource.MetadataRequest{ProviderTypeName: "iboss"}, &md)
		delete(want, md.TypeName)
	}
	for _, f := range p.DataSources(ctx) {
		var md datasource.MetadataResponse
		f().Metadata(ctx, datasource.MetadataRequest{ProviderTypeName: "iboss"}, &md)
		delete(want, md.TypeName)
	}
	if len(want) != 0 {
		t.Errorf("missing type names: %v", want)
	}
}
