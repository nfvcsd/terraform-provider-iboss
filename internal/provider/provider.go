// Package provider implements the iboss Terraform provider with the
// Terraform Plugin Framework.
package provider

import (
	"context"
	"os"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/nfvcsd/iboss-terraform/internal/client"
)

// Environment variables read when the matching provider argument is not set.
const (
	EnvAPIKey            = "IBOSS_API_KEY"
	EnvUsername          = "IBOSS_USERNAME"
	EnvPassword          = "IBOSS_PASSWORD"
	EnvTOTPCode          = "IBOSS_TOTP_CODE"
	EnvAccountSettingsID = "IBOSS_ACCOUNT_SETTINGS_ID"
	EnvGatewayHost       = "IBOSS_GATEWAY_HOST"
)

var _ provider.Provider = (*ibossProvider)(nil)

// Option customizes the provider; used by tests to inject the simulator.
type Option func(*ibossProvider)

// WithClientConfig lets a caller adjust the client configuration after the
// provider configuration has been resolved.
func WithClientConfig(fn func(*client.Config)) Option {
	return func(p *ibossProvider) { p.configHook = fn }
}

type ibossProvider struct {
	version    string
	configHook func(*client.Config)
}

// New returns a provider factory.
func New(version string, opts ...Option) func() provider.Provider {
	return func() provider.Provider {
		p := &ibossProvider{version: version}
		for _, o := range opts {
			o(p)
		}
		return p
	}
}

type providerModel struct {
	APIKey            types.String `tfsdk:"api_key"`
	Username          types.String `tfsdk:"username"`
	Password          types.String `tfsdk:"password"`
	TOTPCode          types.String `tfsdk:"totp_code"`
	AccountSettingsID types.Int64  `tfsdk:"account_settings_id"`
	GatewayHost       types.String `tfsdk:"gateway_host"`
}

func (p *ibossProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "iboss"
	resp.Version = p.version
}

func (p *ibossProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manage the iboss Zero Trust SSE platform through the iboss API.\n\n" +
			"Authenticate with **either** an API key (recommended) **or** a legacy username and password. " +
			"If any credential argument is set in the provider block, credential environment variables are ignored.",
		Attributes: map[string]schema.Attribute{
			"api_key": schema.StringAttribute{
				MarkdownDescription: "iboss API key, sent as `Authorization: Token <key>`. Conflicts with `username`/`password`. Falls back to `" + EnvAPIKey + "`.",
				Optional:            true,
				Sensitive:           true,
			},
			"username": schema.StringAttribute{
				MarkdownDescription: "Administrator username for legacy session login. Requires `password`. Falls back to `" + EnvUsername + "`.",
				Optional:            true,
			},
			"password": schema.StringAttribute{
				MarkdownDescription: "Administrator password for legacy session login. Falls back to `" + EnvPassword + "`.",
				Optional:            true,
				Sensitive:           true,
			},
			"totp_code": schema.StringAttribute{
				MarkdownDescription: "One-time MFA code for legacy login when MFA is enabled. A code is single-use, so a session that expires mid-run cannot be renewed automatically. Falls back to `" + EnvTOTPCode + "`.",
				Optional:            true,
				Sensitive:           true,
			},
			"account_settings_id": schema.Int64Attribute{
				MarkdownDescription: "iboss account settings ID. When omitted, the provider discovers the primary account (the one with no delegated super admin). Falls back to `" + EnvAccountSettingsID + "`.",
				Optional:            true,
				Validators:          []validator.Int64{int64validator.AtLeast(1)},
			},
			"gateway_host": schema.StringAttribute{
				MarkdownDescription: "Host name of the primary gateway node (for example `cn-0000.ibosscloud.com`). When omitted, it is discovered from the account's node clusters. Falls back to `" + EnvGatewayHost + "`.",
				Optional:            true,
			},
		},
	}
}

func (p *ibossProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var cfg providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	unknown := map[string]bool{
		"api_key": cfg.APIKey.IsUnknown(), "username": cfg.Username.IsUnknown(),
		"password": cfg.Password.IsUnknown(), "totp_code": cfg.TOTPCode.IsUnknown(),
		"account_settings_id": cfg.AccountSettingsID.IsUnknown(), "gateway_host": cfg.GatewayHost.IsUnknown(),
	}
	for name, u := range unknown {
		if u {
			resp.Diagnostics.AddAttributeError(path.Root(name), "Unknown provider configuration value",
				"The provider cannot be configured with a value that is unknown until apply. Set "+name+" to a known value or use its environment variable.")
		}
	}
	if resp.Diagnostics.HasError() {
		return
	}

	cc := client.Config{}
	configCreds := !cfg.APIKey.IsNull() || !cfg.Username.IsNull() || !cfg.Password.IsNull() || !cfg.TOTPCode.IsNull()
	if configCreds {
		cc.APIKey = cfg.APIKey.ValueString()
		cc.Username = cfg.Username.ValueString()
		cc.Password = cfg.Password.ValueString()
		cc.TOTPCode = cfg.TOTPCode.ValueString()
	} else {
		cc.APIKey = os.Getenv(EnvAPIKey)
		cc.Username = os.Getenv(EnvUsername)
		cc.Password = os.Getenv(EnvPassword)
		cc.TOTPCode = os.Getenv(EnvTOTPCode)
	}

	if !cfg.AccountSettingsID.IsNull() {
		cc.AccountSettingsID = cfg.AccountSettingsID.ValueInt64()
	} else if v := strings.TrimSpace(os.Getenv(EnvAccountSettingsID)); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 1 {
			resp.Diagnostics.AddAttributeError(path.Root("account_settings_id"), "Invalid "+EnvAccountSettingsID,
				EnvAccountSettingsID+" must be a positive integer.")
			return
		}
		cc.AccountSettingsID = n
	}
	if !cfg.GatewayHost.IsNull() {
		cc.GatewayHost = cfg.GatewayHost.ValueString()
	} else {
		cc.GatewayHost = strings.TrimSpace(os.Getenv(EnvGatewayHost))
	}

	if p.configHook != nil {
		p.configHook(&cc)
	}
	c, err := client.New(cc)
	if err != nil {
		resp.Diagnostics.AddError("Invalid iboss provider configuration", err.Error())
		return
	}
	resp.DataSourceData = c
	resp.ResourceData = c
}

func (p *ibossProvider) Resources(context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewAllowlistEntryResource,
		NewBlocklistEntryResource,
	}
}

func (p *ibossProvider) DataSources(context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewAllowlistDataSource,
		NewBlocklistDataSource,
		NewAllowlistSettingsDataSource,
		NewSecurityGroupDataSource,
		NewSecurityGroupsDataSource,
	}
}
