package provider

import (
	"context"
	"fmt"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/nfvcsd/iboss-terraform/internal/client"
)

func configureDS(req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) *client.Client {
	if req.ProviderData == nil {
		return nil
	}
	c, ok := req.ProviderData.(*client.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", fmt.Sprintf("expected *client.Client, got %T", req.ProviderData))
		return nil
	}
	return c
}

func groupNumberDSAttr(what string) schema.Int64Attribute {
	return schema.Int64Attribute{
		MarkdownDescription: "Security (filtering) group number whose " + what + " to read. Sent as `currentPolicyBeingEdited`.",
		Required:            true,
		Validators:          []validator.Int64{int64validator.AtLeast(0)},
	}
}

func dsEntryAttrs(extra map[string]schema.Attribute) map[string]schema.Attribute {
	a := map[string]schema.Attribute{
		"url":                           schema.StringAttribute{Computed: true, MarkdownDescription: "URL, domain, or pattern (`url`)."},
		"note":                          schema.StringAttribute{Computed: true, MarkdownDescription: "Note (`note`)."},
		"is_regex":                      schema.BoolAttribute{Computed: true, MarkdownDescription: "Regular-expression flag (`isRegex`)."},
		"global":                        schema.BoolAttribute{Computed: true, MarkdownDescription: "Global flag (`global`)."},
		"apply_keyword_and_safe_search": schema.BoolAttribute{Computed: true, MarkdownDescription: "Keyword and safe search flag (`applyKeywordAndSafeSearch`)."},
		"direction":                     schema.Int64Attribute{Computed: true, MarkdownDescription: "Direction code (`direction`); value meanings are undocumented."},
		"priority":                      schema.Int64Attribute{Computed: true, MarkdownDescription: "Priority (`priority`)."},
		"weight":                        schema.Int64Attribute{Computed: true, MarkdownDescription: "Weight (`weight`)."},
		"start_port":                    schema.Int64Attribute{Computed: true, MarkdownDescription: "Start port (`startPort`)."},
		"end_port":                      schema.Int64Attribute{Computed: true, MarkdownDescription: "End port (`endPort`)."},
		"resource_id":                   schema.StringAttribute{Computed: true, MarkdownDescription: "Associated resource ID (`resourceId`)."},
		"is_timed_url":                  schema.BoolAttribute{Computed: true, MarkdownDescription: "Whether the entry expires (`isTimedUrl`)."},
		"timed_url_expires_in_minutes":  schema.Int64Attribute{Computed: true, MarkdownDescription: "Minutes until a timed entry expires (`timedUrlExpiresInMinutes`)."},
	}
	for k, v := range extra {
		a[k] = v
	}
	return a
}

// ---- iboss_allowlist / iboss_blocklist ----

type listDSModel interface {
	group() types.Int64
	fill(id string, entries []client.URLListEntry)
}

type urlListDataSource[T any, PT interface {
	*T
	listDSModel
}] struct {
	v     listVariant
	extra map[string]schema.Attribute
	c     *client.Client
}

// NewAllowlistDataSource reads every entry on a group's allowlist.
func NewAllowlistDataSource() datasource.DataSource {
	return &urlListDataSource[allowlistDSModel, *allowlistDSModel]{v: allowlistVariant, extra: map[string]schema.Attribute{
		"do_dlp_scan":     schema.BoolAttribute{Computed: true, MarkdownDescription: "DLP scan flag (`doDlpScan`)."},
		"do_malware_scan": schema.BoolAttribute{Computed: true, MarkdownDescription: "Malware scan flag (`doMalwareScan`)."},
	}}
}

// NewBlocklistDataSource reads every entry on a group's block list.
func NewBlocklistDataSource() datasource.DataSource {
	return &urlListDataSource[blocklistDSModel, *blocklistDSModel]{v: blocklistVariant, extra: map[string]schema.Attribute{
		"type": schema.Int64Attribute{Computed: true, MarkdownDescription: "Entry type (`type`); value meanings are undocumented."},
	}}
}

func (d *urlListDataSource[T, PT]) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_" + d.v.typeSuffix
}

func (d *urlListDataSource[T, PT]) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads every entry on a security group's " + d.v.displayName + ", in the order the API returns them.",
		Attributes: map[string]schema.Attribute{
			"id":           schema.StringAttribute{Computed: true, MarkdownDescription: "The group number."},
			"group_number": groupNumberDSAttr(d.v.displayName),
			"entries": schema.ListNestedAttribute{
				Computed:            true,
				MarkdownDescription: "Entries on the " + d.v.displayName + ".",
				NestedObject:        schema.NestedAttributeObject{Attributes: dsEntryAttrs(d.extra)},
			},
		},
	}
}

func (d *urlListDataSource[T, PT]) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if c := configureDS(req, resp); c != nil {
		d.c = c
	}
}

func (d *urlListDataSource[T, PT]) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var cfg T
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	m := PT(&cfg)
	group := m.group().ValueInt64()
	lst, err := d.c.ListURLEntries(ctx, d.v.list, group)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read "+d.v.displayName, err.Error())
		return
	}
	if lst.Message != "" {
		resp.Diagnostics.AddWarning("iboss returned a message", lst.Message)
	}
	m.fill(strconv.FormatInt(group, 10), lst.Entries)
	resp.Diagnostics.Append(resp.State.Set(ctx, &cfg)...)
}

// ---- iboss_allowlist_settings ----

type allowlistSettingsModel struct {
	ID                          types.String `tfsdk:"id"`
	GroupNumber                 types.Int64  `tfsdk:"group_number"`
	OnlyAllowAllowlist          types.Bool   `tfsdk:"only_allow_allowlist"`
	DisplayAllowedSitesPage     types.Bool   `tfsdk:"display_allowed_sites_page"`
	DefaultTimedURLTimeout      types.Int64  `tfsdk:"default_timed_url_timeout"`
	GroupInheritanceGroupNumber types.Int64  `tfsdk:"group_inheritance_group_number"`
	GroupInheritancePolicy      types.Int64  `tfsdk:"group_inheritance_policy"`
}

type allowlistSettingsDataSource struct{ c *client.Client }

// NewAllowlistSettingsDataSource reads a group's allowlist settings.
func NewAllowlistSettingsDataSource() datasource.DataSource { return &allowlistSettingsDataSource{} }

func (d *allowlistSettingsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_allowlist_settings"
}

func (d *allowlistSettingsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads a security group's allowlist settings. Read-only: the documentation describes no update operation for these settings.",
		Attributes: map[string]schema.Attribute{
			"id":                             schema.StringAttribute{Computed: true, MarkdownDescription: "The group number."},
			"group_number":                   groupNumberDSAttr("allowlist settings"),
			"only_allow_allowlist":           schema.BoolAttribute{Computed: true, MarkdownDescription: "Only allow sites on the allowlist (`onlyAllowWhiteList`)."},
			"display_allowed_sites_page":     schema.BoolAttribute{Computed: true, MarkdownDescription: "Display the allowed-sites page (`displayAllowedSitesPage`)."},
			"default_timed_url_timeout":      schema.Int64Attribute{Computed: true, MarkdownDescription: "Default timeout for timed entries (`defaultTimedUrlTimeout`); the unit is undocumented."},
			"group_inheritance_group_number": schema.Int64Attribute{Computed: true, MarkdownDescription: "Group whose allowlist is inherited (`groupInheritanceGroupNumber`)."},
			"group_inheritance_policy":       schema.Int64Attribute{Computed: true, MarkdownDescription: "Inheritance policy code (`groupInheritancePolicy`); value meanings are undocumented."},
		},
	}
}

func (d *allowlistSettingsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if c := configureDS(req, resp); c != nil {
		d.c = c
	}
}

func (d *allowlistSettingsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var m allowlistSettingsModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	group := m.GroupNumber.ValueInt64()
	s, err := d.c.GetAllowlistSettings(ctx, group)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read allowlist settings", err.Error())
		return
	}
	if s.Message != "" {
		resp.Diagnostics.AddWarning("iboss returned a message", s.Message)
	}
	m.ID = types.StringValue(strconv.FormatInt(group, 10))
	m.OnlyAllowAllowlist = boolValue(s.OnlyAllowWhiteList)
	m.DisplayAllowedSitesPage = boolValue(s.DisplayAllowedSitesPage)
	m.DefaultTimedURLTimeout = int64Value(s.DefaultTimedURLTimeout)
	m.GroupInheritanceGroupNumber = int64Value(s.GroupInheritanceGroupNumber)
	m.GroupInheritancePolicy = int64Value(s.GroupInheritancePolicy)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

// ---- iboss_security_group ----

type securityGroupModel struct {
	ID                   types.String `tfsdk:"id"`
	Name                 types.String `tfsdk:"name"`
	GroupNumber          types.Int64  `tfsdk:"group_number"`
	Note                 types.String `tfsdk:"note"`
	Priority             types.Int64  `tfsdk:"priority"`
	ParentGroupNumber    types.Int64  `tfsdk:"parent_group_number"`
	ReportingGroupNumber types.Int64  `tfsdk:"reporting_group_number"`
	Reserved             types.Bool   `tfsdk:"reserved"`
}

type securityGroupDataSource struct{ c *client.Client }

// NewSecurityGroupDataSource looks up one security (filtering) group.
func NewSecurityGroupDataSource() datasource.DataSource { return &securityGroupDataSource{} }

func (d *securityGroupDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_security_group"
}

func (d *securityGroupDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Looks up one security (filtering) group by exact name or by number. " +
			"Use its `group_number` with the allowlist and block list resources.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{Computed: true, MarkdownDescription: "The group number."},
			"name": schema.StringAttribute{
				Optional: true, Computed: true,
				MarkdownDescription: "Exact, case-sensitive group name (`groupName`). Exactly one of `name` or `group_number` must be set.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
					stringvalidator.ExactlyOneOf(path.MatchRoot("name"), path.MatchRoot("group_number")),
				},
			},
			"group_number": schema.Int64Attribute{
				Optional: true, Computed: true,
				MarkdownDescription: "Group number (`groupNumber`).",
				Validators:          []validator.Int64{int64validator.AtLeast(0)},
			},
			"note":                   schema.StringAttribute{Computed: true, MarkdownDescription: "Group note (`note`)."},
			"priority":               schema.Int64Attribute{Computed: true, MarkdownDescription: "Group priority (`priority`)."},
			"parent_group_number":    schema.Int64Attribute{Computed: true, MarkdownDescription: "Parent group number (`parentGroupNumber`)."},
			"reporting_group_number": schema.Int64Attribute{Computed: true, MarkdownDescription: "Reporting group number (`reportingGroupNumber`)."},
			"reserved":               schema.BoolAttribute{Computed: true, MarkdownDescription: "Whether the group is reserved (`reservedGroup`)."},
		},
	}
}

func (d *securityGroupDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if c := configureDS(req, resp); c != nil {
		d.c = c
	}
}

func (d *securityGroupDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var m securityGroupModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	groups, err := d.c.ListSecurityGroups(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read security groups", err.Error())
		return
	}
	var matches []client.SecurityGroup
	for _, g := range groups {
		if !m.Name.IsNull() && g.GroupName == m.Name.ValueString() ||
			!m.GroupNumber.IsNull() && g.GroupNumber.Valid && g.GroupNumber.Int64 == m.GroupNumber.ValueInt64() {
			matches = append(matches, g)
		}
	}
	what := fmt.Sprintf("named %q", m.Name.ValueString())
	if m.Name.IsNull() {
		what = fmt.Sprintf("number %d", m.GroupNumber.ValueInt64())
	}
	switch len(matches) {
	case 0:
		resp.Diagnostics.AddError("Security group not found", "No security group "+what+" exists in this account.")
		return
	case 1:
	default:
		resp.Diagnostics.AddError("Multiple security groups found", fmt.Sprintf("%d security groups match %s; look the group up by number instead.", len(matches), what))
		return
	}
	g := matches[0]
	m.ID = types.StringValue(strconv.FormatInt(g.GroupNumber.Int64, 10))
	m.Name = types.StringValue(g.GroupName)
	m.GroupNumber = int64Value(g.GroupNumber)
	m.Note = types.StringValue(g.Note)
	m.Priority = int64Value(g.Priority)
	m.ParentGroupNumber = int64Value(g.ParentGroupNumber)
	m.ReportingGroupNumber = int64Value(g.ReportingGroupNumber)
	m.Reserved = boolValue(g.ReservedGroup)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}
