package provider

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/nfvcsd/terraform-provider-iboss/internal/client"
)

// listVariant describes one documented gateway URL list.
type listVariant struct {
	list        client.URLList
	typeSuffix  string // resource/data source name suffix
	displayName string
	extraRes    map[string]schema.Attribute
}

var allowlistVariant = listVariant{
	list:        client.Allowlist,
	typeSuffix:  "allowlist",
	displayName: "allowlist",
	extraRes: map[string]schema.Attribute{
		"do_dlp_scan": schema.BoolAttribute{
			MarkdownDescription: "Whether DLP scanning applies to traffic matching this entry, as reported by the API (`doDlpScan`). Read-only: the documented add request does not accept it.",
			Computed:            true,
			PlanModifiers:       []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
		},
		"do_malware_scan": schema.BoolAttribute{
			MarkdownDescription: "Whether malware scanning applies to traffic matching this entry, as reported by the API (`doMalwareScan`). Read-only: the documented add request does not accept it.",
			Computed:            true,
			PlanModifiers:       []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
		},
	},
}

var blocklistVariant = listVariant{
	list:        client.Blocklist,
	typeSuffix:  "blocklist",
	displayName: "block list",
	extraRes: map[string]schema.Attribute{
		"type": schema.Int64Attribute{
			MarkdownDescription: "Entry type as reported by the API (`type`). Read-only; the meaning of its values is not documented.",
			Computed:            true,
			PlanModifiers:       []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
		},
	},
}

// entryState is implemented by the per-list resource models.
type entryState interface {
	base() *entryResourceBase
	setExtras(client.URLListEntry)
	nullExtras()
}

type urlListEntryResource[T any, PT interface {
	*T
	entryState
}] struct {
	v      listVariant
	client *client.Client
}

var (
	_ resource.ResourceWithConfigure   = (*urlListEntryResource[allowlistEntryModel, *allowlistEntryModel])(nil)
	_ resource.ResourceWithImportState = (*urlListEntryResource[blocklistEntryModel, *blocklistEntryModel])(nil)
)

// NewAllowlistEntryResource manages one URL on a security group's allowlist.
func NewAllowlistEntryResource() resource.Resource {
	return &urlListEntryResource[allowlistEntryModel, *allowlistEntryModel]{v: allowlistVariant}
}

// NewBlocklistEntryResource manages one URL on a security group's block list.
func NewBlocklistEntryResource() resource.Resource {
	return &urlListEntryResource[blocklistEntryModel, *blocklistEntryModel]{v: blocklistVariant}
}

func (r *urlListEntryResource[T, PT]) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_" + r.v.typeSuffix + "_entry"
}

func replaceBool() []planmodifier.Bool {
	return []planmodifier.Bool{boolplanmodifier.RequiresReplace(), boolplanmodifier.UseStateForUnknown()}
}

func replaceInt() []planmodifier.Int64 {
	return []planmodifier.Int64{int64planmodifier.RequiresReplace(), int64planmodifier.UseStateForUnknown()}
}

func (r *urlListEntryResource[T, PT]) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	attrs := map[string]schema.Attribute{
		"id": schema.StringAttribute{
			MarkdownDescription: "Identifier in the form `<group_number>/<url>`.",
			Computed:            true,
			PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
		},
		"group_number": schema.Int64Attribute{
			MarkdownDescription: "Security (filtering) group number whose " + r.v.displayName + " holds the entry. Sent as `currentPolicyBeingEdited`. Look it up by name with the `iboss_security_group` data source.",
			Required:            true,
			PlanModifiers:       []planmodifier.Int64{int64planmodifier.RequiresReplace()},
		},
		"url": schema.StringAttribute{
			MarkdownDescription: "URL, domain, or pattern to add, for example `example.com`. The entry is located by exact match, or by a single match that differs only in letter case or a trailing `/`.",
			Required:            true,
			PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			Validators:          []validator.String{stringvalidator.LengthAtLeast(1)},
		},
		"note": schema.StringAttribute{
			MarkdownDescription: "Free-text note stored with the entry. Changing it replaces the entry; no update operation is documented.",
			Optional:            true,
			Computed:            true,
			PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace(), stringplanmodifier.UseStateForUnknown()},
		},
		"is_regex": schema.BoolAttribute{
			MarkdownDescription: "Treat `url` as a regular expression (`isRegex`). Server default applies when omitted.",
			Optional:            true, Computed: true, PlanModifiers: replaceBool(),
		},
		"global": schema.BoolAttribute{
			MarkdownDescription: "Global entry flag (`global`). Server default applies when omitted.",
			Optional:            true, Computed: true, PlanModifiers: replaceBool(),
		},
		"apply_keyword_and_safe_search": schema.BoolAttribute{
			MarkdownDescription: "Apply keyword filtering and safe search to this entry (`applyKeywordAndSafeSearch`). Server default applies when omitted.",
			Optional:            true, Computed: true, PlanModifiers: replaceBool(),
		},
		"direction": schema.Int64Attribute{
			MarkdownDescription: "Traffic direction code (`direction`). The documented examples use `0` and `2`; the meaning of each value is not documented, so it is passed through unchanged.",
			Optional:            true, Computed: true, PlanModifiers: replaceInt(),
		},
		"priority": schema.Int64Attribute{
			MarkdownDescription: "Entry priority (`priority`).",
			Optional:            true, Computed: true, PlanModifiers: replaceInt(),
		},
		"weight": schema.Int64Attribute{
			MarkdownDescription: "Entry weight (`weight`).",
			Optional:            true, Computed: true, PlanModifiers: replaceInt(),
		},
		"start_port": schema.Int64Attribute{
			MarkdownDescription: "First port of the range the entry applies to (`startPort`). The documented examples use `0`.",
			Optional:            true, Computed: true, PlanModifiers: replaceInt(),
			Validators: []validator.Int64{int64validator.Between(0, 65535)},
		},
		"end_port": schema.Int64Attribute{
			MarkdownDescription: "Last port of the range the entry applies to (`endPort`). The documented examples use `0`.",
			Optional:            true, Computed: true, PlanModifiers: replaceInt(),
			Validators: []validator.Int64{int64validator.Between(0, 65535)},
		},
		"resource_id": schema.StringAttribute{
			MarkdownDescription: "Associated resource identifier reported by the API (`resourceId`).",
			Computed:            true,
			PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
		},
	}
	for k, a := range r.v.extraRes {
		attrs[k] = a
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: fmt.Sprintf("Manages one entry on a security group's %s.\n\n"+
			"This resource is non-authoritative: other entries on the same list are left alone. "+
			"Every argument forces replacement because the API documents add and delete operations but no update. "+
			"Timed (expiring) entries are not supported, and `create_before_destroy` cannot be used because "+
			"the replacement would collide with the existing entry.", r.v.displayName),
		Attributes: attrs,
	}
}

func (r *urlListEntryResource[T, PT]) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c, ok := req.ProviderData.(*client.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", fmt.Sprintf("expected *client.Client, got %T", req.ProviderData))
		return
	}
	r.client = c
}

func entryID(group int64, url string) string { return strconv.FormatInt(group, 10) + "/" + url }

func (r *urlListEntryResource[T, PT]) apply(m PT, e client.URLListEntry) {
	b := m.base()
	b.entryCommon.fromAPI(e)
	m.setExtras(e)
}

// list reads a list for a state decision (existence, absence). A non-empty
// "message" has undocumented meaning, so it is treated as an error rather
// than trusting the entries alongside it.
func (r *urlListEntryResource[T, PT]) list(ctx context.Context, group int64) (*client.URLListResponse, error) {
	lst, err := r.client.ListURLEntries(ctx, r.v.list, group)
	if err != nil {
		return nil, err
	}
	if lst.Message != "" {
		return nil, fmt.Errorf("iboss returned a message with the %s for group %d: %q", r.v.displayName, group, lst.Message)
	}
	return lst, nil
}

func (r *urlListEntryResource[T, PT]) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan T
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	m := PT(&plan)
	b := m.base()
	group, url := b.GroupNumber.ValueInt64(), b.URL.ValueString()
	configured := b.entryCommon

	unlock := r.client.LockURLList(r.v.list, group)
	defer unlock()

	before, err := r.list(ctx, group)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read "+r.v.displayName, err.Error())
		return
	}
	if e, ok, err := client.FindURLEntry(before.Entries, url); err != nil {
		resp.Diagnostics.AddError("Ambiguous "+r.v.displayName+" entry", err.Error())
		return
	} else if ok {
		resp.Diagnostics.AddError("Entry already exists",
			fmt.Sprintf("Group %d's %s already contains %q. Import it instead of creating it:\n  terraform import <address> %s\n"+
				"(create_before_destroy is not supported for this resource for the same reason.)",
				group, r.v.displayName, e.URL, entryID(group, url)))
		return
	}

	res, err := r.client.AddURLEntry(ctx, r.v.list, group, b.entryCommon.toAPI())
	if err != nil {
		resp.Diagnostics.AddError("Unable to add "+r.v.displayName+" entry", err.Error())
		return
	}
	if res.Message != "" {
		resp.Diagnostics.AddWarning("iboss returned a message", res.Message)
	}

	after, err := r.list(ctx, group)
	if err != nil {
		// The add succeeded but cannot be confirmed. Save the identity so the
		// tainted resource is reconciled (and removed) on the next run.
		b.ID = types.StringValue(entryID(group, url))
		b.entryCommon.nullUnknowns()
		m.nullExtras()
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		resp.Diagnostics.AddError("Unable to confirm "+r.v.displayName+" entry",
			"The entry was added but the list could not be read back: "+err.Error())
		return
	}
	found, ok, err := client.FindURLEntry(after.Entries, url)
	if err != nil {
		resp.Diagnostics.AddError("Ambiguous "+r.v.displayName+" entry", err.Error())
		return
	}
	if !ok {
		r.rollbackUnmatchedAdd(ctx, group, url, before.Entries, after.Entries, &resp.Diagnostics)
		return
	}

	b.ID = types.StringValue(entryID(group, url))
	r.apply(m, found)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	// Saving server values keeps state truthful; differences from the
	// configuration are reported instead of producing an inconsistent result.
	if diffs := configuredDiffs(configured, b.entryCommon); len(diffs) > 0 {
		resp.Diagnostics.AddError("iboss stored different values",
			"The entry was created, but iboss stored these arguments differently from the configuration:\n  "+
				strings.Join(diffs, "\n  ")+"\nUpdate the configuration to the stored values. The resource is marked tainted and will be replaced on the next apply.")
	}
}

// rollbackUnmatchedAdd handles an add whose URL is not found on read-back,
// for example because the server normalized it. If exactly one new entry
// appeared, it is deleted again so nothing is left unmanaged.
func (r *urlListEntryResource[T, PT]) rollbackUnmatchedAdd(ctx context.Context, group int64, url string, before, after []client.URLListEntry, diags *diag.Diagnostics) {
	seen := map[string]int{}
	for _, e := range before {
		seen[e.URL]++
	}
	var added []string
	for _, e := range after {
		if seen[e.URL] > 0 {
			seen[e.URL]--
			continue
		}
		added = append(added, e.URL)
	}
	if len(added) != 1 {
		diags.AddError("Unable to confirm "+r.v.displayName+" entry",
			fmt.Sprintf("iboss accepted %q for group %d, but it was not found on read-back and %d new entries appeared. "+
				"Check the %s in the iboss console and remove any unintended entry.", url, group, len(added), r.v.displayName))
		return
	}
	stored := added[0]
	if _, err := r.client.DeleteURLEntry(ctx, r.v.list, group, stored); err != nil {
		diags.AddError("Unable to roll back "+r.v.displayName+" entry",
			fmt.Sprintf("iboss stored %q as %q, and removing it again failed: %v. Remove %q from group %d's %s manually.",
				url, stored, err, stored, group, r.v.displayName))
		return
	}
	diags.AddError("iboss changed the URL",
		fmt.Sprintf("iboss stored %q as %q. The entry was removed again; set url = %q in the configuration and apply.", url, stored, stored))
}

// configuredDiffs lists arguments whose known configured value differs from
// the value the server stored.
func configuredDiffs(want, got entryCommon) []string {
	var out []string
	str := func(name string, w, g types.String) {
		if known(w.IsNull(), w.IsUnknown()) && !w.Equal(g) {
			out = append(out, fmt.Sprintf("%s: configured %s, stored %s", name, w, g))
		}
	}
	bl := func(name string, w, g types.Bool) {
		if known(w.IsNull(), w.IsUnknown()) && !w.Equal(g) {
			out = append(out, fmt.Sprintf("%s: configured %s, stored %s", name, w, g))
		}
	}
	in := func(name string, w, g types.Int64) {
		if known(w.IsNull(), w.IsUnknown()) && !w.Equal(g) {
			out = append(out, fmt.Sprintf("%s: configured %s, stored %s", name, w, g))
		}
	}
	str("note", want.Note, got.Note)
	bl("is_regex", want.IsRegex, got.IsRegex)
	bl("global", want.Global, got.Global)
	bl("apply_keyword_and_safe_search", want.ApplyKeywordAndSafeSearch, got.ApplyKeywordAndSafeSearch)
	in("direction", want.Direction, got.Direction)
	in("priority", want.Priority, got.Priority)
	in("weight", want.Weight, got.Weight)
	in("start_port", want.StartPort, got.StartPort)
	in("end_port", want.EndPort, got.EndPort)
	return out
}

func (r *urlListEntryResource[T, PT]) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state T
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	m := PT(&state)
	b := m.base()
	group, url := b.GroupNumber.ValueInt64(), b.URL.ValueString()

	lst, err := r.list(ctx, group)
	if err != nil {
		// Never treat errors (including permission errors) as deletion.
		resp.Diagnostics.AddError("Unable to read "+r.v.displayName, err.Error())
		return
	}
	e, ok, err := client.FindURLEntry(lst.Entries, url)
	if err != nil {
		resp.Diagnostics.AddError("Ambiguous "+r.v.displayName+" entry", err.Error())
		return
	}
	if !ok {
		// A successful list response without the entry confirms absence.
		resp.State.RemoveResource(ctx)
		return
	}
	b.ID = types.StringValue(entryID(group, url))
	r.apply(m, e)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *urlListEntryResource[T, PT]) Update(_ context.Context, _ resource.UpdateRequest, resp *resource.UpdateResponse) {
	// Every configurable attribute requires replacement.
	resp.Diagnostics.AddError("Update not supported",
		"The iboss API documents no update operation for list entries; this is a provider bug if reached.")
}

func (r *urlListEntryResource[T, PT]) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state T
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	b := PT(&state).base()
	group, url := b.GroupNumber.ValueInt64(), b.URL.ValueString()

	unlock := r.client.LockURLList(r.v.list, group)
	defer unlock()

	lst, err := r.list(ctx, group)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read "+r.v.displayName, err.Error())
		return
	}
	e, ok, err := client.FindURLEntry(lst.Entries, url)
	if err != nil {
		resp.Diagnostics.AddError("Ambiguous "+r.v.displayName+" entry", err.Error())
		return
	}
	if !ok {
		return // already absent
	}
	res, err := r.client.DeleteURLEntry(ctx, r.v.list, group, e.URL)
	if err != nil {
		resp.Diagnostics.AddError("Unable to delete "+r.v.displayName+" entry", err.Error())
		return
	}
	if res.Message != "" {
		resp.Diagnostics.AddWarning("iboss returned a message", res.Message)
	}
	after, err := r.list(ctx, group)
	if err != nil {
		resp.Diagnostics.AddError("Unable to confirm deletion", err.Error())
		return
	}
	if _, still, _ := client.FindURLEntry(after.Entries, e.URL); still {
		resp.Diagnostics.AddError("Entry still present after delete",
			fmt.Sprintf("iboss accepted the delete request, but %q is still on group %d's %s.", e.URL, group, r.v.displayName))
	}
}

func (r *urlListEntryResource[T, PT]) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	groupStr, url, ok := strings.Cut(req.ID, "/")
	group, err := strconv.ParseInt(groupStr, 10, 64)
	if !ok || err != nil || group < 0 || url == "" {
		resp.Diagnostics.AddError("Invalid import ID",
			fmt.Sprintf("Expected <group_number>/<url>, for example 2/example.com; got %q.", req.ID))
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("group_number"), group)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("url"), url)...)
}
