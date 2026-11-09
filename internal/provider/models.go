package provider

import (
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/nfvcsd/terraform-provider-iboss/internal/client"
)

// entryCommon holds attributes shared by allowlist and blocklist entries in
// both resources and data sources. Names mirror the documented JSON fields.
type entryCommon struct {
	URL                       types.String `tfsdk:"url"`
	Note                      types.String `tfsdk:"note"`
	IsRegex                   types.Bool   `tfsdk:"is_regex"`
	Global                    types.Bool   `tfsdk:"global"`
	ApplyKeywordAndSafeSearch types.Bool   `tfsdk:"apply_keyword_and_safe_search"`
	Direction                 types.Int64  `tfsdk:"direction"`
	Priority                  types.Int64  `tfsdk:"priority"`
	Weight                    types.Int64  `tfsdk:"weight"`
	StartPort                 types.Int64  `tfsdk:"start_port"`
	EndPort                   types.Int64  `tfsdk:"end_port"`
	ResourceID                types.String `tfsdk:"resource_id"`
}

// fromAPI copies server values for every readable field except url, which
// callers set deliberately (resources keep the configured spelling).
func (m *entryCommon) fromAPI(e client.URLListEntry) {
	m.Note = types.StringValue(e.Note)
	m.IsRegex = boolValue(e.IsRegex)
	m.Global = boolValue(e.Global)
	m.ApplyKeywordAndSafeSearch = boolValue(e.ApplyKeywordAndSafeSearch)
	m.Direction = int64Value(e.Direction)
	m.Priority = int64Value(e.Priority)
	m.Weight = int64Value(e.Weight)
	m.StartPort = int64Value(e.StartPort)
	m.EndPort = int64Value(e.EndPort)
	m.ResourceID = types.StringValue(e.ResourceID)
}

// nullUnknowns replaces unknown computed values with null so a partial state
// can be saved after a failed read-back.
func (m *entryCommon) nullUnknowns() {
	if m.Note.IsUnknown() {
		m.Note = types.StringNull()
	}
	for _, b := range []*types.Bool{&m.IsRegex, &m.Global, &m.ApplyKeywordAndSafeSearch} {
		if b.IsUnknown() {
			*b = types.BoolNull()
		}
	}
	for _, i := range []*types.Int64{&m.Direction, &m.Priority, &m.Weight, &m.StartPort, &m.EndPort} {
		if i.IsUnknown() {
			*i = types.Int64Null()
		}
	}
	if m.ResourceID.IsUnknown() {
		m.ResourceID = types.StringNull()
	}
}

// toAPI builds the add-entry body. Null/unknown values are omitted.
func (m *entryCommon) toAPI() client.NewURLListEntry {
	e := client.NewURLListEntry{URL: m.URL.ValueString()}
	if known(m.Note.IsNull(), m.Note.IsUnknown()) {
		v := m.Note.ValueString()
		e.Note = &v
	}
	e.IsRegex = boolPtr(m.IsRegex)
	e.Global = boolPtr(m.Global)
	e.ApplyKeywordAndSafeSearch = boolPtr(m.ApplyKeywordAndSafeSearch)
	e.Direction = intPtr(m.Direction)
	e.Priority = intPtr(m.Priority)
	e.Weight = intPtr(m.Weight)
	e.StartPort = intPtr(m.StartPort)
	e.EndPort = intPtr(m.EndPort)
	return e
}

type entryResourceBase struct {
	ID          types.String `tfsdk:"id"`
	GroupNumber types.Int64  `tfsdk:"group_number"`
	entryCommon
}

type allowlistEntryModel struct {
	entryResourceBase
	DoDLPScan     types.Bool `tfsdk:"do_dlp_scan"`
	DoMalwareScan types.Bool `tfsdk:"do_malware_scan"`
}

func (m *allowlistEntryModel) base() *entryResourceBase { return &m.entryResourceBase }
func (m *allowlistEntryModel) setExtras(e client.URLListEntry) {
	m.DoDLPScan = boolValue(e.DoDLPScan)
	m.DoMalwareScan = boolValue(e.DoMalwareScan)
}
func (m *allowlistEntryModel) nullExtras() {
	m.DoDLPScan = types.BoolNull()
	m.DoMalwareScan = types.BoolNull()
}

type blocklistEntryModel struct {
	entryResourceBase
	Type types.Int64 `tfsdk:"type"`
}

func (m *blocklistEntryModel) base() *entryResourceBase        { return &m.entryResourceBase }
func (m *blocklistEntryModel) setExtras(e client.URLListEntry) { m.Type = int64Value(e.Type) }
func (m *blocklistEntryModel) nullExtras()                     { m.Type = types.Int64Null() }

// Data source entry models add read-only timed-URL fields.
type dsEntryCommon struct {
	entryCommon
	IsTimedURL               types.Bool  `tfsdk:"is_timed_url"`
	TimedURLExpiresInMinutes types.Int64 `tfsdk:"timed_url_expires_in_minutes"`
}

func (m *dsEntryCommon) fromAPI(e client.URLListEntry) {
	m.URL = types.StringValue(e.URL)
	m.entryCommon.fromAPI(e)
	m.IsTimedURL = boolValue(e.IsTimedURL)
	m.TimedURLExpiresInMinutes = int64Value(e.TimedURLExpiresInMinutes)
}

type allowlistDSEntry struct {
	dsEntryCommon
	DoDLPScan     types.Bool `tfsdk:"do_dlp_scan"`
	DoMalwareScan types.Bool `tfsdk:"do_malware_scan"`
}

type blocklistDSEntry struct {
	dsEntryCommon
	Type types.Int64 `tfsdk:"type"`
}

type allowlistDSModel struct {
	ID          types.String       `tfsdk:"id"`
	GroupNumber types.Int64        `tfsdk:"group_number"`
	Entries     []allowlistDSEntry `tfsdk:"entries"`
}

func (m *allowlistDSModel) group() types.Int64 { return m.GroupNumber }
func (m *allowlistDSModel) fill(id string, entries []client.URLListEntry) {
	m.ID = types.StringValue(id)
	m.Entries = make([]allowlistDSEntry, 0, len(entries))
	for _, e := range entries {
		var d allowlistDSEntry
		d.fromAPI(e)
		d.DoDLPScan = boolValue(e.DoDLPScan)
		d.DoMalwareScan = boolValue(e.DoMalwareScan)
		m.Entries = append(m.Entries, d)
	}
}

type blocklistDSModel struct {
	ID          types.String       `tfsdk:"id"`
	GroupNumber types.Int64        `tfsdk:"group_number"`
	Entries     []blocklistDSEntry `tfsdk:"entries"`
}

func (m *blocklistDSModel) group() types.Int64 { return m.GroupNumber }
func (m *blocklistDSModel) fill(id string, entries []client.URLListEntry) {
	m.ID = types.StringValue(id)
	m.Entries = make([]blocklistDSEntry, 0, len(entries))
	for _, e := range entries {
		var d blocklistDSEntry
		d.fromAPI(e)
		d.Type = int64Value(e.Type)
		m.Entries = append(m.Entries, d)
	}
}

func boolValue(f client.FlexInt) types.Bool {
	if !f.Valid {
		return types.BoolNull()
	}
	return types.BoolValue(f.Bool())
}

func int64Value(f client.FlexInt) types.Int64 {
	if !f.Valid {
		return types.Int64Null()
	}
	return types.Int64Value(f.Int64)
}

func known(isNull, isUnknown bool) bool { return !isNull && !isUnknown }

func boolPtr(v types.Bool) *client.FlexInt {
	if !known(v.IsNull(), v.IsUnknown()) {
		return nil
	}
	f := client.BoolInt(v.ValueBool())
	return &f
}

func intPtr(v types.Int64) *client.FlexInt {
	if !known(v.IsNull(), v.IsUnknown()) {
		return nil
	}
	f := client.Int(v.ValueInt64())
	return &f
}
