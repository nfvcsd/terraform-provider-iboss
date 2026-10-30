package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// URLList names a gateway URL list. Values are the documented path segments.
type URLList string

const (
	Allowlist URLList = "allowList"
	Blocklist URLList = "blockList"
)

func (l URLList) valid() error {
	if l != Allowlist && l != Blocklist {
		return fmt.Errorf("unknown URL list %q", string(l))
	}
	return nil
}

// URLListEntry is one entry as returned by "Get Allow List"/"Get Block List".
// Fields follow the documented response examples; doDlpScan/doMalwareScan
// appear only on allowlist entries and type only on blocklist entries.
type URLListEntry struct {
	URL                       string  `json:"url"`
	ApplyKeywordAndSafeSearch FlexInt `json:"applyKeywordAndSafeSearch"`
	Direction                 FlexInt `json:"direction"`
	DoDLPScan                 FlexInt `json:"doDlpScan"`
	DoMalwareScan             FlexInt `json:"doMalwareScan"`
	StartPort                 FlexInt `json:"startPort"`
	EndPort                   FlexInt `json:"endPort"`
	Global                    FlexInt `json:"global"`
	IsRegex                   FlexInt `json:"isRegex"`
	IsTimedURL                FlexInt `json:"isTimedUrl"`
	Note                      string  `json:"note"`
	Priority                  FlexInt `json:"priority"`
	ResourceID                string  `json:"resourceId"`
	TimedURLExpiresInMinutes  FlexInt `json:"timedUrlExpiresInMinutes"`
	Type                      FlexInt `json:"type"`
	Weight                    FlexInt `json:"weight"`
}

// URLListResponse is the documented list response body.
type URLListResponse struct {
	CurrentPolicyBeingEdited FlexInt        `json:"currentPolicyBeingEdited"`
	Entries                  []URLListEntry `json:"entries"`
	Message                  string         `json:"message"`
}

// NewURLListEntry is the body of "Add URL to Allow List"/"Add URL to Block
// List". Nil fields are omitted so the server applies its own defaults; the
// documented example bodies are illustrations, not a list of required fields.
// Timed URLs (isTimedUrl/timedUrl) are intentionally not supported yet.
type NewURLListEntry struct {
	URL                       string   `json:"url"`
	ApplyKeywordAndSafeSearch *FlexInt `json:"applyKeywordAndSafeSearch,omitempty"`
	Direction                 *FlexInt `json:"direction,omitempty"`
	StartPort                 *FlexInt `json:"startPort,omitempty"`
	EndPort                   *FlexInt `json:"endPort,omitempty"`
	Global                    *FlexInt `json:"global,omitempty"`
	IsRegex                   *FlexInt `json:"isRegex,omitempty"`
	Note                      *string  `json:"note,omitempty"`
	Priority                  *FlexInt `json:"priority,omitempty"`
	Weight                    *FlexInt `json:"weight,omitempty"`
}

// MutationResult carries the optional "message" field of a mutation response.
// The documentation has no example mutation responses, so callers must
// confirm the effect by reading the list back.
type MutationResult struct {
	Message string
}

func groupQuery(group int64) url.Values {
	return url.Values{"currentPolicyBeingEdited": {strconv.FormatInt(group, 10)}}
}

func listPath(l URLList) string { return "/json/controls/" + string(l) }

// LockURLList serializes mutations of one list/group pair within this process.
func (c *Client) LockURLList(l URLList, group int64) func() {
	return c.listLock.lock(fmt.Sprintf("%s/%d", l, group))
}

// ListURLEntries implements "Get Allow List"/"Get Block List":
// GET https://{{gatewayNodeApiDomain}}/json/controls/{allowList|blockList}?currentPolicyBeingEdited=N
func (c *Client) ListURLEntries(ctx context.Context, l URLList, group int64) (*URLListResponse, error) {
	if err := l.valid(); err != nil {
		return nil, err
	}
	var raw struct {
		CurrentPolicyBeingEdited FlexInt         `json:"currentPolicyBeingEdited"`
		Entries                  *[]URLListEntry `json:"entries"`
		Message                  string          `json:"message"`
	}
	err := c.call(ctx, true, true, func(s session) error {
		return c.getJSON(ctx, &s, request{
			host: hostGateway, method: http.MethodGet, path: listPath(l),
			query: groupQuery(group), auth: authGateway,
		}, &raw)
	})
	if err != nil {
		return nil, err
	}
	// Absence decisions depend on this response, so anything other than the
	// documented shape for the requested group is an error, never "empty".
	if raw.Entries == nil {
		return nil, &DecodeError{Method: http.MethodGet, Path: listPath(l), Err: fmt.Errorf("response has no entries field (message: %q)", raw.Message)}
	}
	if raw.CurrentPolicyBeingEdited.Valid && raw.CurrentPolicyBeingEdited.Int64 != group {
		return nil, &DecodeError{Method: http.MethodGet, Path: listPath(l), Err: fmt.Errorf("response is for group %d, requested %d", raw.CurrentPolicyBeingEdited.Int64, group)}
	}
	return &URLListResponse{CurrentPolicyBeingEdited: raw.CurrentPolicyBeingEdited, Entries: *raw.Entries, Message: raw.Message}, nil
}

// AddURLEntry implements "Add URL to Allow List"/"Add URL to Block List":
// PUT https://{{gatewayNodeApiDomain}}/json/controls/{allowList|blockList}?currentPolicyBeingEdited=N
// It is never retried.
func (c *Client) AddURLEntry(ctx context.Context, l URLList, group int64, e NewURLListEntry) (MutationResult, error) {
	if err := l.valid(); err != nil {
		return MutationResult{}, err
	}
	if strings.TrimSpace(e.URL) == "" {
		return MutationResult{}, fmt.Errorf("url must not be empty")
	}
	var res MutationResult
	err := c.call(ctx, true, false, func(s session) error {
		resp, err := c.do(ctx, &s, request{
			host: hostGateway, method: http.MethodPut, path: listPath(l),
			query: groupQuery(group), body: e, auth: authGateway,
		})
		if err != nil {
			return err
		}
		res = mutationResult(resp.body)
		return nil
	})
	return res, err
}

// DeleteURLEntry implements "Delete URL from Allow List"/"Delete URL from Block List":
// DELETE https://{{gatewayNodeApiDomain}}/json/controls/{allowList|blockList}?currentPolicyBeingEdited=N&url=U
// It is never retried.
func (c *Client) DeleteURLEntry(ctx context.Context, l URLList, group int64, entryURL string) (MutationResult, error) {
	if err := l.valid(); err != nil {
		return MutationResult{}, err
	}
	q := groupQuery(group)
	q.Set("url", entryURL)
	var res MutationResult
	err := c.call(ctx, true, false, func(s session) error {
		resp, err := c.do(ctx, &s, request{
			host: hostGateway, method: http.MethodDelete, path: listPath(l),
			query: q, auth: authGateway,
		})
		if err != nil {
			return err
		}
		res = mutationResult(resp.body)
		return nil
	})
	return res, err
}

func mutationResult(body []byte) MutationResult {
	var m struct {
		Message string `json:"message"`
	}
	if len(bytes.TrimSpace(body)) > 0 && json.Unmarshal(body, &m) == nil {
		return MutationResult{Message: m.Message}
	}
	return MutationResult{}
}

// AllowlistSettings is the documented "Get Allowlist Settings" response.
type AllowlistSettings struct {
	CurrentPolicyBeingEdited    FlexInt `json:"currentPolicyBeingEdited"`
	DefaultTimedURLTimeout      FlexInt `json:"defaultTimedUrlTimeout"`
	DisplayAllowedSitesPage     FlexInt `json:"displayAllowedSitesPage"`
	GroupInheritanceGroupNumber FlexInt `json:"groupInheritanceGroupNumber"`
	GroupInheritancePolicy      FlexInt `json:"groupInheritancePolicy"`
	Message                     string  `json:"message"`
	OnlyAllowWhiteList          FlexInt `json:"onlyAllowWhiteList"`
}

// GetAllowlistSettings implements "Get Allowlist Settings":
// GET https://{{gatewayNodeApiDomain}}/json/controls/allowList/settings?currentPolicyBeingEdited=N
func (c *Client) GetAllowlistSettings(ctx context.Context, group int64) (*AllowlistSettings, error) {
	var out AllowlistSettings
	err := c.call(ctx, true, true, func(s session) error {
		return c.getJSON(ctx, &s, request{
			host: hostGateway, method: http.MethodGet, path: "/json/controls/allowList/settings",
			query: groupQuery(group), auth: authGateway,
		}, &out)
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// SameURL reports whether two list URLs identify the same entry. Matching is
// exact first; callers may fall back to EquivalentURL when exactly one entry
// differs only by a trailing "/" or ASCII case, because the documented
// examples show both "google.com" and "dropbox.com/" forms and server-side
// normalization is undocumented.
func EquivalentURL(a, b string) bool {
	return strings.EqualFold(strings.TrimSuffix(a, "/"), strings.TrimSuffix(b, "/"))
}

// FindURLEntry returns the entry matching u: an exact match, or else a single
// equivalent match. ok is false when absent; ambiguous equivalents are an error.
func FindURLEntry(entries []URLListEntry, u string) (URLListEntry, bool, error) {
	for _, e := range entries {
		if e.URL == u {
			return e, true, nil
		}
	}
	var matches []URLListEntry
	for _, e := range entries {
		if EquivalentURL(e.URL, u) {
			matches = append(matches, e)
		}
	}
	switch len(matches) {
	case 0:
		return URLListEntry{}, false, nil
	case 1:
		return matches[0], true, nil
	default:
		return URLListEntry{}, false, fmt.Errorf("%d entries match %q when ignoring case and a trailing slash; resolve the duplicates in iboss", len(matches), u)
	}
}
