package client

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
)

// SecurityGroup is one element of the documented "Get Security Groups"
// response. The groupNumber is the value used as currentPolicyBeingEdited by
// gateway policy endpoints such as the allow and block lists.
type SecurityGroup struct {
	GroupNumber          FlexInt `json:"groupNumber"`
	GroupName            string  `json:"groupName"`
	Note                 string  `json:"note"`
	Priority             FlexInt `json:"priority"`
	ParentGroupNumber    FlexInt `json:"parentGroupNumber"`
	ReportingGroupNumber FlexInt `json:"reportingGroupNumber"`
	ReservedGroup        FlexInt `json:"reservedGroup"`
}

// ListSecurityGroups implements "Get Security Groups":
// GET https://{{baseApiDomain}}/ibcloud/web/groups/filtering?accountSettingsId=N
// The documented groupNumber/groupName/wildcard filters are not used because
// their matching semantics are undocumented; callers filter client-side.
// No pagination is documented for this endpoint.
func (c *Client) ListSecurityGroups(ctx context.Context) ([]SecurityGroup, error) {
	var out []SecurityGroup
	err := c.call(ctx, false, true, func(s session) error {
		return c.getJSON(ctx, &s, request{
			host: hostCore, method: http.MethodGet, path: "/ibcloud/web/groups/filtering",
			query: url.Values{"accountSettingsId": {strconv.FormatInt(s.accountSettingsID, 10)}},
			auth:  authCore,
		}, &out)
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
