package commands

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/wyiu/veyport/cli/internal/api"
	"github.com/wyiu/veyport/cli/internal/auth"
	"github.com/wyiu/veyport/cli/internal/cmdutil"
)

// resolveServer probes an ID first, then makes one bounded name search on
// 404 or permission-denied 403. The Hub deliberately returns 403 for both
// unknown and inaccessible IDs to non-admins, including name references.
// Its authenticated list contains only servers visible to the caller.
// The boolean identifies a successful direct lookup for logs' legacy
// handling of an ID response that omits its ID field.
func resolveServer(ctx context.Context, actx *auth.AuthContext, ref string) (api.Server, bool, error) {
	var server api.Server
	getErr := actx.Do(ctx, func(c *api.Client) error {
		return c.Get(ctx, "/api/servers/"+url.PathEscape(ref), nil, &server)
	})
	if getErr == nil {
		return server, true, nil
	}
	code := cmdutil.Code(getErr)
	if code != cmdutil.ExitNotFound && code != cmdutil.ExitForbidden {
		// Disabled/dormant accounts map to ExitAuth, even on HTTP 403.
		return api.Server{}, false, getErr
	}

	var page api.ServersPage
	query := url.Values{"search": {ref}, "limit": {"100"}, "offset": {"0"}}
	if err := actx.Do(ctx, func(c *api.Client) error {
		return c.Get(ctx, "/api/servers", query, &page)
	}); err != nil {
		return api.Server{}, false, err
	}

	var matches []api.Server
	for _, s := range page.Servers {
		if s.Name == ref {
			matches = append(matches, s)
		}
	}
	if len(matches) == 0 && code == cmdutil.ExitForbidden {
		// Keep the original privacy-preserving denial when the caller's
		// visible list cannot resolve the reference, even on a partial page.
		return api.Server{}, false, getErr
	}
	if len(matches) > 1 {
		names := make([]string, 0, len(matches))
		for _, m := range matches {
			names = append(names, fmt.Sprintf("%s (%s)", m.Name, m.ID))
		}
		sort.Strings(names)
		return api.Server{}, false, cmdutil.NewUsageError(fmt.Errorf("%q matches multiple servers: %s", ref, strings.Join(names, ", ")))
	}
	// The Hub caps pages at 100 rows. Searching once must not silently
	// select a name while additional exact matches could be on later pages.
	if page.Offset != 0 || page.Total > len(page.Servers) {
		return api.Server{}, false, cmdutil.NewUsageError(fmt.Errorf("name search for %q returned an incomplete page; use a server ID from vey servers list", ref))
	}
	if len(matches) == 1 {
		return matches[0], false, nil
	}
	return api.Server{}, false, cmdutil.NewNotFoundError(fmt.Errorf("no server found matching %q", ref))
}
