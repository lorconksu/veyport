package commands

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/wyiu/veyport/cli/internal/api"
	"github.com/wyiu/veyport/cli/internal/cmdutil"
)

// RunAudit implements `vey audit export` (contracts/cli-commands.md `vey
// audit export`, spec.md US5): a role-gated streaming passthrough of the
// hub's audit export. The route is GET /api/audit-logs/export, gated
// server-side by auditAccessOnly (hub/internal/server/router.go,
// middleware.go) to admin/auditor roles — everyone else gets a 403 that
// GetStream maps to cmdutil.ExitForbidden (exit 4). The hub responds via
// respondJSON (hub/internal/server/handlers_audit.go
// handleExportAuditLogs), so the real media type is "application/json" and
// the body is model.AuditExportResponse ({"manifest": ..., "entries":
// ...}) — already machine-consumable, so the CLI never decodes it: bytes
// are relayed to stdout verbatim and `--json` is a documented no-op.
func RunAudit(ctx *Context) int {
	if len(ctx.Args) == 0 || ctx.Args[0] != "export" {
		err := cmdutil.NewUsageError(errors.New("usage: vey audit export"))
		ctx.Printer.Error(err)
		return cmdutil.Code(err)
	}
	if len(ctx.Args) > 1 {
		err := cmdutil.NewUsageError(fmt.Errorf("vey audit export takes no arguments (got %v)", ctx.Args[1:]))
		ctx.Printer.Error(err)
		return cmdutil.Code(err)
	}

	hubURL, err := ctx.RequireHub()
	if err != nil {
		ctx.Printer.Error(err)
		return cmdutil.Code(err)
	}
	_, actx, err := newAuthContext(ctx, hubURL)
	if err != nil {
		ctx.Printer.Error(err)
		return cmdutil.Code(err)
	}

	bg := context.Background()
	var body io.ReadCloser
	doErr := actx.Do(bg, func(c *api.Client) error {
		b, streamErr := c.GetStream(bg, "/api/audit-logs/export", nil)
		if streamErr != nil {
			return streamErr
		}
		body = b
		return nil
	})
	if doErr != nil {
		ctx.Printer.Error(doErr)
		return cmdutil.Code(doErr)
	}
	defer body.Close()

	// Passthrough copy: whatever arrives reaches stdout immediately, so a
	// mid-stream failure below still leaves the bytes that made it out
	// intact (contract: "partial data on stdout must be distinguishable
	// from success via the exit code" — spec.md US5 edge cases).
	if _, copyErr := ctx.Printer.PayloadRaw(body); copyErr != nil {
		streamErr := cmdutil.NewConnError(fmt.Errorf("audit export stream interrupted: %w", copyErr))
		ctx.Printer.Error(streamErr)
		return cmdutil.Code(streamErr)
	}

	return cmdutil.ExitOK
}
