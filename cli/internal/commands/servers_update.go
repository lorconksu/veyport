package commands

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/wyiu/veyport/cli/internal/api"
	"github.com/wyiu/veyport/cli/internal/auth"
	"github.com/wyiu/veyport/cli/internal/cmdutil"
)

const serversUpdateUsage = "usage: vey servers update <node> [--check | --status [--operation ID] | --bootstrap-idle-confirmed | --acknowledge-recovery ID --verified-sha256 HASH]"

type serversUpdateOptions struct {
	node                      string
	check, status             bool
	bootstrapIdleConfirmed    bool
	operation, recovery, hash string
}

func parseServersUpdate(args []string) (serversUpdateOptions, error) {
	var o serversUpdateOptions
	fail := func() (serversUpdateOptions, error) { return o, cmdutil.NewUsageError(errors.New(serversUpdateUsage)) }
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--check":
			if o.check {
				return fail()
			}
			o.check = true
		case "--status":
			if o.status {
				return fail()
			}
			o.status = true
		case "--bootstrap-idle-confirmed":
			if o.bootstrapIdleConfirmed {
				return fail()
			}
			o.bootstrapIdleConfirmed = true
		case "--operation", "--acknowledge-recovery", "--verified-sha256":
			if i+1 >= len(args) {
				return fail()
			}
			flag := args[i]
			i++
			if args[i] == "" || strings.HasPrefix(args[i], "-") {
				return fail()
			}
			switch flag {
			case "--operation":
				if o.operation != "" {
					return fail()
				}
				o.operation = args[i]
			case "--acknowledge-recovery":
				if o.recovery != "" {
					return fail()
				}
				o.recovery = args[i]
			case "--verified-sha256":
				if o.hash != "" {
					return fail()
				}
				o.hash = args[i]
			}
		default:
			if strings.HasPrefix(args[i], "-") || o.node != "" {
				return fail()
			}
			o.node = args[i]
		}
	}
	if strings.TrimSpace(o.node) == "" || o.check && o.status || o.operation != "" && !o.status || o.recovery != "" && (o.check || o.status) || ((o.recovery != "") != (o.hash != "")) || o.bootstrapIdleConfirmed && (o.check || o.status || o.recovery != "") {
		return fail()
	}
	return o, nil
}
func runServersUpdate(ctx *Context, args []string) int {
	o, err := parseServersUpdate(args)
	if err != nil {
		return serversUpdateFinish(ctx, err)
	}
	hubURL, err := ctx.RequireHub()
	if err != nil {
		return serversUpdateFinish(ctx, err)
	}
	_, actx, err := newAuthContext(ctx, hubURL)
	if err != nil {
		return serversUpdateFinish(ctx, err)
	}
	if actx.Mode() == auth.ModeAPIToken {
		return serversUpdateFinish(ctx, cmdutil.NewForbiddenError(errors.New("agent updates require vey login; clear VEYPORT_TOKEN and the configured API token")))
	}
	id, err := resolveServerID(actx, o.node)
	if err != nil {
		return serversUpdateFinish(ctx, err)
	}
	base := "/api/servers/" + url.PathEscape(id) + "/agent-update"
	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	call, cancel := context.WithTimeout(signalCtx, 150*time.Second)
	defer cancel()
	if o.status {
		var result api.AgentUpdate
		err = actx.Do(call, func(c *api.Client) error {
			return c.Get(call, base+"/status", url.Values{"operation_id": {o.operation}}, &result)
		})
		if err == nil {
			err = printAgentUpdate(ctx, result)
		}
		return serversUpdateFinish(ctx, err)
	}
	if o.recovery != "" {
		var result api.AgentUpdate
		err = actx.Do(call, func(c *api.Client) error {
			return c.Post(call, base+"/recovery", struct {
				OperationID    string `json:"operation_id"`
				VerifiedSHA256 string `json:"verified_sha256"`
			}{o.recovery, o.hash}, &result)
		})
		if err == nil {
			err = printAgentUpdate(ctx, result)
		}
		return serversUpdateFinish(ctx, err)
	}
	var check api.AgentUpdateCheck
	err = actx.Do(call, func(c *api.Client) error { return c.Get(call, base, nil, &check) })
	if err != nil {
		return serversUpdateFinish(ctx, err)
	}
	if o.bootstrapIdleConfirmed && (!check.BootstrapRequired || !check.BootstrapIdleConfirmationRequired) {
		return serversUpdateFinish(ctx, cmdutil.NewForbiddenError(errors.New("--bootstrap-idle-confirmed is only valid for the preserving manual bootstrap path")))
	}
	if !o.check && check.BootstrapRequired && check.BootstrapIdleConfirmationRequired && (!o.bootstrapIdleConfirmed || check.ConnectionID == "") {
		return serversUpdateFinish(ctx, cmdutil.NewForbiddenError(errors.New("this agent cannot prove complete file/upload/log quiescence. Through direct SSH and operator coordination, close user file/log clients and agent sessions, let all work finish, verify the agent is idle, then run vey servers update "+updateShellQuote(o.node)+" --bootstrap-idle-confirmed. Known active work will still refuse")))
	}
	if !o.check && !check.BootstrapRequired && !check.Supported {
		return serversUpdateFinish(ctx, cmdutil.NewForbiddenError(fmt.Errorf("agent update is unsupported: %s", check.Reason)))
	}
	if !o.check && !check.BootstrapRequired && check.Supported && !check.UpdateAvailable && check.Operation != nil && (check.Operation.State == "confirmation_pending" || check.Operation.State == "rollback_confirmation_pending" || check.Operation.State == "unknown") {
		return serversUpdateFinish(ctx, errors.New("the existing update outcome is unconfirmed; inspect vey servers update "+updateShellQuote(o.node)+" --status"))
	}
	if o.check || !check.BootstrapRequired && check.Supported && !check.UpdateAvailable {
		err = ctx.Printer.Payload(check, func(w io.Writer, _ any) error {
			current := "unknown (bootstrap required)"
			if check.Current != nil {
				current = check.Current.Version
			}
			_, err := fmt.Fprintf(w, "Current agent: %s\nHub artifact: %s (%s)\nUpdate available: %t\nBootstrap required: %t\n", current, check.Target.Version, check.Target.SHA256, check.UpdateAvailable, check.BootstrapRequired)
			if check.Reason != "" {
				fmt.Fprintln(w, check.Reason)
			}
			return err
		})
		return serversUpdateFinish(ctx, err)
	}
	var start api.AgentUpdateStart
	err = actx.Do(call, func(c *api.Client) error {
		return c.Post(call, base, struct {
			Version                string `json:"expected_version"`
			Revision               string `json:"expected_revision"`
			BootstrapIdleConfirmed bool   `json:"bootstrap_idle_confirmed,omitempty"`
			ExpectedConnectionID   string `json:"expected_connection_id,omitempty"`
		}{check.Target.Version, check.Target.Revision, o.bootstrapIdleConfirmed, func() string {
			if o.bootstrapIdleConfirmed {
				return check.ConnectionID
			}
			return ""
		}()}, &start)
	})
	if err != nil {
		return serversUpdateFinish(ctx, err)
	}
	if start.Operation.ID == "" || start.Operation.NodeID != id {
		return serversUpdateFinish(ctx, errors.New("Hub returned an invalid update operation; inspect status before retrying"))
	}
	if start.BootstrapTicket != "" {
		if len(start.BootstrapTicket) != 64 {
			return serversUpdateFinish(ctx, errors.New("Hub returned an invalid bootstrap ticket"))
		}
		start.BootstrapCommand = fmt.Sprintf("curl -fsS --proto '=https' %s | sudo bash -s -- --hub %s --ticket %s", updateShellQuote(hubURL+"/install/agent-update.sh"), updateShellQuote(hubURL), updateShellQuote(start.BootstrapTicket))
		err = ctx.Printer.Payload(start, func(w io.Writer, _ any) error {
			_, err := fmt.Fprintf(w, "Operation: %s\nRun on the node through direct SSH before the ticket expires:\n%s\nThen inspect: vey servers update %s --status --operation %s\n", start.Operation.ID, start.BootstrapCommand, updateShellQuote(o.node), start.Operation.ID)
			return err
		})
		return serversUpdateFinish(ctx, err)
	}
	ctx.Printer.Errorf("Agent update operation %s started; waiting for verified reconnection.\n", start.Operation.ID)
	result := start.Operation
	for {
		err = actx.Do(call, func(c *api.Client) error {
			return c.Get(call, base+"/status", url.Values{"operation_id": {start.Operation.ID}}, &result)
		})
		if err != nil {
			ctx.Printer.Errorf("Inspect this operation before retrying: vey servers update %s --status --operation %s\n", updateShellQuote(o.node), start.Operation.ID)
			return serversUpdateFinish(ctx, err)
		}
		if result.ID != start.Operation.ID || result.NodeID != id {
			return serversUpdateFinish(ctx, errors.New("Hub status returned a different update operation"))
		}
		switch result.State {
		case "succeeded":
			if result.ObservedVersion != start.Operation.Target.Version || result.ObservedRevision != start.Operation.Target.Revision || result.ObservedSHA256 != start.Operation.Target.SHA256 {
				return serversUpdateFinish(ctx, errors.New("agent success lacks exact reconnect artifact evidence"))
			}
			return serversUpdateFinish(ctx, printAgentUpdate(ctx, result))
		case "failed", "rolled_back", "expired", "unknown", "recovery_acknowledged":
			if err = printAgentUpdate(ctx, result); err != nil {
				return serversUpdateFinish(ctx, err)
			}
			return serversUpdateFinish(ctx, errors.New("agent update did not reach verified success; inspect the reported operation before retrying"))
		}
		select {
		case <-call.Done():
			ctx.Printer.Errorf("Outcome is unconfirmed. Inspect: vey servers update %s --status --operation %s\n", updateShellQuote(o.node), start.Operation.ID)
			return serversUpdateFinish(ctx, call.Err())
		case <-time.After(500 * time.Millisecond):
		}
	}
}
func updateShellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }
func printAgentUpdate(ctx *Context, op api.AgentUpdate) error {
	return ctx.Printer.Payload(op, func(w io.Writer, _ any) error {
		_, err := fmt.Fprintf(w, "Operation: %s\nState: %s\nTarget: %s\n", op.ID, op.State, op.Target.Version)
		if err != nil {
			return err
		}
		if op.ObservedSHA256 != "" {
			fmt.Fprintf(w, "Reconnected agent: %s (%s)\n", op.ObservedVersion, op.ObservedSHA256)
		}
		if op.Reason != "" {
			fmt.Fprintln(w, op.Reason)
		}
		if op.State == "unknown" && op.PreviousSHA256 != "" {
			fmt.Fprintf(w, "After direct SSH verification of the original binary and service, recovery can be acknowledged after %s UTC.\nVerify on the node: sudo sha256sum /usr/local/bin/veyport-agent; sudo systemctl status veyport-agent\nExpected original SHA256: %s\n", time.UnixMilli(op.ExpiresAt+190000).UTC().Format("2006-01-02 15:04:05"), op.PreviousSHA256)
		}
		return nil
	})
}
func serversUpdateFinish(ctx *Context, err error) int {
	if err != nil {
		ctx.Printer.Error(err)
		return cmdutil.Code(err)
	}
	return cmdutil.ExitOK
}
