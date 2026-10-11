// The optional independent receipt service is never started by the Standard hub.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/wyiu/veyport/hub/internal/auditingest"
)

var version = "dev"

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:], os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "audit receipt service unavailable")
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, output io.Writer) error {
	return runWithBuilder(ctx, args, output, func(ctx context.Context, path string) (*http.Server, error) {
		config, err := auditingest.LoadFileConfig(path)
		if err != nil {
			return nil, auditingest.ErrUnavailable
		}
		return config.Build(ctx)
	})
}

func runWithBuilder(ctx context.Context, args []string, output io.Writer, build func(context.Context, string) (*http.Server, error)) error {
	flags := flag.NewFlagSet("veyport-audit-ingest", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.Usage = func() {
		fmt.Fprintln(output, "Usage: veyport-audit-ingest --config <protected-file>\n       veyport-audit-ingest --version")
	}
	path := flags.String("config", "", "path to protected service configuration")
	showVersion := flags.Bool("version", false, "print version")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if *showVersion {
		fmt.Fprintln(output, version)
		return nil
	}
	if *path == "" || flags.NArg() != 0 {
		return auditingest.ErrUnavailable
	}
	server, err := build(ctx, *path)
	if err != nil {
		return auditingest.ErrUnavailable
	}
	stopped := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			_ = server.Shutdown(shutdown)
		case <-stopped:
		}
	}()
	err = server.ListenAndServeTLS("", "")
	close(stopped)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return auditingest.ErrUnavailable
}
