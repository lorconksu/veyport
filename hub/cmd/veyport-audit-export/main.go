// Optional privileged archive-to-search worker. It has no admission authority.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/wyiu/veyport/hub/internal/auditingest"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if run(ctx, os.Args[1:], os.Stderr) != nil {
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("veyport-audit-export", flag.ContinueOnError)
	flags.SetOutput(output)
	config := flags.String("config", "", "private exporter configuration path")
	once := flags.Bool("once", false, "export one bounded page")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		return auditingest.ErrUnavailable
	}
	worker, err := auditingest.LoadExporter(*config)
	if err != nil {
		fmt.Fprintln(output, "audit exporter configuration unavailable")
		return auditingest.ErrUnavailable
	}
	for {
		err = worker.Step(ctx)
		if *once {
			if err != nil {
				fmt.Fprintln(output, "audit exporter page unavailable")
				return auditingest.ErrUnavailable
			}
			return nil
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}
