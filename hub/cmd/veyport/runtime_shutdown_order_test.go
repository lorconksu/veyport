package main

import (
	"context"
	"database/sql/driver"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
	"modernc.org/sqlite"
)

func TestServerWaitsForSessionPrunerOnHTTPStartupFailure(t *testing.T) {
	const subprocessMarker = "veyport-session-pruner-child"
	if args := flag.Args(); len(args) == 1 && args[0] == subprocessMarker {
		// A fresh private directory also isolates a manually invoked child.
		directory, err := os.MkdirTemp(".", "pruner-")
		if err != nil {
			t.Fatal(err)
		}
		// Initialize the process-wide signal machinery outside the bubble.
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, os.Interrupt)
		synctest.Test(t, func(*testing.T) {
			err := checkPrunerShutdown(filepath.Join(directory, "hub.db"))
			if err := errors.Join(err, os.RemoveAll(directory)); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			// The token blacklist is a process-lifetime worker with no stop
			// method. Exit the isolated process after the assertions so that
			// it cannot keep the synctest bubble alive.
			os.Exit(0)
		})
		return
	}

	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^"+t.Name()+"$", "--", subprocessMarker)
	cmd.Dir = t.TempDir()
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("shutdown worker check: %v\n%s", err, output)
	}
}

func checkPrunerShutdown(path string) error {
	const (
		host       = "veyport-shutdown-test.invalid."
		dnsRefusal = "fixture refused DNS resolution"
	)
	entered, release := make(chan struct{}), make(chan struct{})
	refused := make(chan struct{})
	var refuseOnce sync.Once
	if err := sqlite.RegisterScalarFunction("veyport_test_wait_for_pruner", 0, func(*sqlite.FunctionContext, []driver.Value) (driver.Value, error) {
		close(entered)
		<-release
		return nil, nil
	}); err != nil {
		return err
	}
	if err := seedBlockedSessionPrune(path); err != nil {
		return fmt.Errorf("seed session pruner fixture: %w", err)
	}

	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			// Hold HTTP startup until the real pruner starts deleting
			// the fixture's expired session. No DNS request leaves Go.
			<-entered
			refuseOnce.Do(func() { close(refused) })
			return nil, errors.New(dnsRefusal)
		},
	}
	os.Args = []string{"veyport", "--db", path, "--addr", host + ":0", "--grpc-addr", "invalid-bind-address"}
	flag.CommandLine = flag.NewFlagSet("shutdown-fixture", flag.ContinueOnError)
	result := make(chan error, 1)
	go func() { result <- runServer() }()

	// Run every runnable goroutine while the SQLite deletion is held.
	// With the shutdown join removed, startup can return at this point.
	synctest.Wait()
	select {
	case <-entered:
	default:
		const missingPrune = "the session pruner did not reach the expired session"
		select {
		case err := <-result:
			return fmt.Errorf("%s: runServer returned %v", missingPrune, err)
		default:
			return errors.New(missingPrune)
		}
	}
	select {
	case <-refused:
	default:
		close(release)
		synctest.Wait()
		return errors.New("HTTP startup did not reach the fixture bind refusal while the session pruner was held")
	}
	select {
	case err := <-result:
		close(release)
		synctest.Wait()
		return fmt.Errorf("runServer returned before the session pruner was released: %v", err)
	default:
	}

	close(release)
	var bindErr *net.OpError
	var dnsErr *net.DNSError
	if err := <-result; !errors.As(err, &bindErr) || bindErr.Op != "listen" ||
		!errors.As(bindErr, &dnsErr) || dnsErr.Name != host || dnsErr.Err != dnsRefusal {
		return fmt.Errorf("startup error = %v, want failure listening on %s", err, host)
	}
	st, err := store.New(path)
	if err != nil {
		return err
	}
	defer st.Close()
	if _, err := st.GetSession("stale"); !errors.Is(err, store.ErrSessionNotFound) {
		return fmt.Errorf("session pruner did not delete the expired session before return: %v", err)
	}
	return nil
}

func seedBlockedSessionPrune(path string) (err error) {
	st, err := store.New(path)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, st.Close()) }()
	const userID = "prune-fixture"
	if err = st.SetConfig("ssh_gateway_enabled", "false"); err != nil {
		return err
	}
	if err = st.CreateUser(&model.User{ID: userID, Username: userID, Email: "prune@example.test", Role: model.RoleViewer, PasswordHash: "unused"}); err != nil {
		return err
	}
	ended := time.Now().AddDate(0, -2, 0)
	session := &model.Session{ID: "stale", UserID: userID, Kind: model.SessionKindWeb, CreatedAt: ended, LastSeenAt: ended}
	if err = st.CreateSession(session); err != nil {
		return err
	}
	if _, err = st.EndSession(session.ID, "logout", nil, ended); err != nil {
		return err
	}
	_, err = st.DB().Exec(`CREATE TRIGGER hold_test_prune BEFORE DELETE ON sessions
		WHEN OLD.id = 'stale'
		BEGIN SELECT veyport_test_wait_for_pruner(); END`)
	return err
}
