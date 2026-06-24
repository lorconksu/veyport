package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/wyiu/veyport/hub/internal/server"
)

// runRotateJWTSecret implements the `rotate-jwt-secret` admin subcommand.
func runRotateJWTSecret(args []string) error {
	fs := newAdminFlagSet("rotate-jwt-secret")
	dbPath := fs.String("db", defaultAdminDBPath, dbPathFlagUsage)
	yes := fs.Bool("yes", false, "skip confirmation prompt")
	if err := fs.Parse(args); err != nil {
		return err
	}

	st, err := openAdminStore(*dbPath)
	if err != nil {
		return err
	}
	defer st.Close()

	if !*yes {
		// Count active tokens for impact summary.
		var activeCount int
		row := st.DB().QueryRow(
			`SELECT COUNT(*) FROM api_tokens WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > datetime('now'))`,
		)
		_ = row.Scan(&activeCount)

		fmt.Println("WARNING: JWT secret rotation will invalidate ALL active user sessions.")
		fmt.Printf("Active API tokens that will be revoked: %d\n", activeCount)
		fmt.Println("The hub must be restarted after rotation for the new key to take effect.")
		fmt.Print("Type 'yes' to confirm: ")

		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		input := strings.TrimSpace(scanner.Text())
		if input != "yes" {
			return fmt.Errorf("rotation aborted")
		}
	}

	result, err := server.RotateJWTSecret(st)
	if err != nil {
		return err
	}

	fmt.Println("JWT signing secret rotated.")
	fmt.Printf("Revoked API tokens: %d\n", result.RevokedAPITokens)
	fmt.Println("All user sessions are now invalid; users must sign in again.")
	fmt.Println("Restart the hub to apply: systemctl restart veyport  (or: docker compose restart)")
	return nil
}
