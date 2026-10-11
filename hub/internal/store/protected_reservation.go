package store

import (
	"context"
	"database/sql"
)

// protectedWriteTransaction reserves the writer before reading authority or
// evidence state. Without reservation, another writer can invalidate a deferred
// WAL snapshot and its later write fails with BUSY_SNAPSHOT. Reservation is a
// constant, caller-selected no-op UPDATE on the relevant existing table; it
// changes no rows and preserves protectedTransaction's FULL durability.
func (s *Store) protectedWriteTransaction(ctx context.Context, reservation string) (*sql.Tx, func(), error) {
	tx, cleanup, err := s.protectedTransaction(ctx)
	if err != nil {
		return nil, cleanup, err
	}
	if _, err = tx.ExecContext(ctx, reservation); err != nil {
		cleanup()
		return nil, func() {}, err
	}
	return tx, cleanup, nil
}
