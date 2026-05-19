package store

import (
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/wyiu/veyport/hub/internal/model"
)

func (s *Store) ListAuditSavedFilters() ([]model.AuditSavedFilter, error) {
	rows, err := s.db.Query(
		`SELECT id, name, created_by, filters_json, created_at, updated_at
		 FROM audit_saved_filters
		 ORDER BY updated_at DESC`,
	)
	if err != nil {
		return nil, fmt.Errorf("list audit saved filters: %w", err)
	}
	defer rows.Close()

	var filters []model.AuditSavedFilter
	for rows.Next() {
		var f model.AuditSavedFilter
		if err := rows.Scan(&f.ID, &f.Name, &f.CreatedBy, &f.FiltersJSON, &f.CreatedAt, &f.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan audit saved filter: %w", err)
		}
		filters = append(filters, f)
	}
	return filters, rows.Err()
}

func (s *Store) CreateAuditSavedFilter(createdBy, name, filtersJSON string) (*model.AuditSavedFilter, error) {
	id := uuid.NewString()
	_, err := s.db.Exec(
		`INSERT INTO audit_saved_filters (id, name, created_by, filters_json)
		 VALUES (?, ?, ?, ?)`,
		id, name, createdBy, filtersJSON,
	)
	if err != nil {
		return nil, fmt.Errorf("create audit saved filter: %w", err)
	}
	row := s.db.QueryRow(
		`SELECT id, name, created_by, filters_json, created_at, updated_at
		 FROM audit_saved_filters WHERE id = ?`, id,
	)
	var f model.AuditSavedFilter
	if err := row.Scan(&f.ID, &f.Name, &f.CreatedBy, &f.FiltersJSON, &f.CreatedAt, &f.UpdatedAt); err != nil {
		return nil, fmt.Errorf("read audit saved filter: %w", err)
	}
	return &f, nil
}

func (s *Store) DeleteAuditSavedFilter(id string) error {
	result, err := s.db.Exec(`DELETE FROM audit_saved_filters WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete audit saved filter: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete audit saved filter rows: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf(errNotFound)
	}
	return nil
}

func (s *Store) ListAuditReviews(limit int) ([]model.AuditReview, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := s.db.Query(
		`SELECT r.id, r.reviewer_id, u.username, r.filters_json, r.notes, r.from_time, r.to_time, r.completed_at, r.created_at
		 FROM audit_reviews r
		 JOIN users u ON u.id = r.reviewer_id
		 ORDER BY r.completed_at DESC
		 LIMIT ?`,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("list audit reviews: %w", err)
	}
	defer rows.Close()

	var reviews []model.AuditReview
	for rows.Next() {
		var review model.AuditReview
		var fromTime, toTime sql.NullString
		if err := rows.Scan(&review.ID, &review.ReviewerID, &review.Reviewer, &review.FiltersJSON,
			&review.Notes, &fromTime, &toTime, &review.CompletedAt, &review.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan audit review: %w", err)
		}
		if fromTime.Valid {
			review.From = &fromTime.String
		}
		if toTime.Valid {
			review.To = &toTime.String
		}
		reviews = append(reviews, review)
	}
	return reviews, rows.Err()
}

func (s *Store) CreateAuditReview(reviewerID, filtersJSON, notes string, from, to *string) (*model.AuditReview, error) {
	id := uuid.NewString()
	_, err := s.db.Exec(
		`INSERT INTO audit_reviews (id, reviewer_id, filters_json, notes, from_time, to_time)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		id, reviewerID, filtersJSON, notes, from, to,
	)
	if err != nil {
		return nil, fmt.Errorf("create audit review: %w", err)
	}
	row := s.db.QueryRow(
		`SELECT r.id, r.reviewer_id, u.username, r.filters_json, r.notes, r.from_time, r.to_time, r.completed_at, r.created_at
		 FROM audit_reviews r
		 JOIN users u ON u.id = r.reviewer_id
		 WHERE r.id = ?`, id,
	)
	var review model.AuditReview
	var fromTime, toTime sql.NullString
	if err := row.Scan(&review.ID, &review.ReviewerID, &review.Reviewer, &review.FiltersJSON,
		&review.Notes, &fromTime, &toTime, &review.CompletedAt, &review.CreatedAt); err != nil {
		return nil, fmt.Errorf("read audit review: %w", err)
	}
	if fromTime.Valid {
		review.From = &fromTime.String
	}
	if toTime.Valid {
		review.To = &toTime.String
	}
	return &review, nil
}

func (s *Store) ListAuditFlags(limit int) ([]model.AuditFlag, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := s.db.Query(
		`SELECT f.id, f.entry_id, u.username, f.created_by, f.filters_json, f.note, f.created_at
		 FROM audit_flags f
		 JOIN users u ON u.id = f.created_by
		 ORDER BY f.created_at DESC
		 LIMIT ?`,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("list audit flags: %w", err)
	}
	defer rows.Close()

	var flags []model.AuditFlag
	for rows.Next() {
		var flag model.AuditFlag
		var entryID sql.NullString
		if err := rows.Scan(&flag.ID, &entryID, &flag.CreatedBy, &flag.CreatedByID, &flag.FiltersJSON, &flag.Note, &flag.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan audit flag: %w", err)
		}
		if entryID.Valid {
			flag.EntryID = &entryID.String
		}
		flags = append(flags, flag)
	}
	return flags, rows.Err()
}

func (s *Store) CreateAuditFlag(createdBy string, entryID *string, filtersJSON, note string) (*model.AuditFlag, error) {
	id := uuid.NewString()
	_, err := s.db.Exec(
		`INSERT INTO audit_flags (id, entry_id, created_by, filters_json, note)
		 VALUES (?, ?, ?, ?, ?)`,
		id, entryID, createdBy, filtersJSON, note,
	)
	if err != nil {
		return nil, fmt.Errorf("create audit flag: %w", err)
	}
	row := s.db.QueryRow(
		`SELECT f.id, f.entry_id, u.username, f.created_by, f.filters_json, f.note, f.created_at
		 FROM audit_flags f
		 JOIN users u ON u.id = f.created_by
		 WHERE f.id = ?`,
		id,
	)
	var flag model.AuditFlag
	var nullableEntryID sql.NullString
	if err := row.Scan(&flag.ID, &nullableEntryID, &flag.CreatedBy, &flag.CreatedByID, &flag.FiltersJSON, &flag.Note, &flag.CreatedAt); err != nil {
		return nil, fmt.Errorf("read audit flag: %w", err)
	}
	if nullableEntryID.Valid {
		flag.EntryID = &nullableEntryID.String
	}
	return &flag, nil
}
