package store

import (
	"testing"
)

const (
	testBaseQuery       = "SELECT * FROM servers"
	testStatusClause    = "status = ?"
	testUnexpectedQuery = "unexpected query: %q"
	testUnexpectedArgs  = "unexpected args: %v"
)

func TestQueryBuilder_Empty(t *testing.T) {
	qb := newQueryBuilder(testBaseQuery)
	q, args := qb.Build()
	if q != "SELECT * FROM servers" {
		t.Fatalf("expected plain base query, got %q", q)
	}
	if len(args) != 0 {
		t.Fatalf("expected no args, got %v", args)
	}
}

func TestQueryBuilder_SingleWhere(t *testing.T) {
	qb := newQueryBuilder(testBaseQuery)
	qb.Where(testStatusClause, "online")
	q, args := qb.Build()
	if q != "SELECT * FROM servers WHERE status = ?" {
		t.Fatalf(testUnexpectedQuery, q)
	}
	if len(args) != 1 || args[0] != "online" {
		t.Fatalf(testUnexpectedArgs, args)
	}
}

func TestQueryBuilder_MultipleWhere(t *testing.T) {
	qb := newQueryBuilder(testBaseQuery)
	qb.Where(testStatusClause, "online")
	qb.Where("name LIKE ?", "%web%")
	q, args := qb.Build()
	if q != "SELECT * FROM servers WHERE status = ? AND name LIKE ?" {
		t.Fatalf(testUnexpectedQuery, q)
	}
	if len(args) != 2 {
		t.Fatalf("expected 2 args, got %d", len(args))
	}
}

func TestQueryBuilder_OrderBy(t *testing.T) {
	qb := newQueryBuilder(testBaseQuery)
	qb.OrderBy("created_at DESC")
	q, _ := qb.Build()
	if q != "SELECT * FROM servers ORDER BY created_at DESC" {
		t.Fatalf(testUnexpectedQuery, q)
	}
}

func TestQueryBuilder_LimitOffset(t *testing.T) {
	qb := newQueryBuilder(testBaseQuery)
	qb.Limit(10)
	qb.Offset(20)
	q, args := qb.Build()
	if q != "SELECT * FROM servers LIMIT ? OFFSET ?" {
		t.Fatalf(testUnexpectedQuery, q)
	}
	if len(args) != 2 || args[0] != 10 || args[1] != 20 {
		t.Fatalf(testUnexpectedArgs, args)
	}
}

func TestQueryBuilder_LimitWithoutOffset(t *testing.T) {
	qb := newQueryBuilder(testBaseQuery)
	qb.Limit(5)
	q, args := qb.Build()
	if q != "SELECT * FROM servers LIMIT ?" {
		t.Fatalf(testUnexpectedQuery, q)
	}
	if len(args) != 1 || args[0] != 5 {
		t.Fatalf(testUnexpectedArgs, args)
	}
}

func TestQueryBuilder_OffsetWithoutLimit(t *testing.T) {
	qb := newQueryBuilder(testBaseQuery)
	qb.Offset(10)
	q, args := qb.Build()
	if q != "SELECT * FROM servers OFFSET ?" {
		t.Fatalf(testUnexpectedQuery, q)
	}
	if len(args) != 1 || args[0] != 10 {
		t.Fatalf(testUnexpectedArgs, args)
	}
}

func TestQueryBuilder_Full(t *testing.T) {
	qb := newQueryBuilder(testBaseQuery)
	qb.Where(testStatusClause, "online")
	qb.OrderBy("created_at DESC")
	qb.Limit(10)
	qb.Offset(5)
	q, args := qb.Build()
	expected := "SELECT * FROM servers WHERE status = ? ORDER BY created_at DESC LIMIT ? OFFSET ?"
	if q != expected {
		t.Fatalf("expected %q, got %q", expected, q)
	}
	if len(args) != 3 || args[0] != "online" || args[1] != 10 || args[2] != 5 {
		t.Fatalf(testUnexpectedArgs, args)
	}
}

func TestQueryBuilder_CountQuery_NoWhere(t *testing.T) {
	qb := newQueryBuilder("SELECT * FROM audit_logs")
	q, args := qb.CountQuery("audit_logs")
	if q != "SELECT COUNT(*) FROM audit_logs" {
		t.Fatalf("unexpected count query: %q", q)
	}
	if len(args) != 0 {
		t.Fatalf("expected no args, got %v", args)
	}
}

func TestQueryBuilder_CountQuery_WithWhere(t *testing.T) {
	qb := newQueryBuilder("SELECT * FROM audit_logs")
	qb.Where("user_id = ?", "user-1")
	q, args := qb.CountQuery("audit_logs")
	if q != "SELECT COUNT(*) FROM audit_logs WHERE user_id = ?" {
		t.Fatalf("unexpected count query: %q", q)
	}
	if len(args) != 1 || args[0] != "user-1" {
		t.Fatalf(testUnexpectedArgs, args)
	}
}

func TestQueryBuilder_WhereIn(t *testing.T) {
	qb := newQueryBuilder("DELETE FROM servers")
	qb.WhereIn("id", []interface{}{"s1", "s2", "s3"})
	q, args := qb.Build()
	if q != "DELETE FROM servers WHERE id IN (?,?,?)" {
		t.Fatalf(testUnexpectedQuery, q)
	}
	if len(args) != 3 {
		t.Fatalf("expected 3 args, got %d", len(args))
	}
}
