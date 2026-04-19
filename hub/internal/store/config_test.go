package store_test

import (
	"strings"
	"testing"
)

func TestConfigGetSet(t *testing.T) {
	s := testStore(t)

	// Set a value
	if err := s.SetConfig("jwt_key", "test-secret"); err != nil {
		t.Fatalf("set config: %v", err)
	}

	// Get the value
	val, err := s.GetConfig("jwt_key")
	if err != nil {
		t.Fatalf("get config: %v", err)
	}
	if val != "test-secret" {
		t.Fatalf("expected 'test-secret', got '%s'", val)
	}
}

func TestConfigGetMissing(t *testing.T) {
	s := testStore(t)

	_, err := s.GetConfig("nonexistent")
	if err == nil {
		t.Fatal("expected error for missing key")
	}
}

func TestLookupConfigMissing(t *testing.T) {
	s := testStore(t)

	value, ok, err := s.LookupConfig("nonexistent")
	if err != nil {
		t.Fatalf("lookup missing config: %v", err)
	}
	if ok {
		t.Fatal("expected missing config lookup to return ok=false")
	}
	if value != "" {
		t.Fatalf("expected empty missing config value, got %q", value)
	}
}

func TestGetConfig_PropagatesLookupErrors(t *testing.T) {
	s := testStore(t)
	if err := s.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	_, err := s.GetConfig("jwt_key")
	if err == nil {
		t.Fatal("expected query error after store close")
	}
	if !strings.Contains(err.Error(), `get config "jwt_key":`) {
		t.Fatalf("expected wrapped lookup error, got %v", err)
	}
}
