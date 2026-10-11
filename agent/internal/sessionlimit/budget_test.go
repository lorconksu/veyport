package sessionlimit

import "testing"

func TestConcurrentReservationsCannotExceedSharedBudget(t *testing.T) {
	budget := New(8)
	start := make(chan struct{})
	results := make(chan bool, 100)
	for i := 0; i < 100; i++ {
		go func() { <-start; results <- budget.Acquire() }()
	}
	close(start)
	acquired := 0
	for i := 0; i < 100; i++ {
		if <-results {
			acquired++
		}
	}
	if acquired != 8 {
		t.Fatalf("concurrent reservations=%d, want8", acquired)
	}
	for i := 0; i < 8; i++ {
		budget.Release()
	}
	budget.Release()
	for i := 0; i < 8; i++ {
		if !budget.Acquire() {
			t.Fatal("released slot not reusable")
		}
	}
	if budget.Acquire() {
		t.Fatal("extra release created unauthorized capacity")
	}
}
