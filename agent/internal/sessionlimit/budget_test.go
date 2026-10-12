package sessionlimit

import "testing"

func TestMaintenanceAndAdmissionCannotRace(t *testing.T) {
	for attempt := 0; attempt < 100; attempt++ {
		b := New(8)
		start := make(chan struct{})
		admitted := make(chan bool, 1)
		maintenance := make(chan bool, 1)
		go func() { <-start; admitted <- b.Acquire() }()
		go func() { <-start; maintenance <- b.TryMaintenance() }()
		close(start)
		a, m := <-admitted, <-maintenance
		if a == m {
			t.Fatalf("admission=%v maintenance=%v", a, m)
		}
		if m {
			if b.Acquire() || b.TryMaintenance() {
				t.Fatal("exclusive maintenance allowed work")
			}
			b.EndMaintenance()
			if !b.Acquire() {
				t.Fatal("maintenance did not release")
			}
		} else {
			if b.TryMaintenance() {
				t.Fatal("active work accepted maintenance")
			}
			b.Release()
			if !b.TryMaintenance() {
				t.Fatal("quiescent reservation refused")
			}
		}
	}
}

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
