package sessionlimit

import (
	"sync"
	"testing"
)

func TestWholeActivityReservationsPreserveExecutionCapacityAndBoundResources(t *testing.T) {
	b := New(8)
	var releases []func()
	for i := 0; i < MaxActivities; i++ {
		release, ok := b.AcquireActivity()
		if !ok {
			t.Fatal("activity capacity refused early", i)
		}
		releases = append(releases, release)
	}
	if _, ok := b.AcquireActivity(); ok {
		t.Fatal("unbounded activities")
	}
	if b.TryMaintenance() {
		t.Fatal("maintenance interrupted activities")
	}
	for i := 0; i < 8; i++ {
		if !b.Acquire() {
			t.Fatal("activities consumed terminal capacity")
		}
	}
	if b.Acquire() {
		t.Fatal("terminal capacity increased")
	}
	var wg sync.WaitGroup
	for _, release := range releases {
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go func(release func()) { defer wg.Done(); release() }(release)
		}
	}
	wg.Wait()
	if b.ActivityCount() != 0 || b.TryMaintenance() {
		t.Fatal("activity release corrupted execution reservations")
	}
	for i := 0; i < 8; i++ {
		b.Release()
	}
	if !b.TryMaintenance() {
		t.Fatal("quiescent maintenance refused")
	}
	if _, ok := b.AcquireActivity(); ok {
		t.Fatal("maintenance admitted activity")
	}
	b.EndMaintenance()
	release, ok := b.AcquireActivity()
	if !ok {
		t.Fatal("activity admission stayed closed")
	}
	release()
}

func TestActivityObservationOrderAndOldGenerationDetach(t *testing.T) {
	b := New(8)
	var old, current []uint32
	oldDetach := b.ObserveActivities(func(count uint32) { old = append(old, count) })
	release, _ := b.AcquireActivity()
	newDetach := b.ObserveActivities(func(count uint32) { current = append(current, count) })
	oldDetach()
	release()
	next, _ := b.AcquireActivity()
	next()
	newDetach()
	unobserved, _ := b.AcquireActivity()
	unobserved()
	if len(old) != 2 || old[0] != 0 || old[1] != 1 {
		t.Fatal("initial generation", old)
	}
	want := []uint32{1, 0, 1, 0}
	if len(current) != len(want) {
		t.Fatal("replacement generation", current)
	}
	for i, count := range want {
		if current[i] != count {
			t.Fatal("out of order mutation", current)
		}
	}
}

func TestActivityAdmissionAndMaintenanceCannotBothWin(t *testing.T) {
	for attempt := 0; attempt < 100; attempt++ {
		b := New(8)
		start := make(chan struct{})
		admitted := make(chan func(), 1)
		maintenance := make(chan bool, 1)
		go func() { <-start; release, _ := b.AcquireActivity(); admitted <- release }()
		go func() { <-start; maintenance <- b.TryMaintenance() }()
		close(start)
		release, m := <-admitted, <-maintenance
		if (release != nil) == m {
			t.Fatal("maintenance/activity race", m)
		}
		if release != nil {
			release()
		} else {
			b.EndMaintenance()
		}
	}
}

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
