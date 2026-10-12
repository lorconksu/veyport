package sessionlimit

import "sync"

// Budget atomically bounds terminal sessions and prepared/running executions.
type Budget struct {
	mu          sync.Mutex
	used        int
	maximum     int
	maintenance bool
}

func New(maximum int) *Budget { return &Budget{maximum: maximum} }
func (b *Budget) Acquire() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.maintenance || b.used >= b.maximum {
		return false
	}
	b.used++
	return true
}

// TryMaintenance reserves an exclusive, quiescent lease. It shares the same
// lock as admission, including preparations that have not started a process.
func (b *Budget) TryMaintenance() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.maintenance || b.used != 0 {
		return false
	}
	b.maintenance = true
	return true
}

func (b *Budget) EndMaintenance() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.maintenance = false
}
func (b *Budget) Release() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.used > 0 {
		b.used--
	}
}
