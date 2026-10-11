package sessionlimit

import "sync"

// Budget atomically bounds terminal sessions and prepared/running executions.
type Budget struct {
	mu      sync.Mutex
	used    int
	maximum int
}

func New(maximum int) *Budget { return &Budget{maximum: maximum} }
func (b *Budget) Acquire() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.used >= b.maximum {
		return false
	}
	b.used++
	return true
}
func (b *Budget) Release() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.used > 0 {
		b.used--
	}
}
