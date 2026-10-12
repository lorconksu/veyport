package sessionlimit

import "sync"

// Budget atomically bounds terminal sessions and prepared/running executions.
type Budget struct {
	mu          sync.Mutex
	used        int
	maximum     int
	maintenance bool
	activities  uint32
	observer    *activityObserver
}

const MaxActivities = 128

type activityObserver struct{ emit func(uint32) }

// AcquireActivity reserves a whole file operation or log tail, independently
// of terminal capacity. The returned release is safe to call more than once.
func (b *Budget) AcquireActivity() (func(), bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.maintenance || b.activities >= MaxActivities {
		return nil, false
	}
	b.activities++
	b.notifyActivity()
	var once sync.Once
	return func() {
		once.Do(func() {
			b.mu.Lock()
			defer b.mu.Unlock()
			b.activities--
			b.notifyActivity()
		})
	}, true
}

func (b *Budget) ActivityCount() uint32 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.activities
}

// ObserveActivities emits the initial count and every subsequent change in
// mutation order. emit must only enqueue to a bounded, cancellation-aware
// session queue: it must not call back into Budget or acquire Runtime locks.
func (b *Budget) ObserveActivities(emit func(uint32)) func() {
	b.mu.Lock()
	defer b.mu.Unlock()
	o := &activityObserver{emit: emit}
	b.observer = o
	b.notifyActivity()
	return func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.observer == o {
			b.observer = nil
		}
	}
}

func (b *Budget) notifyActivity() {
	if b.observer != nil {
		b.observer.emit(b.activities)
	}
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
	if b.maintenance || b.used != 0 || b.activities != 0 {
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
