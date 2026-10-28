package store

// WithInteractivePolicy serializes local authorization/registration with policy
// mutations. Callbacks must not reacquire this lock. An established terminal's
// bounded ordered send may remain inside the callback so policy revocation
// cannot commit between its final authorization check and agent delivery.
func (s *Store) WithInteractivePolicy(fn func() error) error {
	s.interactivePolicyMu.Lock()
	defer s.interactivePolicyMu.Unlock()
	return fn()
}

// ObserveInteractivePolicy installs a local invalidation observer. It runs
// after a successful policy mutation, before new admissions can observe it.
func (s *Store) ObserveInteractivePolicy(fn func()) {
	s.interactivePolicyMu.Lock()
	defer s.interactivePolicyMu.Unlock()
	s.interactivePolicyObservers = append(s.interactivePolicyObservers, fn)
}

func (s *Store) changeInteractivePolicy(fn func() error) error {
	return s.WithInteractivePolicy(func() error {
		if err := fn(); err != nil {
			return err
		}
		for _, observe := range s.interactivePolicyObservers {
			observe()
		}
		return nil
	})
}
