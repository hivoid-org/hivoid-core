package server

import (
	"sync"
	"sync/atomic"
)

type userCounter struct {
	active atomic.Int64
}

// ConnectionLimiter tracks active per-user forwarded connections.
type ConnectionLimiter struct {
	counters sync.Map // map[[16]byte]*userCounter
}

func (l *ConnectionLimiter) counter(uuid [16]byte) *userCounter {
	if v, ok := l.counters.Load(uuid); ok {
		return v.(*userCounter)
	}
	created := &userCounter{}
	actual, _ := l.counters.LoadOrStore(uuid, created)
	return actual.(*userCounter)
}

// TryAcquire increments active count and checks max limit.
// max=0 means unlimited.
func (l *ConnectionLimiter) TryAcquire(uuid [16]byte, max int) (active int64, ok bool) {
	c := l.counter(uuid)
	active = c.active.Add(1)
	if max > 0 && active > int64(max) {
		c.active.Add(-1)
		return int64(max), false
	}
	return active, true
}

// Release decrements active count for the user.
func (l *ConnectionLimiter) Release(uuid [16]byte) int64 {
	c := l.counter(uuid)
	n := c.active.Add(-1)
	if n < 0 {
		c.active.Store(0)
		return 0
	}
	return n
}
