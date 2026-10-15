package group_waiter

import (
	"sync"
)

type Waitable interface {
	Wait()
}

type GroupWaiter struct {
	waitGroup *sync.WaitGroup
	// sem bounds how many functions passed to Do can be running concurrently. A nil sem
	// (the New() zero case) means no limit is enforced.
	sem chan struct{}
}

// New returns a GroupWaiter that runs every function passed to Do concurrently, with no
// cap on how many run at once.
func New() *GroupWaiter {
	return &GroupWaiter{
		waitGroup: new(sync.WaitGroup),
	}
}

// NewWithLimit returns a GroupWaiter that behaves like New(), except that at most
// maxConcurrency functions passed to Do will run at the same time; further Do calls block
// (without blocking already-running work) until a slot frees up. This is useful to avoid
// unbounded fan-out when, e.g., iterating over a large number of items that each trigger
// one or more API calls, which can otherwise trip server-side rate limiting.
//
// A non-positive maxConcurrency behaves the same as New(), i.e. no limit.
func NewWithLimit(maxConcurrency int) *GroupWaiter {
	gw := &GroupWaiter{
		waitGroup: new(sync.WaitGroup),
	}
	if maxConcurrency > 0 {
		gw.sem = make(chan struct{}, maxConcurrency)
	}
	return gw
}

func (gw *GroupWaiter) Do(f func()) {
	gw.waitGroup.Add(1)
	if gw.sem != nil {
		// Acquire a slot before spawning the goroutine, so that once maxConcurrency
		// goroutines are already running, further Do calls block the caller (e.g. a
		// for loop submitting work) instead of spawning unbounded goroutines that
		// would then all contend for the slot anyway.
		gw.sem <- struct{}{}
	}
	go func() {
		defer gw.waitGroup.Done()
		if gw.sem != nil {
			defer func() { <-gw.sem }()
		}
		f()
	}()
}

func (gw *GroupWaiter) Wait() {
	gw.waitGroup.Wait()
}
