package workers

import "sync"

// wg tracks the long-lived background workers so shutdown can wait for them.
// Without it, workerCancel() only closed a channel and the process proceeded to
// exit — a tailer holding a read-but-uncommitted batch simply lost it, with no
// record that anything had been dropped (SECURE-CONC-02).
var wg sync.WaitGroup

// track runs fn as a tracked worker goroutine.
func track(fn func()) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		fn()
	}()
}

// Wait blocks until every tracked worker has returned. Callers should bound it
// with a timeout: a worker wedged on I/O must not prevent the process exiting.
func Wait() { wg.Wait() }
