// Package budget bounds the body bytes the WAF inspects at the same time.
//
// Each inspection holds the body it read and several working copies of it
// (normalization, body segments, base64 decoding, the Core Rule Set pass), and
// nothing bounded how many ran at once: 64 concurrent requests with 1 MiB
// bodies took the WAF past its 256 MiB container limit and the kernel killed
// it. With REQMOD fail-closed, Squid then suspended the ICAP service and
// refused every client for three minutes.
//
// A request reserves its body size before the body is read, and waits while
// the budget is spent. go-icap reads the body only when the handler does (it
// sends "100 Continue" on the first read), so a waiting request holds no more
// than Squid's preview.
//
// Waiters are not served in order: any request that fits goes in. A strict
// FIFO (golang.org/x/sync/semaphore) would hold a small form post behind every
// queued 1 MiB body; here the large ones wait, and give up at their deadline.
package budget

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// Budget is a count of bytes that can be reserved and released.
type Budget struct {
	mu      sync.Mutex
	total   int64
	used    int64
	changed chan struct{} // closed and replaced on every release
}

// New returns a budget of total bytes. A total under 1 is taken as 1.
func New(total int64) *Budget {
	if total < 1 {
		total = 1
	}
	return &Budget{total: total, changed: make(chan struct{})}
}

// Total is the size of the budget.
func (b *Budget) Total() int64 { return b.total }

// Used is the number of bytes reserved now.
func (b *Budget) Used() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.used
}

// Acquire reserves n bytes, waiting until they fit or ctx ends. It returns the
// number of bytes reserved, to give back to Release, and whether it got them.
// n is cut to the total, so a body larger than the whole budget still goes in
// when nothing else is reserved. n <= 0 reserves nothing and never waits.
func (b *Budget) Acquire(ctx context.Context, n int64) (int64, bool) {
	if n <= 0 {
		return 0, true
	}
	if n > b.total {
		n = b.total
	}
	for {
		b.mu.Lock()
		if b.used+n <= b.total {
			b.used += n
			b.mu.Unlock()
			return n, true
		}
		ch := b.changed
		b.mu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			return 0, false
		}
	}
}

// Release gives back n bytes reserved by Acquire and wakes the waiters.
func (b *Budget) Release(n int64) {
	if n <= 0 {
		return
	}
	b.mu.Lock()
	b.used -= n
	if b.used < 0 {
		b.used = 0
	}
	close(b.changed)
	b.changed = make(chan struct{})
	b.mu.Unlock()
}

// Size derives the budget from the cgroup memory limit in cgroupDir:
// (memory.max - memory.current) / costPerByte, so that the bytes in
// inspection, times what an inspected byte costs, fit in the memory still
// free. It returns fallback when there is no limit or it cannot be read, and
// never less than floor, so that one body of the largest inspected size always
// fits.
func Size(cgroupDir string, costPerByte, floor, fallback int64) (total, limit int64) {
	limit = ReadLimit(cgroupDir)
	if limit <= 0 || costPerByte <= 0 {
		return max(fallback, floor), limit
	}
	current := readInt(filepath.Join(cgroupDir, "memory.current"))
	free := limit - current
	return max(free/costPerByte, floor), limit
}

// ReadLimit returns the cgroup v2 memory limit in bytes, or 0 when there is
// none ("max") or it cannot be read.
func ReadLimit(cgroupDir string) int64 {
	return readInt(filepath.Join(cgroupDir, "memory.max"))
}

func readInt(path string) int64 {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	v, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil || v < 0 {
		return 0
	}
	return v
}
