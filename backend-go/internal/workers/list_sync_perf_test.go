package workers

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestListSyncPerformance measures a 500,000-name feed: the first run, a
// second with a tenth of the names replaced, the heap, the longest wait of a
// writer that inserts into proxy_logs every 50 ms meanwhile, as the log
// tailer does, and the longest a refresh transaction held the write lock. Run with SPM_PERF=1 go test -run ListSyncPerformance -v.
func TestListSyncPerformance(t *testing.T) {
	if os.Getenv("SPM_PERF") == "" {
		t.Skip("set SPM_PERF=1 to measure")
	}
	t.Setenv("SPM_DNS_BLOCKLIST_MAX_DOMAINS", "2000000")
	db, cleanup := setupTestDB(t)
	defer cleanup()
	const n = 500_000
	feed := func(from int) string {
		var b strings.Builder
		for i := from; i < from+n; i++ {
			fmt.Fprintf(&b, "0.0.0.0 d%07d.example.com\n", i)
		}
		return b.String()
	}

	var peak atomic.Uint64
	stopMem := make(chan struct{})
	go func() {
		var m runtime.MemStats
		for {
			select {
			case <-stopMem:
				return
			case <-time.After(20 * time.Millisecond):
				runtime.ReadMemStats(&m)
				if m.HeapAlloc > peak.Load() {
					peak.Store(m.HeapAlloc)
				}
			}
		}
	}()
	// The tailer: one insert every 50 ms, timed.
	var maxWait atomic.Int64
	var failures atomic.Int64
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for ctx.Err() == nil {
			start := time.Now()
			if _, err := db.Exec("INSERT INTO proxy_logs(timestamp, unix_timestamp, source_ip, destination, status) VALUES(datetime('now'), strftime('%s','now'), '192.168.1.5', 'x.test:443', 'TCP_TUNNEL/200')"); err != nil {
				failures.Add(1)
			}
			if d := time.Since(start).Milliseconds(); d > maxWait.Load() {
				maxWait.Store(d)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()

	var maxHeld atomic.Int64
	var txs atomic.Int64
	prevHeld := writeLockHeld
	writeLockHeld = func(d time.Duration) {
		txs.Add(1)
		if ms := d.Milliseconds(); ms > maxHeld.Load() {
			maxHeld.Store(ms)
		}
	}
	t.Cleanup(func() { writeLockHeld = prevHeld })

	serveFeeds(t, map[string]string{feedA: feed(0)})
	start := time.Now()
	c1 := syncDomains(db, feedA)
	first := time.Since(start)

	// B: one name, its id after A's half million. Its windows must read its
	// own row, not the half million before it.
	serveFeeds(t, map[string]string{feedA: feed(0), feedB: hosts("only-b.example")})
	syncDomains(db, feedA, feedB)

	serveFeeds(t, map[string]string{feedA: feed(n / 10), feedB: hosts("only-b.example")}) // a tenth dropped, a tenth new
	start = time.Now()
	c2 := syncDomains(db, feedA, feedB)
	second := time.Since(start)
	cancel()
	wg.Wait()
	close(stopMem)

	t.Logf("first run %v: %+v", first.Round(time.Millisecond), c1)
	t.Logf("second run %v: %+v", second.Round(time.Millisecond), c2)
	t.Logf("peak heap %d MiB; writer: longest wait %d ms, %d failed inserts; refresh: %d write transactions, longest held %d ms",
		peak.Load()>>20, maxWait.Load(), failures.Load(), txs.Load(), maxHeld.Load())
	if c1.Added != n || c2.Added != n/10 || c2.Removed != n/10 || c2.Fetched != 2 {
		t.Errorf("counts: first %+v, second %+v", c1, c2)
	}
	// Measured on an M4 laptop: 4.4 to 4.9 s, 3.7 to 4.4 s, 75 MiB, the
	// writer waiting 57 to 112 ms. The bounds leave room for a slower host.
	if first > 15*time.Second || second > 15*time.Second || peak.Load() > 400<<20 || maxWait.Load() > 500 || maxHeld.Load() > 300 || failures.Load() > 0 {
		t.Errorf("over the predictions: first %v, second %v, heap %d MiB, writer wait %d ms, failures %d",
			first, second, peak.Load()>>20, maxWait.Load(), failures.Load())
	}
}
