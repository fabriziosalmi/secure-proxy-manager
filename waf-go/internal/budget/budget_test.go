package budget

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAcquireWithinTheTotalDoesNotWait(t *testing.T) {
	b := New(10)
	n, ok := b.Acquire(context.Background(), 6)
	if !ok || n != 6 || b.Used() != 6 {
		t.Fatalf("got n=%d ok=%v used=%d, want 6 true 6", n, ok, b.Used())
	}
	b.Release(n)
	if b.Used() != 0 {
		t.Fatalf("used=%d after release, want 0", b.Used())
	}
}

func TestAcquireBeyondTheTotalGivesUpAtTheDeadline(t *testing.T) {
	b := New(10)
	held, _ := b.Acquire(context.Background(), 8)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, ok := b.Acquire(ctx, 5); ok {
		t.Fatal("5 bytes were granted with 8 of 10 held")
	}
	if d := time.Since(start); d < 40*time.Millisecond {
		t.Fatalf("gave up after %v, before the deadline", d)
	}
	if b.Used() != 8 {
		t.Fatalf("used=%d after a refused acquire, want 8", b.Used())
	}
	b.Release(held)
}

func TestReleaseWakesAWaiter(t *testing.T) {
	b := New(10)
	held, _ := b.Acquire(context.Background(), 8)
	got := make(chan bool, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		n, ok := b.Acquire(ctx, 5)
		got <- ok && n == 5
	}()
	time.Sleep(20 * time.Millisecond)
	b.Release(held)
	select {
	case ok := <-got:
		if !ok {
			t.Fatal("the waiter did not get its 5 bytes")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the waiter was not woken by the release")
	}
}

// A small body is not held behind a large one that waits.
func TestASmallRequestPassesALargeOneThatWaits(t *testing.T) {
	b := New(10)
	held, _ := b.Acquire(context.Background(), 7)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go b.Acquire(ctx, 9) // waits until cancel
	time.Sleep(20 * time.Millisecond)
	quick, qcancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer qcancel()
	n, ok := b.Acquire(quick, 2)
	if !ok || n != 2 {
		t.Fatalf("a 2-byte request behind a waiting 9-byte one: n=%d ok=%v", n, ok)
	}
	b.Release(n)
	b.Release(held)
}

func TestARequestLargerThanTheTotalGoesInAlone(t *testing.T) {
	b := New(10)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	n, ok := b.Acquire(ctx, 50)
	if !ok || n != 10 {
		t.Fatalf("got n=%d ok=%v, want the whole budget", n, ok)
	}
	b.Release(n)
}

func TestNothingToReserveNeverWaits(t *testing.T) {
	b := New(1)
	held, _ := b.Acquire(context.Background(), 1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if n, ok := b.Acquire(ctx, 0); !ok || n != 0 {
		t.Fatalf("a request without a body waited or failed: n=%d ok=%v", n, ok)
	}
	b.Release(held)
}

func writeCgroup(t *testing.T, max, current string) string {
	t.Helper()
	dir := t.TempDir()
	if max != "" {
		if err := os.WriteFile(filepath.Join(dir, "memory.max"), []byte(max+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if current != "" {
		if err := os.WriteFile(filepath.Join(dir, "memory.current"), []byte(current+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestSizeFromTheCgroupLimit(t *testing.T) {
	const mib = 1 << 20
	// 256 MiB limit, 56 MiB in use, each inspected byte costing 20: 10 MiB.
	dir := writeCgroup(t, "268435456", "58720256")
	total, limit := Size(dir, 20, mib, 64*mib)
	if total != 10*mib || limit != 256*mib {
		t.Fatalf("total=%d limit=%d, want %d %d", total, limit, 10*mib, 256*mib)
	}
}

func TestSizeNeverBelowTheFloor(t *testing.T) {
	const mib = 1 << 20
	dir := writeCgroup(t, "268435456", "260000000")
	if total, _ := Size(dir, 20, mib+1, 64*mib); total != mib+1 {
		t.Fatalf("total=%d, want the floor %d", total, mib+1)
	}
}

func TestSizeWithoutALimitUsesTheFallback(t *testing.T) {
	const mib = 1 << 20
	for name, dir := range map[string]string{
		"max":     writeCgroup(t, "max", "1000"),
		"missing": t.TempDir(),
	} {
		total, limit := Size(dir, 20, mib, 64*mib)
		if total != 64*mib || limit != 0 {
			t.Errorf("%s: total=%d limit=%d, want the fallback and no limit", name, total, limit)
		}
	}
}
