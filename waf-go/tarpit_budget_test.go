package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-icap/icap"

	"secure-proxy-waf/internal/engine"
)

// withTarPit sets the tar-pit delay for one test and records `blocks` recent
// blocks for clientIP, so its next block is tar-pitted.
func withTarPit(t *testing.T, delay time.Duration, clientIP string, blocks int) {
	t.Helper()
	prevDelay := tarPitDelay
	tarPitDelay = delay
	trackerMutex.Lock()
	prevBlocks, had := ipBlockTracker[clientIP]
	seeded := make([]time.Time, blocks)
	for i := range seeded {
		seeded[i] = time.Now()
	}
	ipBlockTracker[clientIP] = seeded
	trackerMutex.Unlock()
	t.Cleanup(func() {
		tarPitDelay = prevDelay
		trackerMutex.Lock()
		if had {
			ipBlockTracker[clientIP] = prevBlocks
		} else {
			delete(ipBlockTracker, clientIP)
		}
		trackerMutex.Unlock()
	})
}

// A block gives its reservation back early and the handler's defer gives it
// back again: the second call must not take another inspection's bytes.
func TestReserveWeightReleasesOnce(t *testing.T) {
	const n = 1000
	b := withBudget(t, 2*n, 0, 20*time.Millisecond)
	first, ok1 := reserveWeight(n)
	second, ok2 := reserveWeight(n)
	if !ok1 || !ok2 {
		t.Fatal("two reservations that fit the budget were refused")
	}
	first()
	first()
	if used := b.Used(); used != n {
		t.Errorf("budget used %d after one reservation was released twice, want %d (the other one)", used, n)
	}
	second()
	if used := b.Used(); used != 0 {
		t.Errorf("budget used %d after both were released, want 0", used)
	}
}

// A tar-pitted block delays the offender's own answer, and only that: the
// inspection budget its body reserved is given back before the sleep, so
// another client's body is inspected at once instead of waiting for the
// sleep to end (and, with enough sleeping blocks, being refused with a 503).
func TestTarPittedBlockGivesBackTheBudgetBeforeItSleeps(t *testing.T) {
	const (
		offender = "198.51.100.77"
		delay    = 300 * time.Millisecond
	)
	withEngine(t, engine.Config{BlockThreshold: 10})
	withCRS(t, nil)
	withTarPit(t, delay, offender, 3)

	body := "q=1' UNION SELECT password FROM users--&pad=" + strings.Repeat("a", 32<<10)
	weight := inspectFixedWeight + int64(len(body))
	// The budget fits one such body: while the offender holds it, nothing else
	// of that size gets in.
	b := withBudget(t, weight, 0, 50*time.Millisecond)

	r := httptest.NewRequest("POST", "http://upstream.example/login", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	hdr := squidHeader()
	hdr.Set("X-Client-Ip", offender)
	req := &icap.Request{Method: "REQMOD", Request: r, Header: hdr}
	w := &mockResponseWriter{}

	type result struct{ took time.Duration }
	done := make(chan result, 1)
	start := time.Now()
	go func() {
		handleReqmod(w, req)
		done <- result{time.Since(start)}
	}()

	// The inspection of a 32 KiB body takes milliseconds; a third of the
	// delay in, the offender is asleep in the tar-pit.
	time.Sleep(delay / 3)
	select {
	case <-done:
		t.Fatalf("the blocked request was answered before the tar-pit delay of %v", delay)
	default:
	}
	if used := b.Used(); used != 0 {
		t.Errorf("budget used %d while the offender sleeps in the tar-pit, want 0 (its body weighs %d)", used, weight)
	}
	reserveStart := time.Now()
	release, ok := reserveWeight(weight)
	waited := time.Since(reserveStart)
	if !ok {
		t.Errorf("a second client's body was refused the budget (waited %v) while the offender sleeps", waited)
	} else {
		release()
		if waited > 20*time.Millisecond {
			t.Errorf("a second client's body waited %v for the budget, want at once", waited)
		}
	}

	res := <-done
	if res.took < delay {
		t.Errorf("the offender was answered after %v, want at least the tar-pit delay %v", res.took, delay)
	}
	if w.code != 200 || httpStatus(w) != http.StatusForbidden {
		t.Fatalf("ICAP %d carrying HTTP %d, want 200 carrying 403", w.code, httpStatus(w))
	}
	if b.Used() != 0 {
		t.Errorf("budget used %d after the block was answered, want 0", b.Used())
	}
	if r.Body != http.NoBody {
		t.Errorf("the blocked request still holds its body (%T) after the block", r.Body)
	}
}
