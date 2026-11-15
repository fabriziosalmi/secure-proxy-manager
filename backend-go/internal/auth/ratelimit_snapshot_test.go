package auth

import (
	"testing"
	"time"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/config"
)

// The snapshot lists blocked addresses first, then by address, and says when
// a blocked one may sign in again: when the attempt MaxAttempts from the
// newest leaves the window.
func TestRateLimitSnapshotSaysWhenABlockedAddressMaySignInAgain(t *testing.T) {
	s := NewService(&config.Config{MaxAttempts: 3, RateLimitWindow: 10 * time.Minute}, nil)
	now := time.Now()
	at := func(minAgo int) time.Time { return now.Add(-time.Duration(minAgo) * time.Minute) }
	s.attempts = map[string][]time.Time{
		"10.0.0.9": {at(9)},                       // one failure
		"10.0.0.2": {at(8), at(6), at(5), at(1)},  // four in the window: blocked
		"10.0.0.1": {at(30), at(4), at(3), at(2)}, // the oldest left the window: three
		"10.0.0.5": {at(20)},                      // out of the window: not listed
	}
	snap := s.RateLimitSnapshot()
	var order []string
	for _, row := range snap {
		order = append(order, row["ip"].(string))
	}
	if want := []string{"10.0.0.1", "10.0.0.2", "10.0.0.9"}; len(order) != 3 || order[0] != want[0] || order[1] != want[1] || order[2] != want[2] {
		t.Fatalf("order %v, want %v", order, want)
	}
	// 10.0.0.2: the three newest are 6, 5 and 1 minutes ago; it is blocked
	// until the one 6 minutes ago is 10 minutes old, in 4 minutes.
	if got, want := snap[1]["until"], at(6).Add(10*time.Minute).Unix(); got != want {
		t.Errorf("10.0.0.2 until %v, want %v", got, want)
	}
	if got, want := snap[0]["until"], at(4).Add(10*time.Minute).Unix(); got != want {
		t.Errorf("10.0.0.1 until %v, want %v", got, want)
	}
	if snap[1]["attempts"] != 4 || snap[1]["last_attempt"] != at(1).Unix() {
		t.Errorf("10.0.0.2: %v", snap[1])
	}
	if _, ok := snap[2]["until"]; ok || snap[2]["blocked"] != false {
		t.Errorf("10.0.0.9 is not blocked and has no until: %v", snap[2])
	}
}
