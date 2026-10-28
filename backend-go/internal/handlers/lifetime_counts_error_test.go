package handlers

import (
	"testing"
	"time"
)

// A failed all-time count query must not become the dashboard's answer for the
// next 25 seconds. lifetimeBase used to discard the error and cache whatever
// the variables held, zeros, as a fresh result.
func TestLifetimeCountsKeepThePreviousAnswerWhenTheQueryFails(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	for i := 0; i < 3; i++ {
		insertLogRow(t, db, time.Now(), lanClient, "GET", "http://a.test/", 0, "none")
	}
	h := NewAnalyticsHandlers(db, cfg)

	_, total, _, _ := h.lifetimeBase()
	if total != 3 {
		t.Fatalf("setup: total %d, want 3", total)
	}

	// The cache has expired and the query fails (here: the table is gone).
	h.countsMu.Lock()
	h.countsFetched = time.Time{}
	h.countsMu.Unlock()
	if _, err := db.Exec("ALTER TABLE proxy_logs RENAME TO proxy_logs_away"); err != nil {
		t.Fatal(err)
	}
	if _, total, _, _ = h.lifetimeBase(); total != 3 {
		t.Errorf("after a failed query the total is %d, want the previous 3", total)
	}
	h.countsMu.Lock()
	cached := !h.countsFetched.IsZero()
	h.countsMu.Unlock()
	if cached {
		t.Error("the failed query's result was cached; the next request would not retry")
	}

	// Once the query works again the next call recomputes.
	if _, err := db.Exec("ALTER TABLE proxy_logs_away RENAME TO proxy_logs"); err != nil {
		t.Fatal(err)
	}
	insertLogRow(t, db, time.Now(), lanClient, "GET", "http://b.test/", 0, "none")
	if _, total, _, _ = h.lifetimeBase(); total != 4 {
		t.Errorf("after the query recovers the total is %d, want 4", total)
	}
}
