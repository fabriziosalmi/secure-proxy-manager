package workers

import (
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
)

// addSignals stores one request's signals; each call is its own event, as
// each inspected request is.
func addSignals(t *testing.T, db *sql.DB, client string, at time.Time, cats ...string) {
	t.Helper()
	eventSeq++
	sigs := make([]database.WAFSignal, len(cats))
	for i, c := range cats {
		sigs[i] = database.WAFSignal{At: at, ClientIP: client, Host: strings.ToLower(c) + ".test", Category: c,
			EventID: fmt.Sprintf("e-%d", eventSeq)}
	}
	if err := database.StoreWAFSignals(db, sigs); err != nil {
		t.Fatal(err)
	}
}

var eventSeq int

func trajectoryRows(t *testing.T, db *sql.DB) []database.WAFTrajectory {
	t.Helper()
	ts, err := database.ListWAFTrajectories(db, time.Time{}, 100)
	if err != nil {
		t.Fatal(err)
	}
	return ts
}

func sweep(t *testing.T, db *sql.DB, now time.Time) []database.WAFTrajectory {
	t.Helper()
	found, err := SweepTrajectories(db, now)
	if err != nil {
		t.Fatal(err)
	}
	return found
}

// A trajectory is stored once, at its first sweep; while its day is open,
// later signals update it; after the day a new episode is a second row.
func TestSweepTrajectories(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	t0 := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	const c = "192.0.2.7"

	addSignals(t, db, c, t0, "TYPOSQUATTING")
	if found := sweep(t, db, t0.Add(time.Minute)); len(found) != 0 {
		t.Fatalf("one signal made %+v", found)
	}
	addSignals(t, db, c, t0.Add(15*time.Minute), "HEURISTIC_BEACONING")
	found := sweep(t, db, t0.Add(16*time.Minute))
	if len(found) != 1 || found[0].Rule != "order" || !found[0].Start.Equal(t0) ||
		!found[0].Closed.Equal(t0.Add(15*time.Minute)) || found[0].Signals != 2 {
		t.Fatalf("found %+v, want one order trajectory from t0 closed at +15m", found)
	}
	if again := sweep(t, db, t0.Add(17*time.Minute)); len(again) != 0 || len(trajectoryRows(t, db)) != 1 {
		t.Fatalf("a second sweep found %+v; rows %d", again, len(trajectoryRows(t, db)))
	}

	// A secret an hour later is the same episode: the row grows.
	addSignals(t, db, c, t0.Add(75*time.Minute), "CLOUD_SECRETS")
	if again := sweep(t, db, t0.Add(76*time.Minute)); len(again) != 0 {
		t.Fatalf("a signal within the day made a new trajectory %+v", again)
	}
	rows := trajectoryRows(t, db)
	if len(rows) != 1 || rows[0].Signals != 3 || !rows[0].End.Equal(t0.Add(75*time.Minute)) ||
		strings.Join(rows[0].Categories, ",") != "TYPOSQUATTING,HEURISTIC_BEACONING,CLOUD_SECRETS" ||
		strings.Join(rows[0].Phases, ",") != "arrival,contact,action" {
		t.Fatalf("after the secret: %+v", rows)
	}

	// Two days later a beacon alone is nothing; with a generated name
	// before it, a second episode.
	t2 := t0.Add(50 * time.Hour)
	addSignals(t, db, c, t2, "HEURISTIC_BEACONING")
	if found := sweep(t, db, t2.Add(time.Minute)); len(found) != 0 {
		t.Fatalf("a lone beacon made %+v", found)
	}
	addSignals(t, db, c, t2.Add(10*time.Minute), "POST_EXPLOIT")
	found = sweep(t, db, t2.Add(11*time.Minute))
	if len(found) != 1 || !found[0].Start.Equal(t2) || len(trajectoryRows(t, db)) != 2 {
		t.Fatalf("second episode: found %+v, rows %d", found, len(trajectoryRows(t, db)))
	}
}

// Two signals that need corroboration, in order, are not a trajectory; nor
// are another client's.
func TestSweepTrajectoriesNeedsCorroboration(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	t0 := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	addSignals(t, db, "192.0.2.8", t0, "HEURISTIC_BEACONING")
	addSignals(t, db, "192.0.2.8", t0.Add(30*time.Minute), "HEURISTIC_SHARDING")
	addSignals(t, db, "192.0.2.9", t0.Add(40*time.Minute), "CLOUD_SECRETS")
	if found := sweep(t, db, t0.Add(time.Hour)); len(found) != 0 {
		t.Errorf("found %+v", found)
	}
}

// Signals older than a day are not read for a client with no recent one.
func TestSweepTrajectoriesSkipsQuietClients(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	t0 := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	addSignals(t, db, "192.0.2.10", t0, "TYPOSQUATTING")
	addSignals(t, db, "192.0.2.10", t0.Add(time.Minute), "DGA_DOMAIN")
	if found := sweep(t, db, t0.Add(25*time.Hour)); len(found) != 0 {
		t.Errorf("a client quiet for a day was read: %+v", found)
	}
}

// One trajectory per client and day, even when a sweep reads a whole
// episode at once: signals within the first trajectory's day that would
// make an order of their own do not make a second one.
func TestSweepTrajectoriesOneRowPerDay(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	now := time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)
	const c = "192.0.2.11"
	addSignals(t, db, c, now.Add(-40*time.Hour), "TYPOSQUATTING")
	addSignals(t, db, c, now.Add(-39*time.Hour), "DGA_DOMAIN")
	addSignals(t, db, c, now.Add(-38*time.Hour), "DGA_DOMAIN")
	addSignals(t, db, c, now.Add(-37*time.Hour), "CLOUD_SECRETS")
	addSignals(t, db, c, now.Add(-1*time.Hour), "HEURISTIC_BEACONING")
	found := sweep(t, db, now)
	if len(found) != 1 || !found[0].Start.Equal(now.Add(-40*time.Hour)) || found[0].Signals != 4 {
		t.Errorf("found %+v, want one trajectory from -40h holding 4 signals", found)
	}
}

// A client stored masked (from before GDPR mode dropped signals) is a
// network: its signals, which may be several clients', make no trajectory.
func TestSweepTrajectoriesSkipsMaskedClients(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	t0 := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	addSignals(t, db, "192.0.2.x", t0, "TYPOSQUATTING")
	addSignals(t, db, "192.0.2.x", t0.Add(time.Minute), "CLOUD_SECRETS")
	if found := sweep(t, db, t0.Add(2*time.Minute)); len(found) != 0 {
		t.Errorf("a masked network made %+v", found)
	}
}

// A clear waits for a sweep in progress, so a sweep that read signals
// before the clear cannot store a trajectory after it.
func TestClearWaitsForTheSweep(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	unlock := database.LockWAFRecords() // a sweep in progress
	done := make(chan struct{})
	go func() { database.ClearWAFRecords(db); close(done) }()
	select {
	case <-done:
		t.Fatal("the clear ran while a sweep held the WAF records")
	case <-time.After(100 * time.Millisecond):
	}
	unlock()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the clear did not run after the sweep")
	}
}

// The sweep takes the same lock: while a clear holds it, a sweep waits.
func TestSweepWaitsForAClear(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	unlock := database.LockWAFRecords() // a clear in progress
	done := make(chan struct{})
	go func() { _, _ = SweepTrajectories(db, time.Now()); close(done) }()
	select {
	case <-done:
		t.Fatal("the sweep ran while a clear held the WAF records")
	case <-time.After(100 * time.Millisecond):
	}
	unlock()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the sweep did not run after the clear")
	}
}
