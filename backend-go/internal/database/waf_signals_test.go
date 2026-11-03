package database

import (
	"testing"
	"time"
)

// Signals are stored one row each and cleared with the WAF's block events,
// as the access log's Clear and the counters' reset do.
func TestStoreAndClearWAFSignals(t *testing.T) {
	db := openInit(t)
	at := time.Date(2026, 11, 3, 10, 0, 0, 123_000_000, time.UTC)
	if err := StoreWAFSignals(db, []WAFSignal{
		{At: at, ClientIP: "192.0.2.7", Host: "paypa1.com", Category: "TYPOSQUATTING", Rule: "ML-TYPO-001", EventID: "e"},
		{At: at, ClientIP: "192.0.2.7", Category: "CLOUD_SECRETS", Observed: true, Blocked: true, EventID: "e"},
	}); err != nil {
		t.Fatal(err)
	}
	var n, observed, blocked int
	var tsMS int64
	if err := db.QueryRow("SELECT COUNT(*), SUM(observed), SUM(blocked), MIN(ts_ms) FROM waf_signals").Scan(&n, &observed, &blocked, &tsMS); err != nil {
		t.Fatal(err)
	}
	if n != 2 || observed != 1 || blocked != 1 || tsMS != at.UnixMilli() {
		t.Errorf("rows %d observed %d blocked %d ts_ms %d, want 2 1 1 %d", n, observed, blocked, tsMS, at.UnixMilli())
	}
	if _, err := db.Exec("INSERT INTO waf_events (event_id) VALUES ('e')"); err != nil {
		t.Fatal(err)
	}
	ClearWAFRecords(db)
	var events, signals int
	_ = db.QueryRow("SELECT COUNT(*) FROM waf_events").Scan(&events)
	_ = db.QueryRow("SELECT COUNT(*) FROM waf_signals").Scan(&signals)
	if events != 0 || signals != 0 {
		t.Errorf("after ClearWAFRecords: %d events, %d signals", events, signals)
	}
}
