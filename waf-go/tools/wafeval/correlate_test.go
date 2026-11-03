package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func ev(min int, signal string) signalEvent {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(min) * time.Minute)
	return signalEvent{at: at, signal: signal, phase: signalPhase[signal], id: signal + "@" + at.Format("1504"), attack: true}
}

func TestCorrelateRules(t *testing.T) {
	for _, c := range []struct {
		name string
		evs  []signalEvent
		rule string // "" for no trajectory
	}{
		{"contact then action", []signalEvent{ev(0, "HEURISTIC_BEACONING"), ev(30, "CLOUD_SECRETS")}, "order"},
		// Two probabilistic signals in order are not enough: a device's
		// check-ins and a news page with its ad hosts make them too. A third
		// signal, or one that is not probabilistic, is.
		{"probabilistic contact then action", []signalEvent{ev(0, "HEURISTIC_BEACONING"), ev(30, "HEURISTIC_SHARDING")}, ""},
		{"probabilistic, then a third", []signalEvent{ev(0, "HEURISTIC_BEACONING"), ev(30, "HEURISTIC_SHARDING"), ev(40, "HEURISTIC_ENTROPY")}, "breadth"},
		{"generated name then probabilistic action", []signalEvent{ev(0, "DGA_DOMAIN"), ev(30, "HEURISTIC_SHARDING")}, "order"},
		{"arrival then contact", []signalEvent{ev(0, "TYPOSQUATTING"), ev(5, "DGA_DOMAIN")}, "order"},
		{"arrival then action", []signalEvent{ev(0, "TYPOSQUATTING"), ev(60, "CLOUD_SECRETS")}, "order"},
		// The other way round is not a trajectory, and two signals are not
		// breadth.
		{"action then contact", []signalEvent{ev(0, "HEURISTIC_SHARDING"), ev(30, "HEURISTIC_BEACONING")}, ""},
		{"same phase twice", []signalEvent{ev(0, "HEURISTIC_BEACONING"), ev(1, "HEURISTIC_BEACONING")}, ""},
		// More than a day apart.
		{"contact then action a day later", []signalEvent{ev(0, "HEURISTIC_BEACONING"), ev(24*60+1, "POST_EXPLOIT")}, ""},
		{"exactly a day", []signalEvent{ev(0, "HEURISTIC_BEACONING"), ev(24*60, "POST_EXPLOIT")}, "order"},
		{"three distinct actions", []signalEvent{ev(0, "CLOUD_SECRETS"), ev(1, "DATA_EXFIL"), ev(2, "POST_EXPLOIT")}, "breadth"},
		{"three distinct actions, never three in a day", []signalEvent{ev(0, "CLOUD_SECRETS"), ev(1000, "DATA_EXFIL"), ev(2000, "POST_EXPLOIT")}, ""},
		{"action, contact, then a later action", []signalEvent{ev(0, "HEURISTIC_SHARDING"), ev(10, "DGA_DOMAIN"), ev(20, "HEURISTIC_SHARDING")}, "order"},
		// Two signals of one instant (one request: a generated name whose
		// body holds a secret) have no order between them.
		{"one instant", []signalEvent{ev(0, "DGA_DOMAIN"), ev(0, "CLOUD_SECRETS")}, ""},
		{"one instant, then a later action", []signalEvent{ev(0, "DGA_DOMAIN"), ev(0, "CLOUD_SECRETS"), ev(1, "POST_EXPLOIT")}, "order"},
	} {
		t.Run(c.name, func(t *testing.T) {
			ts := correlate(map[string][]signalEvent{"c": c.evs})
			got := ""
			if len(ts) == 1 {
				got = ts[0].Rule
			}
			if len(ts) > 1 || got != c.rule {
				t.Errorf("trajectories = %+v; want rule %q", ts, c.rule)
			}
		})
	}
}

// A client that beacons all day and does nothing else is the common case,
// and must not cost the square of its signals: 100,000 check-ins within a
// day take well under a second.
func TestCorrelateLongQuietClient(t *testing.T) {
	evs := make([]signalEvent, 100_000)
	t0 := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	for i := range evs {
		evs[i] = signalEvent{at: t0.Add(time.Duration(i) * 500 * time.Millisecond), signal: "HEURISTIC_BEACONING", phase: contact, line: lineRef{0, i + 1}}
	}
	start := time.Now()
	ts := correlate(map[string][]signalEvent{"c": evs})
	if took := time.Since(start); len(ts) != 0 || took > 2*time.Second {
		t.Errorf("%d trajectories in %v; want none, in under 2s", len(ts), took)
	}
}

func TestCorrelateReadsTimelines(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "tl.jsonl")
	lines := []string{
		`{"ts":"2026-11-01T10:00:00Z","client":"a","id":"1","label":"attack","host":"x.test","signals":["HEURISTIC_BEACONING"],"score":6,"blocked":false}`,
		`{"ts":"2026-11-01T10:05:00Z","client":"a","id":"2","label":"attack","host":"y.test","signals":["SQL_INJECTION"],"score":10,"blocked":true}`,
		`{"ts":"2026-11-01T10:10:00Z","client":"a","id":"3","label":"attack","host":"z.test","signals":["DATA_EXFIL"],"score":6,"blocked":false}`,
		`{"ts":"2026-11-01T10:10:00Z","client":"b","id":"4","label":"benign","host":"z.test","signals":["HEURISTIC_SHARDING"],"score":6,"blocked":false}`,
		`{"id":"5","label":"benign","signals":["HEURISTIC_SHARDING"],"score":6,"blocked":false}`,
		`{"ts":"2026-11-01T11:00:00Z","client":"c","id":"6","label":"attack","host":"paypa1.com","signals":["TYPOSQUATTING"],"score":5,"blocked":false}`,
		`{"ts":"2026-11-01T12:00:00Z","client":"c","id":"7","label":"attack","host":"c2.test","observed":["CLOUD_SECRETS"],"score":0,"blocked":false}`,
	}
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A second timeline reuses id 1 for another request of client a.
	p2 := filepath.Join(dir, "tl2.jsonl")
	if err := os.WriteFile(p2, []byte(`{"ts":"2026-11-01T10:20:00Z","client":"a","id":"1","label":"attack","host":"w.test","signals":["POST_EXPLOIT"],"score":10,"blocked":true}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	byClient, n, err := readSignalEvents([]string{p, p2})
	if err != nil {
		t.Fatal(err)
	}
	// SQL_INJECTION has no phase; the line with no client is skipped; an
	// observed category counts as a signal.
	if n != 8 || len(byClient["a"]) != 3 || len(byClient["b"]) != 1 || len(byClient["c"]) != 2 || len(byClient) != 3 {
		t.Fatalf("read %d lines, clients %v", n, byClient)
	}
	ts := correlate(byClient)
	if len(ts) != 2 || ts[0].Client != "a" || ts[0].Rule != "order" ||
		strings.Join(ts[0].Phases, ",") != "contact,action" || strings.Join(ts[0].Hosts, ",") != "x.test,z.test,w.test" ||
		ts[0].Attack != 3 || len(ts[0].Events) != 3 || ts[0].Closed != "2026-11-01T10:10:00Z" {
		t.Errorf("trajectories = %+v", ts)
	}
	if len(ts) == 2 && (ts[1].Client != "c" || strings.Join(ts[1].Signals, ",") != "TYPOSQUATTING,CLOUD_SECRETS") {
		t.Errorf("observed secret: trajectory %+v, want c with TYPOSQUATTING then CLOUD_SECRETS", ts[1])
	}

	out := filepath.Join(dir, "out.json")
	if err := runCorrelate(out, []string{p}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readSignalEvents([]string{filepath.Join(dir, "missing")}); err == nil {
		t.Error("a missing timeline was not an error")
	}
	bad := filepath.Join(dir, "bad.jsonl")
	_ = os.WriteFile(bad, []byte(`{"ts":"yesterday","client":"a","id":"1","label":"x","signals":[],"score":0,"blocked":false}`+"\n"), 0o600)
	if _, _, err := readSignalEvents([]string{bad}); err == nil || !strings.Contains(err.Error(), "line 1: ts") {
		t.Errorf("bad ts: %v", err)
	}
}
