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
		{"contact then action", []signalEvent{ev(0, "HEURISTIC_BEACONING"), ev(30, "HEURISTIC_SHARDING")}, "order"},
		{"arrival then contact", []signalEvent{ev(0, "TYPOSQUATTING"), ev(5, "DGA_DOMAIN")}, "order"},
		{"arrival then action", []signalEvent{ev(0, "TYPOSQUATTING"), ev(60, "CLOUD_SECRETS")}, "order"},
		// The other way round is not a trajectory, and two signals are not
		// breadth.
		{"action then contact", []signalEvent{ev(0, "HEURISTIC_SHARDING"), ev(30, "HEURISTIC_BEACONING")}, ""},
		{"same phase twice", []signalEvent{ev(0, "HEURISTIC_BEACONING"), ev(1, "HEURISTIC_BEACONING")}, ""},
		// More than a day apart.
		{"contact then action a day later", []signalEvent{ev(0, "HEURISTIC_BEACONING"), ev(24*60+1, "HEURISTIC_SHARDING")}, ""},
		{"exactly a day", []signalEvent{ev(0, "HEURISTIC_BEACONING"), ev(24*60, "HEURISTIC_SHARDING")}, "order"},
		{"three distinct actions", []signalEvent{ev(0, "CLOUD_SECRETS"), ev(1, "DATA_EXFIL"), ev(2, "POST_EXPLOIT")}, "breadth"},
		{"action, contact, then a later action", []signalEvent{ev(0, "HEURISTIC_SHARDING"), ev(10, "DGA_DOMAIN"), ev(20, "HEURISTIC_SHARDING")}, "order"},
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

func TestCorrelateReadsTimelines(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "tl.jsonl")
	lines := []string{
		`{"ts":"2026-11-01T10:00:00Z","client":"a","id":"1","label":"attack","host":"x.test","signals":["HEURISTIC_BEACONING"],"score":6,"blocked":false}`,
		`{"ts":"2026-11-01T10:05:00Z","client":"a","id":"2","label":"attack","host":"y.test","signals":["SQL_INJECTION"],"score":10,"blocked":true}`,
		`{"ts":"2026-11-01T10:10:00Z","client":"a","id":"3","label":"attack","host":"z.test","signals":["HEURISTIC_SHARDING"],"score":6,"blocked":false}`,
		`{"ts":"2026-11-01T10:10:00Z","client":"b","id":"4","label":"benign","host":"z.test","signals":["HEURISTIC_SHARDING"],"score":6,"blocked":false}`,
		`{"id":"5","label":"benign","signals":["HEURISTIC_SHARDING"],"score":6,"blocked":false}`,
		`{"ts":"2026-11-01T11:00:00Z","client":"c","id":"6","label":"attack","host":"paypa1.com","signals":["TYPOSQUATTING"],"score":5,"blocked":false}`,
		`{"ts":"2026-11-01T12:00:00Z","client":"c","id":"7","label":"attack","host":"c2.test","observed":["CLOUD_SECRETS"],"score":0,"blocked":false}`,
	}
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	byClient, n, err := readSignalEvents([]string{p})
	if err != nil {
		t.Fatal(err)
	}
	// SQL_INJECTION has no phase; the line with no client is skipped; an
	// observed category counts as a signal.
	if n != 7 || len(byClient["a"]) != 2 || len(byClient["b"]) != 1 || len(byClient["c"]) != 2 || len(byClient) != 3 {
		t.Fatalf("read %d lines, clients %v", n, byClient)
	}
	ts := correlate(byClient)
	if len(ts) != 2 || ts[0].Client != "a" || ts[0].Rule != "order" ||
		strings.Join(ts[0].Phases, ",") != "contact,action" || strings.Join(ts[0].Hosts, ",") != "x.test,z.test" || ts[0].Attack != 2 {
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
