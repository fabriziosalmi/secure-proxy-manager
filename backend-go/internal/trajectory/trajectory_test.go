package trajectory

import (
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)

func ev(min int, category string) Signal {
	return Signal{At: t0.Add(time.Duration(min) * time.Minute), Category: category, Host: category + ".test"}
}

// The cases of wafeval -correlate (waf-go/tools/wafeval/correlate_test.go),
// unchanged: the live correlator answers as the measured one did.
func TestFirstRules(t *testing.T) {
	for _, c := range []struct {
		name string
		evs  []Signal
		rule string // "" for no trajectory
	}{
		{"contact then action", []Signal{ev(0, "HEURISTIC_BEACONING"), ev(30, "CLOUD_SECRETS")}, "order"},
		// Two probabilistic signals in order are not enough: a device's
		// check-ins and a news page with its ad hosts make them too. A third
		// signal, or one that is not probabilistic, is.
		{"probabilistic contact then action", []Signal{ev(0, "HEURISTIC_BEACONING"), ev(30, "HEURISTIC_SHARDING")}, ""},
		{"probabilistic, then a third", []Signal{ev(0, "HEURISTIC_BEACONING"), ev(30, "HEURISTIC_SHARDING"), ev(40, "HEURISTIC_ENTROPY")}, "breadth"},
		{"generated name then probabilistic action", []Signal{ev(0, "DGA_DOMAIN"), ev(30, "HEURISTIC_SHARDING")}, "order"},
		{"arrival then contact", []Signal{ev(0, "TYPOSQUATTING"), ev(5, "DGA_DOMAIN")}, "order"},
		{"arrival then action", []Signal{ev(0, "TYPOSQUATTING"), ev(60, "CLOUD_SECRETS")}, "order"},
		// The other way round is not a trajectory, and two signals are not
		// breadth.
		{"action then contact", []Signal{ev(0, "HEURISTIC_SHARDING"), ev(30, "HEURISTIC_BEACONING")}, ""},
		{"same phase twice", []Signal{ev(0, "HEURISTIC_BEACONING"), ev(1, "HEURISTIC_BEACONING")}, ""},
		// More than a day apart.
		{"contact then action a day later", []Signal{ev(0, "HEURISTIC_BEACONING"), ev(24*60+1, "POST_EXPLOIT")}, ""},
		{"exactly a day", []Signal{ev(0, "HEURISTIC_BEACONING"), ev(24*60, "POST_EXPLOIT")}, "order"},
		{"three distinct actions", []Signal{ev(0, "CLOUD_SECRETS"), ev(1, "DATA_EXFIL"), ev(2, "POST_EXPLOIT")}, "breadth"},
		{"three distinct actions, never three in a day", []Signal{ev(0, "CLOUD_SECRETS"), ev(1000, "DATA_EXFIL"), ev(2000, "POST_EXPLOIT")}, ""},
		{"action, contact, then a later action", []Signal{ev(0, "HEURISTIC_SHARDING"), ev(10, "DGA_DOMAIN"), ev(20, "HEURISTIC_SHARDING")}, "order"},
		// Two signals of one instant (one request: a generated name whose
		// body holds a secret) have no order between them.
		{"one instant", []Signal{ev(0, "DGA_DOMAIN"), ev(0, "CLOUD_SECRETS")}, ""},
		{"one instant, then a later action", []Signal{ev(0, "DGA_DOMAIN"), ev(0, "CLOUD_SECRETS"), ev(1, "POST_EXPLOIT")}, "order"},
	} {
		t.Run(c.name, func(t *testing.T) {
			tr, ok := First(c.evs)
			got := ""
			if ok {
				got = tr.Rule
			}
			if got != c.rule {
				t.Errorf("rule %q (%+v), want %q", got, tr, c.rule)
			}
		})
	}
}

// A trajectory starts at its window's first signal, closes when the rule
// first holds and ends at the last signal within a day of its start;
// categories without a phase are left out.
func TestFirstShape(t *testing.T) {
	sigs := []Signal{
		ev(0, "SQL_INJECTION"),
		ev(5, "TYPOSQUATTING"),
		ev(20, "HEURISTIC_BEACONING"),
		ev(60, "CLOUD_SECRETS"),
		ev(5+24*60, "POST_EXPLOIT"),
		ev(6+24*60, "POST_EXPLOIT"),
	}
	tr, ok := First(sigs)
	if !ok {
		t.Fatal("no trajectory")
	}
	if tr.Rule != "order" || !tr.Start.Equal(t0.Add(5*time.Minute)) || !tr.Closed.Equal(t0.Add(20*time.Minute)) ||
		!tr.End.Equal(t0.Add((5+24*60)*time.Minute)) || tr.Count != 4 ||
		strings.Join(tr.Phases, ",") != "arrival,contact,action" ||
		strings.Join(tr.Categories, ",") != "TYPOSQUATTING,HEURISTIC_BEACONING,CLOUD_SECRETS,POST_EXPLOIT" ||
		len(tr.Hosts) != 4 {
		t.Errorf("trajectory = %+v", tr)
	}
}

// A client that beacons all day and does nothing else costs one pass.
func TestFirstLongQuietClient(t *testing.T) {
	sigs := make([]Signal, 100_000)
	for i := range sigs {
		sigs[i] = Signal{At: t0.Add(time.Duration(i) * 500 * time.Millisecond), Category: "HEURISTIC_BEACONING"}
	}
	start := time.Now()
	_, ok := First(sigs)
	if took := time.Since(start); ok || took > 2*time.Second {
		t.Errorf("trajectory %v in %v; want none, in under 2s", ok, took)
	}
}
