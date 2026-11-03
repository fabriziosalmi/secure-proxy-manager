package trajectory

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"testing"
	"time"
)

// TestReplayTimeline runs First on a wafeval -timeline file, one client at a
// time, and writes client, rule, start and closed per trajectory to
// TRAJECTORY_OUT: the check that this package answers as wafeval -correlate
// did on the same replay. It needs TRAJECTORY_TIMELINE; without it, it is
// skipped.
func TestReplayTimeline(t *testing.T) {
	in, out := os.Getenv("TRAJECTORY_TIMELINE"), os.Getenv("TRAJECTORY_OUT")
	if in == "" || out == "" {
		t.Skip("TRAJECTORY_TIMELINE and TRAJECTORY_OUT not set")
	}
	f, err := os.Open(in)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	byClient := map[string][]Signal{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		var e struct {
			TS, Client, Host  string
			Signals, Observed []string
		}
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatal(err)
		}
		if e.Client == "" || e.TS == "" {
			continue
		}
		at, err := time.Parse(time.RFC3339Nano, e.TS)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range append(e.Signals, e.Observed...) {
			byClient[e.Client] = append(byClient[e.Client], Signal{At: at, Category: c, Host: e.Host})
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	clients := make([]string, 0, len(byClient))
	for c := range byClient {
		clients = append(clients, c)
	}
	sort.Strings(clients)
	w, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	n := 0
	for _, c := range clients {
		sigs := byClient[c]
		Sort(sigs)
		if tr, ok := First(sigs); ok {
			n++
			fmt.Fprintf(w, "%s %s %s %s\n", c, tr.Rule, tr.Start.UTC().Format(time.RFC3339), tr.Closed.UTC().Format(time.RFC3339))
		}
	}
	t.Logf("%d clients, %d trajectories", len(clients), n)
}
