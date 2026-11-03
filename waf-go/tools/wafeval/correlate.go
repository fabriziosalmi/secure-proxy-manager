package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"
)

// A trajectory: one client whose signals, over a day, read as an internal
// host that was reached, called out and acted. SPM sits on the way out, so
// the phases are those of egress:
//
//   - arrival: the client reached something meant to compromise it (a
//     typosquatted name);
//   - contact: it called out the way an implant does (a generated name,
//     regular check-ins, a TLS name other than the one it asked for);
//   - action: it did what an implant does (spread over many hosts, tunnel,
//     post-exploitation strings, secrets or data on the way out).
//
// This is the offline prototype the backend's correlator will follow: it
// reads the -timeline lines of a replay and says which clients it would
// report and why, so the rules are measured on real and synthetic timelines
// before any of them runs on a live installation.

type phase int

const (
	arrival phase = iota + 1
	contact
	action
)

func (p phase) String() string {
	return [...]string{"", "arrival", "contact", "action"}[p]
}

// signalPhase is the phase each signal belongs to. A signal not here (a
// classic web attack, a protocol anomaly, the Core Rule Set) is not part of a
// trajectory: on the way out it does not describe a compromised host.
var signalPhase = map[string]phase{
	"TYPOSQUATTING": arrival,

	"DGA_DOMAIN":          contact,
	"HEURISTIC_BEACONING": contact,
	"TLS_SNI_MISMATCH":    contact,

	"HEURISTIC_SHARDING":   action,
	"CRYPTO_TUNNEL":        action,
	"POST_EXPLOIT":         action,
	"DATA_EXFIL":           action,
	"CLOUD_SECRETS":        action,
	"DATA_LEAK_PREVENTION": action,
	"FINANCIAL_DATA":       action,
	"HEURISTIC_ENTROPY":    action,
	"HEURISTIC_GHOSTING":   action,
	"RANSOMWARE":           action,
}

// probabilistic are the signals the WAF scores below its block threshold
// because, alone, they need corroboration (the heuristics' own words):
// regular check-ins, many hosts in a minute, a high-entropy body or URL,
// another protocol in a body. Browsing makes them too (a device's periodic
// check-in, a news page and its ad hosts), so two of them do not make an
// order trajectory on their own.
var probabilistic = map[string]bool{
	"HEURISTIC_BEACONING": true,
	"HEURISTIC_SHARDING":  true,
	"HEURISTIC_ENTROPY":   true,
	"HEURISTIC_GHOSTING":  true,
}

// trajectoryWindow is how far apart two signals of one trajectory may be.
const trajectoryWindow = 24 * time.Hour

// breadthMin is how many distinct signals in one window make a trajectory on
// their own (rule "breadth").
const breadthMin = 3

// signalEvent is one signal of one timeline line.
type signalEvent struct {
	at     time.Time
	signal string
	phase  phase
	host   string
	id     string
	line   lineRef
	attack bool
}

// lineRef is the timeline line a signal came from: one record, even where
// two timelines reuse an id (each "timeline.py real" output starts at
// real/0).
type lineRef struct{ file, line int }

// Trajectory is one client's report: the rule that made it, the signals in
// the order they came, and how many of its lines were labelled attack (a
// replay knows; a live installation would not).
type Trajectory struct {
	Client string `json:"client"`
	Rule   string `json:"rule"` // "order" or "breadth"
	Start  string `json:"start"`
	End    string `json:"end"`
	// Closed is the instant the rule first held: when a live correlator
	// would have reported.
	Closed  string   `json:"closed"`
	Phases  []string `json:"phases"`
	Signals []string `json:"signals"`
	Hosts   []string `json:"hosts"`
	Events  []string `json:"events"`
	Attack  int      `json:"attack_events"`
	Benign  int      `json:"benign_events"`
}

// correlate reads the signal events of each client in time order and
// reports each client once, at the first instant a rule holds (see
// firstTrajectory).
func correlate(byClient map[string][]signalEvent) []Trajectory {
	clients := make([]string, 0, len(byClient))
	for c := range byClient {
		clients = append(clients, c)
	}
	sort.Strings(clients)
	var out []Trajectory
	for _, c := range clients {
		evs := byClient[c]
		sort.SliceStable(evs, func(i, j int) bool { return evs[i].at.Before(evs[j].at) })
		if t, ok := firstTrajectory(c, evs); ok {
			out = append(out, t)
		}
	}
	return out
}

// firstTrajectory walks evs (in time order) as a live correlator would, one
// instant at a time, keeping the signals of the last trajectoryWindow, and
// stops at the first instant a rule holds:
//
//   - order: a signal of this instant is of a later phase than one of an
//     earlier instant in the window (arrival then contact, contact then
//     action, arrival then action), and a signal of the window is not
//     probabilistic;
//   - breadth: breadthMin distinct signals in the window, whatever their
//     phases.
//
// Signals of one instant (one request, or requests at the same time) have
// no order among them. The counts move with the window, so a client that
// only beacons all day costs one pass. The trajectory runs from the
// window's first signal to the last within trajectoryWindow of it.
func firstTrajectory(client string, evs []signalEvent) (Trajectory, bool) {
	var phases [action + 1]int
	signals := map[string]int{}
	firm := 0 // signals in the window that are not probabilistic
	add := func(e signalEvent, n int) {
		phases[e.phase] += n
		signals[e.signal] += n
		if signals[e.signal] == 0 {
			delete(signals, e.signal)
		}
		if !probabilistic[e.signal] {
			firm += n
		}
	}
	lo := 0
	for k := 0; k < len(evs); {
		at := evs[k].at
		for lo < k && at.Sub(evs[lo].at) > trajectoryWindow {
			add(evs[lo], -1)
			lo++
		}
		earliest := phase(0)
		for p := arrival; p <= action; p++ {
			if phases[p] > 0 {
				earliest = p
				break
			}
		}
		next, later := k, false
		for ; next < len(evs) && evs[next].at.Equal(at); next++ {
			later = later || earliest != 0 && evs[next].phase > earliest
			add(evs[next], 1)
		}
		rule := ""
		if later && firm > 0 {
			rule = "order"
		} else if len(signals) >= breadthMin {
			rule = "breadth"
		}
		if rule != "" {
			last := next
			for last < len(evs) && evs[last].at.Sub(evs[lo].at) <= trajectoryWindow {
				last++
			}
			t := trajectoryOf(client, rule, evs[lo:last])
			t.Closed = at.UTC().Format(time.RFC3339)
			return t, true
		}
		k = next
	}
	return Trajectory{}, false
}

func trajectoryOf(client, rule string, win []signalEvent) Trajectory {
	t := Trajectory{Client: client, Rule: rule, Start: win[0].at.UTC().Format(time.RFC3339), End: win[len(win)-1].at.UTC().Format(time.RFC3339)}
	seenPhase, seenSignal, seenHost, seenLine := map[phase]bool{}, map[string]bool{}, map[string]bool{}, map[lineRef]bool{}
	for _, e := range win {
		if !seenPhase[e.phase] {
			seenPhase[e.phase] = true
			t.Phases = append(t.Phases, e.phase.String())
		}
		if !seenSignal[e.signal] {
			seenSignal[e.signal] = true
			t.Signals = append(t.Signals, e.signal)
		}
		if e.host != "" && !seenHost[e.host] {
			seenHost[e.host] = true
			t.Hosts = append(t.Hosts, e.host)
		}
		if !seenLine[e.line] {
			seenLine[e.line] = true
			t.Events = append(t.Events, e.id)
			if e.attack {
				t.Attack++
			} else {
				t.Benign++
			}
		}
	}
	return t
}

// readSignalEvents reads -timeline lines and keeps, per client, the signals
// that belong to a phase, scored or observed: a category in Log only still
// says what the client did. A line without a time or a client is skipped.
func readSignalEvents(paths []string) (map[string][]signalEvent, int, error) {
	byClient := map[string][]signalEvent{}
	lines := 0
	for fi, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			return nil, lines, err
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<24)
		n := 0
		for sc.Scan() {
			n++
			var e TimelineEntry
			if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
				f.Close()
				return nil, lines, fmt.Errorf("%s line %d: %w", p, n, err)
			}
			lines++
			if e.Client == "" || e.TS == "" {
				continue
			}
			at, err := time.Parse(time.RFC3339Nano, e.TS)
			if err != nil {
				f.Close()
				return nil, lines, fmt.Errorf("%s line %d: ts: %w", p, n, err)
			}
			for _, s := range append(e.Signals, e.Observed...) {
				if ph, ok := signalPhase[s]; ok {
					byClient[e.Client] = append(byClient[e.Client], signalEvent{at: at, signal: s, phase: ph, host: e.Host, id: e.ID, line: lineRef{fi, n}, attack: e.Label == "attack"})
				}
			}
		}
		err = sc.Err()
		f.Close()
		if err != nil {
			return nil, lines, fmt.Errorf("%s: %w", p, err)
		}
	}
	return byClient, lines, nil
}

// runCorrelate is wafeval -correlate: the trajectories of the timelines in
// paths, written as JSON to out, with a summary on stdout.
func runCorrelate(out string, paths []string) error {
	byClient, lines, err := readSignalEvents(paths)
	if err != nil {
		return err
	}
	ts := correlate(byClient)
	f, err := os.OpenFile(out, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(map[string]any{"lines": lines, "clients_with_signals": len(byClient), "trajectories": ts}); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	byRule := map[string]int{}
	attack := 0
	for _, t := range ts {
		byRule[t.Rule]++
		if t.Attack > 0 {
			attack++
		}
	}
	fmt.Printf("wafeval: %d lines, %d clients with signals, %d trajectories (order %d, breadth %d), %d with an attack event; report in %s\n",
		lines, len(byClient), len(ts), byRule["order"], byRule["breadth"], attack, out)
	return nil
}
