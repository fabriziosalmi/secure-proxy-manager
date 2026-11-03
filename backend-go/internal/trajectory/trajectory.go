// Package trajectory reads one client's WAF signals as a trajectory: a host
// that was reached, called out and acted, within a day. The rules are the
// ones measured offline by wafeval -correlate (waf-go/tools/wafeval/
// correlate.go) on replayed timelines; this is the same walk, on the signals
// the WAF reports live.
package trajectory

import (
	"sort"
	"time"
)

// Phase is a stage of what a compromised host does on the way out.
type Phase int

const (
	Arrival Phase = iota + 1 // it reached something meant to compromise it
	Contact                  // it called out the way an implant does
	Action                   // it did what an implant does
)

func (p Phase) String() string {
	return [...]string{"", "arrival", "contact", "action"}[p]
}

// PhaseOf is the phase of each signal category. A category not here is not
// part of a trajectory.
var PhaseOf = map[string]Phase{
	"TYPOSQUATTING": Arrival,

	"DGA_DOMAIN":          Contact,
	"HEURISTIC_BEACONING": Contact,
	"TLS_SNI_MISMATCH":    Contact,

	"HEURISTIC_SHARDING":   Action,
	"CRYPTO_TUNNEL":        Action,
	"POST_EXPLOIT":         Action,
	"DATA_EXFIL":           Action,
	"CLOUD_SECRETS":        Action,
	"DATA_LEAK_PREVENTION": Action,
	"FINANCIAL_DATA":       Action,
	"HEURISTIC_ENTROPY":    Action,
	"HEURISTIC_GHOSTING":   Action,
	"RANSOMWARE":           Action,
}

// Probabilistic are the signals the WAF scores below its block threshold
// because, alone, they need corroboration: regular check-ins, many hosts in
// a minute, a high-entropy body or URL, another protocol in a body. Browsing
// makes them too (a device's periodic check-in, a news page and its ad
// hosts), so two of them do not make an order trajectory on their own.
var Probabilistic = map[string]bool{
	"HEURISTIC_BEACONING": true,
	"HEURISTIC_SHARDING":  true,
	"HEURISTIC_ENTROPY":   true,
	"HEURISTIC_GHOSTING":  true,
}

// Window is how far apart two signals of one trajectory may be.
const Window = 24 * time.Hour

// BreadthMin is how many distinct signals in one window make a trajectory
// on their own (rule "breadth").
const BreadthMin = 3

// Signal is one signal of one client: a category at an instant.
type Signal struct {
	At       time.Time
	Category string
	Host     string
}

// Trajectory is what First found: the rule, the instant it held (Closed),
// and the signals of the window from Start to End.
type Trajectory struct {
	Rule   string // "order" or "breadth"
	Start  time.Time
	Closed time.Time
	End    time.Time
	Summary
}

// Summary is what a window of signals holds, each named once in the order
// it came.
type Summary struct {
	Phases     []string
	Categories []string
	Hosts      []string
	Count      int
}

// Sort puts sigs in time order, keeping the order of signals of one instant.
func Sort(sigs []Signal) {
	sort.SliceStable(sigs, func(i, j int) bool { return sigs[i].At.Before(sigs[j].At) })
}

// First walks sigs (in time order; categories without a phase are skipped)
// as a live correlator does, one instant at a time, keeping the signals of
// the last Window, and stops at the first instant a rule holds:
//
//   - order: a signal of this instant is of a later phase than one of an
//     earlier instant in the window, and a signal of the window is not
//     probabilistic;
//   - breadth: BreadthMin distinct signals in the window, whatever their
//     phases.
//
// Signals of one instant have no order among them. The counts move with the
// window, so a client that only beacons all day costs one pass. The
// trajectory runs from the window's first signal to the last within Window
// of it.
func First(sigs []Signal) (Trajectory, bool) {
	evs := make([]Signal, 0, len(sigs))
	for _, s := range sigs {
		if PhaseOf[s.Category] != 0 {
			evs = append(evs, s)
		}
	}
	var phases [Action + 1]int
	cats := map[string]int{}
	firm := 0 // signals in the window that are not probabilistic
	add := func(s Signal, n int) {
		phases[PhaseOf[s.Category]] += n
		cats[s.Category] += n
		if cats[s.Category] == 0 {
			delete(cats, s.Category)
		}
		if !Probabilistic[s.Category] {
			firm += n
		}
	}
	lo := 0
	for k := 0; k < len(evs); {
		at := evs[k].At
		for lo < k && at.Sub(evs[lo].At) > Window {
			add(evs[lo], -1)
			lo++
		}
		earliest := Phase(0)
		for p := Arrival; p <= Action; p++ {
			if phases[p] > 0 {
				earliest = p
				break
			}
		}
		next, later := k, false
		for ; next < len(evs) && evs[next].At.Equal(at); next++ {
			later = later || earliest != 0 && PhaseOf[evs[next].Category] > earliest
			add(evs[next], 1)
		}
		rule := ""
		if later && firm > 0 {
			rule = "order"
		} else if len(cats) >= BreadthMin {
			rule = "breadth"
		}
		if rule != "" {
			last := next
			for last < len(evs) && evs[last].At.Sub(evs[lo].At) <= Window {
				last++
			}
			win := evs[lo:last]
			return Trajectory{Rule: rule, Start: win[0].At, Closed: at, End: win[len(win)-1].At, Summary: Summarize(win)}, true
		}
		k = next
	}
	return Trajectory{}, false
}

// Summarize names the phases, categories and hosts of sigs once each, in the
// order they came, and counts the signals that have a phase.
func Summarize(sigs []Signal) Summary {
	var s Summary
	seenPhase, seenCat, seenHost := map[Phase]bool{}, map[string]bool{}, map[string]bool{}
	for _, e := range sigs {
		p := PhaseOf[e.Category]
		if p == 0 {
			continue
		}
		s.Count++
		if !seenPhase[p] {
			seenPhase[p] = true
			s.Phases = append(s.Phases, p.String())
		}
		if !seenCat[e.Category] {
			seenCat[e.Category] = true
			s.Categories = append(s.Categories, e.Category)
		}
		if e.Host != "" && !seenHost[e.Host] {
			seenHost[e.Host] = true
			s.Hosts = append(s.Hosts, e.Host)
		}
	}
	return s
}
