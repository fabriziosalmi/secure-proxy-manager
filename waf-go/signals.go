package main

import (
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"secure-proxy-waf/internal/engine"
)

// Signals: what a client does on the way out, sent to the backend so it can
// read a day of one client's signals as a trajectory (reached, called out,
// acted). Most of them score below the block threshold, so a block alert
// never carries them, and the traffic log, which has them, is not the
// backend's to read.
//
// They go to their own endpoint and queue: the backend sends every alert it
// receives to the notification channels, and a signal is not an alert, and a
// burst of signals must never push a block alert out of its queue.

// signalCategories are the categories that describe the client rather than
// the request: a typosquatted name it reached, a generated name, regular
// check-ins or a TLS name other than the one it asked for, and what an
// implant does (many hosts, tunnels, post-exploitation strings, secrets or
// data on the way out). Classic web attacks and CRS describe a request.
var signalCategories = map[string]bool{
	"TYPOSQUATTING":        true,
	"DGA_DOMAIN":           true,
	"HEURISTIC_BEACONING":  true,
	"TLS_SNI_MISMATCH":     true,
	"HEURISTIC_SHARDING":   true,
	"CRYPTO_TUNNEL":        true,
	"POST_EXPLOIT":         true,
	"DATA_EXFIL":           true,
	"CLOUD_SECRETS":        true,
	"DATA_LEAK_PREVENTION": true,
	"FINANCIAL_DATA":       true,
	"HEURISTIC_ENTROPY":    true,
	"HEURISTIC_GHOSTING":   true,
	"RANSOMWARE":           true,
}

// signalCoalesce: a client's category is sent once in this long. Its first
// time is what a trajectory needs; a beacon recognised on every check-in
// would otherwise be a row a minute all day.
const signalCoalesce = 10 * time.Minute

// signalSeenMax bounds the (client, category) pairs remembered. When it is
// full of pairs seen within signalCoalesce, a new pair is dropped and
// counted rather than the table grown.
const signalSeenMax = 50_000

var (
	signalChan  = make(chan map[string]interface{}, 256)
	signalTable = newSignalSeen(signalSeenMax)

	// signalCounts counts each signal by what became of it.
	signalCounts = map[string]*atomic.Int64{
		"queued":     new(atomic.Int64), // handed to the delivery queue
		"coalesced":  new(atomic.Int64), // the client's category was sent within signalCoalesce
		"no_client":  new(atomic.Int64), // no client address to correlate on
		"queue_full": new(atomic.Int64), // the delivery queue was full
		"table_full": new(atomic.Int64), // signalSeenMax pairs, all recent
	}
	// signalFailed counts deliveries that did not reach the backend, by the
	// reasons notifyFailed uses.
	signalFailed = map[string]*atomic.Int64{
		"network":       new(atomic.Int64),
		"rejected":      new(atomic.Int64),
		"server_error":  new(atomic.Int64),
		"no_credential": new(atomic.Int64),
		"rate_limited":  new(atomic.Int64),
	}
)

type signalSeen struct {
	mu        sync.Mutex
	at        map[string]time.Time
	max       int
	lastSweep time.Time
}

func newSignalSeen(max int) *signalSeen {
	return &signalSeen{at: map[string]time.Time{}, max: max}
}

// admit records category for client at now and says whether to send it:
// not if it was sent within signalCoalesce (coalesced), nor if the table is
// full of recent pairs (full). A full table is swept of old pairs at most
// once a minute, so a flood of new clients costs one sweep, not one each.
func (s *signalSeen) admit(client, category string, now time.Time) (send, full bool) {
	key := client + "\x00" + category
	s.mu.Lock()
	defer s.mu.Unlock()
	last, seen := s.at[key]
	if seen && now.Sub(last) < signalCoalesce {
		return false, false
	}
	if !seen && len(s.at) >= s.max {
		if now.Sub(s.lastSweep) >= time.Minute {
			s.lastSweep = now
			for k, t := range s.at {
				if now.Sub(t) >= signalCoalesce {
					delete(s.at, k)
				}
			}
		}
		if len(s.at) >= s.max {
			return false, true
		}
	}
	s.at[key] = now
	return true, false
}

// forget undoes admit for a signal that was not sent after all, unless a
// later admit has replaced it.
func (s *signalSeen) forget(client, category string, at time.Time) {
	key := client + "\x00" + category
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.at[key]; ok && t.Equal(at) {
		delete(s.at, key)
	}
}

// signalItem is one category of one request: the first rule that matched
// it, and whether it only matched in Log only (scored 0).
type signalItem struct {
	Category string `json:"category"`
	Rule     string `json:"rule"`
	Observed bool   `json:"observed"`
}

// signalsOf names, once each, the signal categories among matches.
func signalsOf(matches []engine.MatchResult) []signalItem {
	var out []signalItem
	at := map[string]int{}
	for _, m := range matches {
		if !signalCategories[m.Category] {
			continue
		}
		i, ok := at[m.Category]
		if !ok {
			at[m.Category] = len(out)
			out = append(out, signalItem{Category: m.Category, Rule: m.RuleID, Observed: m.Score == 0})
			continue
		}
		if m.Score > 0 {
			out[i].Observed = false
		}
	}
	return out
}

// queueSignals hands the backend the signals of one inspected request, each
// the first of its category for this client within signalCoalesce. It never
// waits.
func queueSignals(in *inspection, host string, now time.Time) {
	items := signalsOf(in.Matches)
	if len(items) == 0 {
		return
	}
	if in.ClientIP == "" || in.ClientIP == "unknown" {
		signalCounts["no_client"].Add(int64(len(items)))
		return
	}
	var send []signalItem
	for _, it := range items {
		ok, full := signalTable.admit(in.ClientIP, it.Category, now)
		switch {
		case full:
			signalCounts["table_full"].Add(1)
		case !ok:
			signalCounts["coalesced"].Add(1)
		default:
			send = append(send, it)
		}
	}
	if len(send) == 0 {
		return
	}
	data := map[string]interface{}{
		"event_id":  in.eventID,
		"ts":        now.UTC().Format(time.RFC3339Nano),
		"client_ip": in.ClientIP,
		"host":      hostForSignal(host),
		"blocked":   in.Blocked(),
		"signals":   send,
	}
	select {
	case signalChan <- data:
		signalCounts["queued"].Add(int64(len(send)))
	default:
		signalCounts["queue_full"].Add(int64(len(send)))
		// Not sent: the next request of this client and category may be.
		for _, it := range send {
			signalTable.forget(in.ClientIP, it.Category, now)
		}
	}
}

// hostForSignal is host, or nothing when it is longer than a name can be
// (253 bytes): the backend refuses a longer one, and a cut name names no
// host.
func hostForSignal(host string) string {
	if len(host) > 253 {
		return ""
	}
	return host
}

// signalWorker delivers queued signals until stop is closed (nil: forever).
func signalWorker(stop <-chan struct{}) {
	for {
		select {
		case <-stop:
			return
		case data := <-signalChan:
			deliverBackend("/api/internal/signals", data, signalFailed)
		}
	}
}

func writeSignalMetrics(w http.ResponseWriter) {
	fmt.Fprintf(w, "# HELP waf_signals_total Client signals (trajectory categories) by what became of them.\n# TYPE waf_signals_total counter\n")
	for _, r := range []string{"queued", "coalesced", "no_client", "queue_full", "table_full"} {
		fmt.Fprintf(w, "waf_signals_total{result=%q} %d\n", r, signalCounts[r].Load())
	}
	fmt.Fprintf(w, "# HELP waf_signals_failed_total Signal deliveries that did not reach the backend, by reason.\n# TYPE waf_signals_failed_total counter\n")
	for _, r := range []string{"network", "rejected", "server_error", "no_credential", "rate_limited"} {
		fmt.Fprintf(w, "waf_signals_failed_total{reason=%q} %d\n", r, signalFailed[r].Load())
	}
}
