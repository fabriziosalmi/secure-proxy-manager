package main

import (
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// TLS fingerprints of peeked CONNECTs, recorded with no score: how many JA4
// fingerprints each client shows and how often a client shows a new one is
// measured on real traffic before anything is scored on it.
var (
	// tlsJA4Total counts handshakes fingerprinted, tlsJA4Unparsed TLS
	// handshakes that did not parse as a whole ClientHello, tlsJA4NewForClient
	// fingerprints a client showed after it had shown another one.
	tlsJA4Total        atomic.Int64
	tlsJA4Unparsed     atomic.Int64
	tlsJA4NewForClient atomic.Int64

	ja4Seen = newJA4Tracker()
	uaLinks = newUALinks()
)

const (
	maxJA4Clients   = 10000 // as many as the per-client heuristic state
	maxJA4PerClient = 64
	maxUALinks      = 10000
	uaLinkTTL       = 30 * time.Second
)

// ja4Tracker holds, per client address, the fingerprints its handshakes
// had since the WAF started. Past the bounds a new client or fingerprint is
// not recorded, and reported as untracked.
type ja4Tracker struct {
	mu      sync.Mutex
	clients map[string]map[string]struct{}
	pairs   int
}

func newJA4Tracker() *ja4Tracker {
	return &ja4Tracker{clients: map[string]map[string]struct{}{}}
}

// observe records that client showed ja4. isNew is true the first time the
// pair is seen; before is how many other fingerprints the client had then.
func (t *ja4Tracker) observe(client, ja4 string) (isNew bool, before int, tracked bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	fps, ok := t.clients[client]
	if !ok {
		if len(t.clients) >= maxJA4Clients {
			return false, 0, false
		}
		fps = map[string]struct{}{}
		t.clients[client] = fps
	}
	if _, seen := fps[ja4]; seen {
		return false, len(fps) - 1, true
	}
	if len(fps) >= maxJA4PerClient {
		return false, len(fps), false
	}
	fps[ja4] = struct{}{}
	t.pairs++
	return true, len(fps) - 1, true
}

// size is the number of clients and of client x fingerprint pairs held.
func (t *ja4Tracker) size() (clients, pairs int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.clients), t.pairs
}

// uaLinkStore keeps, for a short while, the User-Agent of a CONNECT's first
// pass, so its second pass (which Squid sends with no User-Agent) can be
// logged with it. The key is the client and the CONNECT's host.
type uaLinkStore struct {
	mu sync.Mutex
	m  map[string]uaLink
}

type uaLink struct {
	ua string
	at time.Time
}

func newUALinks() *uaLinkStore { return &uaLinkStore{m: map[string]uaLink{}} }

func uaLinkKey(client, hostport string) string {
	h, _, err := net.SplitHostPort(hostport)
	if err != nil {
		h = hostport
	}
	return client + "|" + strings.TrimSuffix(strings.ToLower(h), ".")
}

func (l *uaLinkStore) put(key, ua string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.m) >= maxUALinks {
		for k, v := range l.m {
			if now.Sub(v.at) > uaLinkTTL {
				delete(l.m, k)
			}
		}
		if len(l.m) >= maxUALinks {
			return
		}
	}
	l.m[key] = uaLink{ua: ua, at: now}
}

// take returns and forgets the User-Agent stored under key, "" when there
// is none or it is older than uaLinkTTL.
func (l *uaLinkStore) take(key string, now time.Time) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	v, ok := l.m[key]
	if !ok {
		return ""
	}
	delete(l.m, key)
	if now.Sub(v.at) > uaLinkTTL {
		return ""
	}
	return v.ua
}
