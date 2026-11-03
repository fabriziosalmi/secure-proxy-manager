package workers

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/metrics"
)

// Events the workers raise for the alert channels. Alerts used to come only
// from WAF blocks and failed sign-ins, so the events an admin of a small
// network needs most (the proxy stopped, a blocklist feed no longer
// downloads, a new version) reached no channel. Each is raised once per
// change of state, not on every check, and goes through the same queue,
// limits and switch (notify_system) as the others.

// AlertSink receives an event; main sets it to the notification queue.
type AlertSink func(event map[string]any)

var alertSink atomic.Pointer[AlertSink]

// SetAlertSink sets where raised events go. Until it is set, nothing is sent.
func SetAlertSink(s AlertSink) { alertSink.Store(&s) }

// raiseAlert hands one event to the sink.
func raiseAlert(eventType, level, message string) {
	p := alertSink.Load()
	if p == nil {
		return
	}
	(*p)(map[string]any{
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
		"event_type": eventType,
		"level":      level,
		"message":    message,
	})
}

// raiseClientAlert hands the sink an event about one client: client_ip makes
// it group with that client's other events of the type, as a WAF block does.
func raiseClientAlert(eventType, level, message, clientIP string, details map[string]any) {
	p := alertSink.Load()
	if p == nil {
		return
	}
	event := map[string]any{
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
		"event_type": eventType,
		"level":      level,
		"message":    message,
		"client_ip":  clientIP,
	}
	for k, v := range details {
		event[k] = v
	}
	(*p)(event)
}

// proxyWatch is the proxy's state as the watch last decided it.
type proxyWatch struct {
	down     bool
	failures int
}

// proxyDownAfter is how many failed probes in a row make the proxy down: one
// probe can fail while Squid reconfigures.
const proxyDownAfter = 2

// step takes one probe result and returns the event to raise, if any.
func (p *proxyWatch) step(up bool, addr string) (eventType, level, message string) {
	if up {
		p.failures = 0
		if p.down {
			p.down = false
			return "proxy_up", "info", "The proxy at " + addr + " answers again."
		}
		return "", "", ""
	}
	p.failures++
	if !p.down && p.failures >= proxyDownAfter {
		p.down = true
		return "proxy_down", "error", fmt.Sprintf("The proxy at %s has not answered for %d checks in a row: clients cannot browse.", addr, p.failures)
	}
	return "", "", ""
}

// proxyWatchEvery is how often the proxy is probed; a test shortens it.
var proxyWatchEvery = time.Minute

// StartProxyWatch probes the proxy every minute and raises proxy_down when it
// stops answering and proxy_up when it is back. probe is the same check
// GET /api/status makes.
func StartProxyWatch(ctx context.Context, addr string, probe func(context.Context) bool) {
	Track(func() {
		var w proxyWatch
		t := time.NewTicker(proxyWatchEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			up := probe(pctx)
			cancel()
			metrics.WorkerHeartbeat("proxy_watch")
			if typ, level, msg := w.step(up, addr); typ != "" {
				log.Warn().Str("event", typ).Msg(msg)
				raiseAlert(typ, level, msg)
			}
		}
	})
}
