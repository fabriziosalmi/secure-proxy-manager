package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/auth"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/config"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/metrics"
	appMW "github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/middleware"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/models"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/validate"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/workers"
)

// NotifyQueue is a bounded channel for fire-and-forget security notifications.
type NotifyQueue chan map[string]any

// NewNotifyQueue creates the queue and starts its dispatcher under ctx. The
// dispatcher applies the notification limits (notify_limit.go: grouping per
// address and a cap per channel), turns what passes into one delivery per
// configured channel and hands each to that channel's own worker (see
// notify.go), so a channel that is down delays only itself.
//
// The worker used to be spawned with no owner: nothing tracked it, nothing
// cancelled it, and the channel was never closed, so shutdown discarded
// whatever was still buffered — up to 256 events plus the one being delivered,
// on the path that carries login-failure and WAF-block alerts. The restart most
// likely to lose them is a restart during an attack (SECURE-CONC-01).
//
// It also emitted no liveness signal. The six background workers report a
// last-success timestamp precisely so an idle worker is distinguishable from a
// stopped one; this queue's counters stay flat when it dies, and flat is also
// what a quiet week looks like — so it could stop with no observable difference
// (SECURE-OBS-01).
func NewNotifyQueue(ctx context.Context, db *sql.DB, encKey string) NotifyQueue {
	ticker := time.NewTicker(notifyFlushInterval)
	return startNotifyQueue(ctx, db, encKey, time.Now, ticker.C, ticker.Stop)
}

// notifyFlushInterval is how often the dispatcher closes the groups whose
// window has ended and sends the held-back notices that are due, so a digest
// arrives within this long of its window's end. It is also the heartbeat.
const notifyFlushInterval = 5 * time.Second

// notifyQueueSize bounds what the dispatcher may have waiting.
const notifyQueueSize = 256

// startNotifyQueue is NewNotifyQueue with the clock and the flush tick given,
// so tests drive time instead of sleeping. stop, if set, runs when the
// dispatcher returns.
func startNotifyQueue(ctx context.Context, db *sql.DB, encKey string,
	now func() time.Time, tick <-chan time.Time, stop func()) NotifyQueue {
	q := make(NotifyQueue, notifyQueueSize)
	fan := newNotifyFanout()
	lim := newNotifyLimiter(now)
	workers.Track(func() {
		if stop != nil {
			defer stop()
		}
		// Heartbeat before the receive as well as after a delivery, so the
		// signal reports that the loop is alive rather than that something was
		// recently sent: a queue with nothing to do must still look alive.
		metrics.WorkerHeartbeat("notify_queue")
		// deliver sends ev to every configured channel that is under its cap.
		deliver := func(settings map[string]string, limits notifyLimits, ev map[string]any) {
			for _, d := range buildDeliveries(settings, ev) {
				if lim.allow(d.channel, limits) {
					fan.submit(d)
				}
			}
		}
		dispatch := func(event map[string]any) {
			settings, ok := loadNotificationSettings(db, encKey)
			if !ok {
				return
			}
			limits := limitsFrom(settings)
			if !limits.wants(event) {
				return
			}
			for _, ev := range lim.admit(event, limits) {
				deliver(settings, limits, ev)
			}
		}
		// flush sends the digests of the groups whose window has closed (every
		// open group when final) and the held-back notices that are due. The
		// settings are read only when there is something to send.
		flush := func(final bool) {
			var digests []map[string]any
			if final {
				digests = lim.flushAll()
			} else {
				digests = lim.expire()
			}
			if len(digests) == 0 && !lim.holding() {
				return
			}
			settings, ok := loadNotificationSettings(db, encKey)
			if !ok {
				lim.forgetHeld()
				return
			}
			limits := limitsFrom(settings)
			for _, ev := range digests {
				deliver(settings, limits, ev)
			}
			for channel, count := range lim.notices(limits, final) {
				for _, d := range buildDeliveries(settings, heldNotice(count, now())) {
					if d.channel == channel {
						fan.submit(d)
					}
				}
			}
		}
		// drain dispatches what is queued, at most limit events (no limit
		// when negative), and returns when the queue is empty.
		drain := func(limit int) {
			for i := 0; limit < 0 || i < limit; i++ {
				select {
				case event := <-q:
					dispatch(event)
				default:
					return
				}
			}
		}
		for {
			select {
			case <-ctx.Done():
				// Hand what is already queued to the channel workers, then the
				// open digests and the held-back notices, then close their
				// queues: each drains what it holds and returns, so a restart
				// during an attack does not discard what was counted. Shutdown
				// bounds the wait, so a wedged webhook cannot hold the process.
				drain(-1)
				flush(true)
				fan.close()
				log.Info().Msg("notification queue drained")
				return
			case event := <-q:
				dispatch(event)
				metrics.WorkerHeartbeat("notify_queue")
			case <-tick:
				// What was queued before the tick is counted before the flush,
				// at most one queue's worth so a flood cannot hold it off.
				drain(notifyQueueSize)
				flush(false)
				metrics.WorkerHeartbeat("notify_queue")
			}
		}
	})
	return q
}

type SecurityHandlers struct {
	db     *sql.DB
	svc    *auth.Service
	cfg    *config.Config
	notify NotifyQueue
}

func NewSecurityHandlers(db *sql.DB, svc *auth.Service, cfg *config.Config, notify NotifyQueue) *SecurityHandlers {
	return &SecurityHandlers{db: db, svc: svc, cfg: cfg, notify: notify}
}

func (h *SecurityHandlers) Register(r chi.Router, authMW func(http.Handler) http.Handler) {
	// /api/internal/alert is service-to-service, not operator-facing: the WAF
	// posts block notifications to it. It gets its own credential so the WAF
	// does not need the admin password (SECURE-AUTH-02). With no token
	// configured ServiceAuth returns authMW unchanged, which is the pre-upgrade
	// behaviour.
	alertToken := ""
	if h.cfg != nil {
		alertToken = h.cfg.AlertToken
	}
	r.With(appMW.ServiceAuth(alertToken, authMW)).Post("/api/internal/alert", h.ReceiveAlert)
	r.With(authMW).Get("/api/security/rate-limits", h.GetRateLimits)
	r.With(authMW).Delete("/api/security/rate-limits/{ip}", h.ClearRateLimit)
	r.With(authMW).Get("/api/security/score", h.ScoreGone)
	r.With(authMW).Get("/api/security/cve", h.CVECheck)
	r.With(authMW).Post("/api/notifications/test", h.TestNotification)
}

func (h *SecurityHandlers) CVECheck(w http.ResponseWriter, r *http.Request) {
	cve := workers.GetCVEInfo()
	writeOK(w, cve)
}

func (h *SecurityHandlers) ReceiveAlert(w http.ResponseWriter, r *http.Request) {
	var alert models.InternalAlert
	if err := json.NewDecoder(r.Body).Decode(&alert); err != nil {
		writeError(w, http.StatusBadRequest, "invalid alert payload")
		return
	}
	if err := validate.Struct(&alert); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	event := map[string]any{
		"timestamp":  time.Now().Format(time.RFC3339),
		"event_type": alert.EventType,
		"message":    alert.Message,
		"level":      alert.Level,
	}
	for k, v := range alert.Details {
		event[k] = v
	}
	// Non-blocking enqueue.
	select {
	case h.notify <- event:
	default:
		metrics.NotificationDropped()
		log.Warn().Msg("notification queue full — alert dropped")
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "success"})
}

func (h *SecurityHandlers) GetRateLimits(w http.ResponseWriter, r *http.Request) {
	data := h.svc.RateLimitSnapshot()
	if data == nil {
		data = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "success", "data": data,
		"meta": map[string]any{
			"max_attempts":   h.cfg.MaxAttempts,
			"window_seconds": int(h.cfg.RateLimitWindow.Seconds()),
		},
	})
}

func (h *SecurityHandlers) ClearRateLimit(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip")
	if !h.svc.ClearRateLimit(ip) {
		writeError(w, http.StatusNotFound, fmt.Sprintf("no active rate limit for IP %s", ip))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "success", "message": "Rate limit cleared for " + ip})
}

// ScoreGone answers the retired GET /api/security/score. The score added
// points for enable_ip_blacklist, enable_domain_blacklist, block_direct_ip and
// enable_waf, which nothing else read: Squid always denies the blacklists and
// direct-IP URLs and the WAF is always on the ICAP path, so a working install
// scored low and a switch in Settings raised the score without changing what
// the stack does. No page has shown the score since the Overview dropped it.
// Retired routes answer 410 naming what to use instead (CHANGELOG).
func (h *SecurityHandlers) ScoreGone(w http.ResponseWriter, _ *http.Request) {
	writeError(w, http.StatusGone, "removed: the security score counted settings nothing enforced; Settings > Overview lists what needs attention")
}

func (h *SecurityHandlers) TestNotification(w http.ResponseWriter, r *http.Request) {
	event := map[string]any{
		"timestamp":  time.Now().Format(time.RFC3339),
		"event_type": "notification_test",
		"message":    "This is a test notification from Secure Proxy Manager",
		"level":      "info",
		"client_ip":  r.RemoteAddr,
	}
	// Every channel that has all of its settings stored, whether or not alerts
	// are switched on, so a channel can be proven before alerts are turned on.
	// One attempt each, concurrently, and each channel's own result: the
	// response used to say "sent to all configured channels" after a send
	// whose outcome nobody looked at, with no channel configured, or with
	// alerts off.
	encKey := ""
	if h.cfg != nil {
		encKey = h.cfg.EncryptionKey
	}
	settings, enabled := loadNotificationSettings(h.db, encKey)
	results := deliverEach(buildDeliveries(settings, event), 1)
	delivered := 0
	for _, r := range results {
		if r.Delivered {
			delivered++
		}
	}
	var msg string
	switch {
	case len(results) == 0:
		msg = "No alert channel has all of its settings stored: nothing was sent"
	case delivered == len(results):
		msg = fmt.Sprintf("Delivered to all %d configured channels", len(results))
	default:
		msg = fmt.Sprintf("Delivered to %d of %d configured channels", delivered, len(results))
	}
	resp := map[string]any{
		"status":  "success",
		"message": msg,
		"data":    map[string]any{"notifications_enabled": enabled, "channels": results},
	}
	// This is the moment an operator concludes that notifications work, and it
	// is exactly where the gap is invisible: a test notification is generated
	// inside the backend and delivered, while WAF block alerts travel a
	// different path — the WAF POSTs them to /api/internal/alert — and are
	// dropped when INTERNAL_ALERT_TOKEN is unset, because the shipped compose no
	// longer hands the WAF the admin credential. Everything visible keeps
	// working, so the operator has no reason to look (SECURE-CONF-01).
	if h.cfg != nil && h.cfg.AlertToken == "" {
		resp["warning"] = "WAF block alerts are NOT being delivered: INTERNAL_ALERT_TOKEN is not set. " +
			"This test was generated by the backend and does not exercise that path. " +
			"Set INTERNAL_ALERT_TOKEN (openssl rand -hex 32) on both the waf and backend services, " +
			"or re-run deploy/install.sh, which adds it to an existing .env."
		resp["waf_alerts_delivered"] = false
	} else {
		resp["waf_alerts_delivered"] = true
	}
	writeJSON(w, http.StatusOK, resp)
}

// ── notification dispatcher ───────────────────────────────────────────────────

// titleCase replaces deprecated strings.Title — capitalises first letter of each word.
func titleCase(s string) string {
	words := strings.Fields(s)
	for i, w := range words {
		if len(w) > 0 {
			words[i] = strings.ToUpper(w[:1]) + w[1:]
		}
	}
	return strings.Join(words, " ")
}
