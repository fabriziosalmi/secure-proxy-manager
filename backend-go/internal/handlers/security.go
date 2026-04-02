package handlers

import (
	"bytes"
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
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/models"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/workers"
)

// NotifyQueue is a bounded channel for fire-and-forget security notifications.
type NotifyQueue chan map[string]any

// NewNotifyQueue creates a queue and starts its worker goroutine.
func NewNotifyQueue(db *sql.DB) NotifyQueue {
	q := make(NotifyQueue, 256)
	go func() {
		for event := range q {
			sendSecurityNotification(db, event)
		}
	}()
	return q
}

type SecurityHandlers struct {
	db      *sql.DB
	svc     *auth.Service
	cfg     *config.Config
	notify  NotifyQueue
}

func NewSecurityHandlers(db *sql.DB, svc *auth.Service, cfg *config.Config, notify NotifyQueue) *SecurityHandlers {
	return &SecurityHandlers{db: db, svc: svc, cfg: cfg, notify: notify}
}

func (h *SecurityHandlers) Register(r chi.Router, authMW func(http.Handler) http.Handler) {
	r.With(authMW).Post("/api/internal/alert", h.ReceiveAlert)
	r.With(authMW).Get("/api/security/rate-limits", h.GetRateLimits)
	r.With(authMW).Delete("/api/security/rate-limits/{ip}", h.ClearRateLimit)
	r.With(authMW).Get("/api/security/score", h.Score)
	r.With(authMW).Get("/api/security/cve", h.CVECheck)
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
			"max_attempts":    h.cfg.MaxAttempts,
			"window_seconds":  int(h.cfg.RateLimitWindow.Seconds()),
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

func (h *SecurityHandlers) Score(w http.ResponseWriter, r *http.Request) {
	keys := []string{
		"enable_ip_blacklist", "enable_domain_blacklist", "block_direct_ip",
		"enable_content_filtering", "enable_waf", "ssl_bump_enabled",
		"default_password_changed", "enable_time_restrictions",
	}
	placeholders := strings.Repeat("?,", len(keys))
	placeholders = placeholders[:len(placeholders)-1]

	args := make([]any, len(keys))
	for i, k := range keys {
		args[i] = k
	}
	// #nosec G202
	rows, err := h.db.Query(
		"SELECT setting_name, setting_value FROM settings WHERE setting_name IN ("+placeholders+")",
		args...,
	)
	settings := map[string]string{}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var k, v string
			rows.Scan(&k, &v) //nolint:errcheck
			settings[k] = v
		}
	}

	type check struct {
		key    string
		points int
		rec    string
	}
	checks := []check{
		{"enable_ip_blacklist", 15, "Enable IP blacklisting to block known malicious IP addresses"},
		{"enable_domain_blacklist", 15, "Enable domain blacklisting to block malicious websites"},
		{"block_direct_ip", 10, "Enable direct IP access blocking to prevent bypassing domain filters"},
		{"enable_content_filtering", 10, "Enable content filtering to block risky file types"},
		{"enable_waf", 25, "Enable Outbound WAF (ICAP) to block SQLi, XSS, and Data Leaks"},
		{"ssl_bump_enabled", 15, "Consider enabling HTTPS inspection (SSL Bump) for complete security coverage"},
		{"default_password_changed", 5, "Change the default admin password to improve security"},
		{"enable_time_restrictions", 5, "Enable time restrictions to limit proxy usage to working hours"},
	}
	var score int
	var recs []string
	for _, c := range checks {
		if settings[c.key] == "true" {
			score += c.points
		} else {
			recs = append(recs, c.rec)
		}
	}
	writeOK(w, map[string]any{"score": score, "max_score": 100, "recommendations": recs})
}

// ── notification dispatcher ───────────────────────────────────────────────────

func sendSecurityNotification(db *sql.DB, event map[string]any) {
	rows, err := db.Query(
		"SELECT setting_name, setting_value FROM settings WHERE setting_name IN (?,?,?,?,?,?,?,?,?)",
		"enable_notifications", "webhook_url", "gotify_url", "gotify_token",
		"teams_webhook_url", "telegram_bot_token", "telegram_chat_id",
		"ntfy_url", "ntfy_topic",
	)
	if err != nil {
		return
	}
	defer rows.Close()
	settings := map[string]string{}
	for rows.Next() {
		var k, v string
		rows.Scan(&k, &v) //nolint:errcheck
		settings[k] = v
	}
	if settings["enable_notifications"] != "true" {
		return
	}

	emoji := "ℹ️"
	if event["level"] == "error" {
		emoji = "🔴"
	} else if event["level"] == "warning" {
		emoji = "⚠️"
	}
	title := fmt.Sprintf("%s Secure Proxy Alert: %s", emoji,
		titleCase(strings.ReplaceAll(fmt.Sprintf("%v", event["event_type"]), "_", " ")))

	var msgLines []string
	msgLines = append(msgLines, fmt.Sprintf("**Message:** %v", event["message"]))
	msgLines = append(msgLines, fmt.Sprintf("**Time:** %v", event["timestamp"]))
	msgLines = append(msgLines, fmt.Sprintf("**Client IP:** %v", event["client_ip"]))
	for k, v := range event {
		if k != "timestamp" && k != "client_ip" && k != "event_type" && k != "message" && k != "level" {
			msgLines = append(msgLines, fmt.Sprintf("**%s:** %v", titleCase(k), v))
		}
	}
	plainText := title + "\n\n" + strings.Join(msgLines, "\n")

	client := &http.Client{Timeout: 5 * time.Second}

	// safePost sends a POST and closes the body, ignoring all errors (fire-and-forget).
	safePost := func(url string, body []byte, headers map[string]string) {
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		if resp, err := client.Do(req); err == nil {
			resp.Body.Close()
		}
	}

	// 1. Custom webhook.
	if u := settings["webhook_url"]; u != "" {
		payload, _ := json.Marshal(event)
		safePost(u, payload, map[string]string{"Content-Type": "application/json"})
	}

	// 2. Gotify.
	if u, tok := settings["gotify_url"], settings["gotify_token"]; u != "" && tok != "" {
		if !strings.HasSuffix(u, "/") {
			u += "/"
		}
		prio := 5
		if event["level"] == "error" {
			prio = 8
		}
		payload, _ := json.Marshal(map[string]any{"title": title, "message": plainText, "priority": prio})
		safePost(u+"message?token="+tok, payload, map[string]string{"Content-Type": "application/json"})
	}

	// 3. Microsoft Teams.
	if u := settings["teams_webhook_url"]; u != "" {
		color := "FFA500"
		if event["level"] == "error" {
			color = "FF0000"
		}
		payload, _ := json.Marshal(map[string]any{
			"@type": "MessageCard", "@context": "http://schema.org/extensions",
			"themeColor": color, "summary": title,
			"sections": []map[string]any{{"activityTitle": title, "text": plainText}},
		})
		safePost(u, payload, map[string]string{"Content-Type": "application/json"})
	}

	// 4. Telegram.
	if tok, chatID := settings["telegram_bot_token"], settings["telegram_chat_id"]; tok != "" && chatID != "" {
		payload, _ := json.Marshal(map[string]any{
			"chat_id": chatID, "text": "*" + title + "*\n\n" + strings.Join(msgLines, "\n"), "parse_mode": "Markdown",
		})
		safePost("https://api.telegram.org/bot"+tok+"/sendMessage", payload, map[string]string{"Content-Type": "application/json"})
	}

	// 5. ntfy.sh (self-hosted push notifications).
	if u, topic := settings["ntfy_url"], settings["ntfy_topic"]; u != "" && topic != "" {
		if !strings.HasSuffix(u, "/") {
			u += "/"
		}
		prio := "default"
		if event["level"] == "error" {
			prio = "urgent"
		} else if event["level"] == "warning" {
			prio = "high"
		}
		safePost(u+topic, []byte(plainText), map[string]string{
			"Title": title, "Priority": prio, "Tags": "shield",
		})
	}

	log.Debug().Str("event_type", fmt.Sprintf("%v", event["event_type"])).Msg("security notification sent")
}

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
