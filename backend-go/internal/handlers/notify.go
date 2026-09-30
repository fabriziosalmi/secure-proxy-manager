package handlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	appcrypto "github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/crypto"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/metrics"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/workers"
)

// Notification delivery.
//
// One event becomes one delivery per configured channel. Each channel has its
// own bounded queue and its own worker, so an endpoint that is down or slow
// (5 s per attempt, three attempts, and the sleeps between them) holds up only
// its own deliveries. They used to be made in sequence by a single worker: one
// dead webhook cost every other channel, and every event queued behind it,
// about 18 seconds, and during an attack the 256-slot queue then filled and
// alerts were dropped.

// notifyChannels are the channels, in the order they are planned.
var notifyChannels = []string{"webhook", "gotify", "teams", "telegram", "ntfy"}

// channelQueueSize bounds what one channel may hold. Past it the delivery for
// that channel is dropped and counted; the other channels are unaffected.
const channelQueueSize = 64

// Variables so tests can shorten them; production values are the defaults.
var (
	notifyTimeout    = 5 * time.Second
	notifyBackoff    = func(attempt int) time.Duration { return time.Duration(1<<uint(attempt)) * time.Second } // 1s, 2s, 4s
	notifyMaxTries   = 3
	notifyHTTPClient = func() *http.Client { return &http.Client{Timeout: notifyTimeout} }
)

// delivery is one message for one channel.
type delivery struct {
	channel string
	url     string
	body    []byte
	headers map[string]string
}

// notifyFanout owns the per-channel queues and their workers.
type notifyFanout struct {
	queues map[string]chan delivery
	once   sync.Once
}

func newNotifyFanout() *notifyFanout {
	f := &notifyFanout{queues: make(map[string]chan delivery, len(notifyChannels))}
	client := notifyHTTPClient()
	for _, name := range notifyChannels {
		ch := make(chan delivery, channelQueueSize)
		f.queues[name] = ch
		workers.Track(func() {
			for d := range ch {
				d.send(client)
			}
		})
	}
	return f
}

// submit queues a delivery for its channel without blocking.
func (f *notifyFanout) submit(d delivery) {
	q, ok := f.queues[d.channel]
	if !ok {
		return
	}
	select {
	case q <- d:
	default:
		metrics.NotificationFailed(d.channel)
		metrics.NotificationDropped()
		log.Warn().Str("channel", d.channel).Msg("notification channel queue full — delivery dropped")
	}
}

// close lets every channel worker drain what it holds and return.
func (f *notifyFanout) close() {
	f.once.Do(func() {
		for _, q := range f.queues {
			close(q)
		}
	})
}

// send posts one delivery with bounded retries and backoff. It records the
// outcome on the channel's metrics.
func (d delivery) send(client *http.Client) {
	for attempt := 0; attempt < notifyMaxTries; attempt++ {
		req, err := http.NewRequest(http.MethodPost, d.url, bytes.NewReader(d.body))
		if err != nil {
			return
		}
		for k, v := range d.headers {
			req.Header.Set(k, v)
		}
		resp, err := client.Do(req)
		if err == nil {
			status := resp.StatusCode
			resp.Body.Close()
			if status < 400 {
				metrics.NotificationSent(d.channel)
				return
			}
			if status < 500 {
				// A 4xx is not worth retrying, but it IS a failure: an expired
				// Gotify token or a rotated webhook answers 401/404 and the
				// alert never arrives. This used to return silently, so the
				// channel by which an operator learns about attacks could stop
				// working with no signal at all (SECURE-OBS-02).
				metrics.NotificationFailed(d.channel)
				log.Warn().Str("channel", d.channel).Int("status", status).
					Msg("notification rejected — check the channel credentials")
				return
			}
		}
		if attempt < notifyMaxTries-1 {
			time.Sleep(notifyBackoff(attempt))
		}
	}
	metrics.NotificationFailed(d.channel)
	log.Warn().Str("channel", d.channel).Msg("notification delivery failed after retries")
}

// loadNotificationSettings reads and decrypts the notification settings. ok is
// false when notifications are disabled or the settings cannot be read.
func loadNotificationSettings(db *sql.DB, encKey string) (map[string]string, bool) {
	rows, err := db.Query(
		"SELECT setting_name, setting_value FROM settings WHERE setting_name IN (?,?,?,?,?,?,?,?,?)",
		"enable_notifications", "webhook_url", "gotify_url", "gotify_token",
		"teams_webhook_url", "telegram_bot_token", "telegram_chat_id",
		"ntfy_url", "ntfy_topic",
	)
	if err != nil {
		return nil, false
	}
	defer rows.Close()
	settings := map[string]string{}
	for rows.Next() {
		var k, v string
		rows.Scan(&k, &v) //nolint:errcheck
		// Decrypt sensitive values transparently.
		if appcrypto.IsSensitive(k) {
			if dec, err := appcrypto.Decrypt(v, encKey); err == nil {
				v = dec
			}
		}
		settings[k] = v
	}
	return settings, settings["enable_notifications"] == "true"
}

// planNotifications is the deliveries an event produces under the current
// settings: none when notifications are off.
func planNotifications(db *sql.DB, encKey string, event map[string]any) []delivery {
	settings, ok := loadNotificationSettings(db, encKey)
	if !ok {
		return nil
	}
	return buildDeliveries(settings, event)
}

// sendSecurityNotification delivers an event to every configured channel and
// returns when all have finished. The channels run concurrently, so the call
// takes as long as the slowest one, not the sum. The test-notification endpoint
// uses it to report back synchronously; the queue path uses the per-channel
// workers instead.
func sendSecurityNotification(db *sql.DB, encKey string, event map[string]any) {
	client := notifyHTTPClient()
	var wg sync.WaitGroup
	for _, d := range planNotifications(db, encKey, event) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.send(client)
		}()
	}
	wg.Wait()
	log.Debug().Str("event_type", fmt.Sprintf("%v", event["event_type"])).Msg("security notification sent")
}

// alertText is the human-readable form of an event, shared by the channels.
type alertText struct {
	title    string
	plain    string
	msgLines []string
}

func formatAlert(event map[string]any) alertText {
	emoji := "ℹ️"
	switch event["level"] {
	case "error":
		emoji = "🔴"
	case "warning":
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
	return alertText{title: title, plain: title + "\n\n" + strings.Join(msgLines, "\n"), msgLines: msgLines}
}

var jsonHeader = map[string]string{"Content-Type": "application/json"}

// buildDeliveries turns settings and an event into one delivery per configured
// channel. It does no I/O.
func buildDeliveries(settings map[string]string, event map[string]any) []delivery {
	txt := formatAlert(event)
	var out []delivery
	for _, build := range []func(map[string]string, map[string]any, alertText) (delivery, bool){
		webhookDelivery, gotifyDelivery, teamsDelivery, telegramDelivery, ntfyDelivery,
	} {
		if d, ok := build(settings, event, txt); ok {
			out = append(out, d)
		}
	}
	return out
}

func webhookDelivery(s map[string]string, event map[string]any, _ alertText) (delivery, bool) {
	u := s["webhook_url"]
	if u == "" {
		return delivery{}, false
	}
	payload, _ := json.Marshal(event)
	return delivery{channel: "webhook", url: u, body: payload, headers: jsonHeader}, true
}

func gotifyDelivery(s map[string]string, event map[string]any, t alertText) (delivery, bool) {
	u, tok := s["gotify_url"], s["gotify_token"]
	if u == "" || tok == "" {
		return delivery{}, false
	}
	if !strings.HasSuffix(u, "/") {
		u += "/"
	}
	prio := 5
	if event["level"] == "error" {
		prio = 8
	}
	payload, _ := json.Marshal(map[string]any{"title": t.title, "message": t.plain, "priority": prio})
	return delivery{channel: "gotify", url: u + "message?token=" + tok, body: payload, headers: jsonHeader}, true
}

func teamsDelivery(s map[string]string, event map[string]any, t alertText) (delivery, bool) {
	u := s["teams_webhook_url"]
	if u == "" {
		return delivery{}, false
	}
	color := "FFA500"
	if event["level"] == "error" {
		color = "FF0000"
	}
	payload, _ := json.Marshal(map[string]any{
		"@type": "MessageCard", "@context": "http://schema.org/extensions",
		"themeColor": color, "summary": t.title,
		"sections": []map[string]any{{"activityTitle": t.title, "text": t.plain}},
	})
	return delivery{channel: "teams", url: u, body: payload, headers: jsonHeader}, true
}

func telegramDelivery(s map[string]string, _ map[string]any, t alertText) (delivery, bool) {
	tok, chatID := s["telegram_bot_token"], s["telegram_chat_id"]
	if tok == "" || chatID == "" {
		return delivery{}, false
	}
	payload, _ := json.Marshal(map[string]any{
		"chat_id": chatID, "text": "*" + t.title + "*\n\n" + strings.Join(t.msgLines, "\n"), "parse_mode": "Markdown",
	})
	return delivery{channel: "telegram", url: "https://api.telegram.org/bot" + tok + "/sendMessage", body: payload, headers: jsonHeader}, true
}

func ntfyDelivery(s map[string]string, event map[string]any, t alertText) (delivery, bool) {
	u, topic := s["ntfy_url"], s["ntfy_topic"]
	if u == "" || topic == "" {
		return delivery{}, false
	}
	if !strings.HasSuffix(u, "/") {
		u += "/"
	}
	prio := "default"
	switch event["level"] {
	case "error":
		prio = "urgent"
	case "warning":
		prio = "high"
	}
	return delivery{channel: "ntfy", url: u + topic, body: []byte(t.plain),
		headers: map[string]string{"Title": t.title, "Priority": prio, "Tags": "shield"}}, true
}
