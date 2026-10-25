package handlers

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"

	appcrypto "github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/crypto"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/metrics"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/netguard"
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
// The client refuses this host and the stack's own networks and follows no
// redirect (netguard.NotifyClient); tests that deliver to an httptest server
// on loopback swap it.
var (
	notifyTimeout    = 5 * time.Second
	notifyBackoff    = func(attempt int) time.Duration { return time.Duration(1<<uint(attempt)) * time.Second } // 1s then 2s: there is no sleep after the last of 3 attempts
	notifyMaxTries   = 3
	notifyHTTPClient = func() *http.Client { return netguard.NotifyClient(notifyTimeout) }
)

// deliveryResult is what one delivery came to, as the test endpoint reports
// it. Error never carries the URL: Go's url.Error prints it, and the Gotify
// token and the Telegram bot token are part of it.
type deliveryResult struct {
	Channel   string `json:"channel"`
	Delivered bool   `json:"delivered"`
	// Status is the HTTP status of the last answer, 0 when none came.
	Status int    `json:"status,omitempty"`
	Error  string `json:"error,omitempty"`
}

// describeDeliveryError names why a delivery got no answer, without the URL.
func describeDeliveryError(err error) string {
	var blocked *netguard.BlockedTargetError
	var dnsErr *net.DNSError
	var netErr net.Error
	var unknownCA x509.UnknownAuthorityError
	var badHost x509.HostnameError
	var invalid x509.CertificateInvalidError
	var recordErr tls.RecordHeaderError
	switch {
	case errors.As(err, &blocked):
		return "refused: the address belongs to this host or to the proxy stack"
	case errors.As(err, &dnsErr):
		return "the host name could not be resolved"
	case errors.As(err, &unknownCA), errors.As(err, &badHost), errors.As(err, &invalid), errors.As(err, &recordErr):
		return "the TLS handshake failed: the server's certificate is not trusted, or it does not speak HTTPS"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "the connection was refused"
	case errors.As(err, &netErr) && netErr.Timeout():
		return fmt.Sprintf("no answer within %s", notifyTimeout)
	default:
		return "the connection failed"
	}
}

// describeDeliveryStatus names an answer that is not a delivery.
func describeDeliveryStatus(status int) string {
	switch {
	case status >= 300 && status < 400:
		return fmt.Sprintf("the server answered with a redirect (HTTP %d), which is not followed", status)
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return fmt.Sprintf("the server refused the credentials (HTTP %d)", status)
	case status == http.StatusNotFound:
		return "the server has no such endpoint (HTTP 404)"
	default:
		return fmt.Sprintf("the server answered HTTP %d", status)
	}
}

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
func (d delivery) send(client *http.Client) deliveryResult {
	return d.sendTries(client, notifyMaxTries)
}

// sendTries is send with its own attempt budget: the test endpoint makes one
// attempt, so the operator gets an answer in seconds.
//
// Nothing here logs the URL or the headers: the Gotify token, the Telegram bot
// token and the webhook bearer token travel in them.
func (d delivery) sendTries(client *http.Client, tries int) deliveryResult {
	res := deliveryResult{Channel: d.channel}
	for attempt := 0; attempt < tries; attempt++ {
		req, err := http.NewRequest(http.MethodPost, d.url, bytes.NewReader(d.body))
		if err != nil {
			res.Error = "the URL cannot be used"
			metrics.NotificationFailed(d.channel)
			return res
		}
		for k, v := range d.headers {
			req.Header.Set(k, v)
		}
		resp, err := client.Do(req)
		if err == nil {
			status := resp.StatusCode
			resp.Body.Close()
			res.Status, res.Error = status, ""
			if status < 300 {
				metrics.NotificationSent(d.channel)
				res.Delivered = true
				return res
			}
			res.Error = describeDeliveryStatus(status)
			if status < 500 {
				// A 4xx is not worth retrying, but it IS a failure: an expired
				// Gotify token or a rotated webhook answers 401/404 and the
				// alert never arrives. This used to return silently, so the
				// channel by which an operator learns about attacks could stop
				// working with no signal at all (SECURE-OBS-02). A redirect is
				// not followed (it could point inside the stack) and is not a
				// delivery either.
				metrics.NotificationFailed(d.channel)
				log.Warn().Str("channel", d.channel).Int("status", status).
					Msg("notification rejected: check the channel settings")
				return res
			}
		} else {
			res.Status, res.Error = 0, describeDeliveryError(err)
		}
		if attempt < tries-1 {
			time.Sleep(notifyBackoff(attempt))
		}
	}
	metrics.NotificationFailed(d.channel)
	log.Warn().Str("channel", d.channel).Str("reason", res.Error).Msg("notification delivery failed after retries")
	return res
}

// loadNotificationSettings reads and decrypts the notification settings. ok is
// false when notifications are disabled or the settings cannot be read.
func loadNotificationSettings(db *sql.DB, encKey string) (map[string]string, bool) {
	rows, err := db.Query(
		"SELECT setting_name, setting_value FROM settings WHERE setting_name IN (?,?,?,?,?,?,?,?,?,?)",
		"enable_notifications", "webhook_url", "webhook_bearer_token", "gotify_url", "gotify_token",
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
		// Decrypt sensitive values transparently. One that cannot be decrypted
		// is treated as not set: it used to be used as it was, so the enc::
		// ciphertext went out as a URL or, for the bearer token, as a header.
		if appcrypto.IsSensitive(k) {
			dec, err := appcrypto.Decrypt(v, encKey)
			if err != nil {
				log.Warn().Str("key", k).Msg("notification setting cannot be decrypted: treated as not set")
				dec = ""
			}
			v = dec
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

// deliverEach sends every delivery concurrently with its own attempt budget
// and returns the results in the order of notifyChannels.
func deliverEach(deliveries []delivery, tries int) []deliveryResult {
	client := notifyHTTPClient()
	results := make([]deliveryResult, len(deliveries))
	var wg sync.WaitGroup
	for i, d := range deliveries {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = d.sendTries(client, tries)
		}()
	}
	wg.Wait()
	return results
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

// webhookDelivery posts the event as JSON. With webhook_bearer_token set it
// carries "Authorization: Bearer <token>", so the receiver can refuse a post
// that did not come from this backend; without one anybody who learns the
// URL can post fake alerts to it.
func webhookDelivery(s map[string]string, event map[string]any, _ alertText) (delivery, bool) {
	u := s["webhook_url"]
	if u == "" {
		return delivery{}, false
	}
	payload, _ := json.Marshal(event)
	headers := jsonHeader
	if tok := strings.TrimSpace(s["webhook_bearer_token"]); tok != "" {
		headers = map[string]string{"Content-Type": "application/json", "Authorization": "Bearer " + tok}
	}
	return delivery{channel: "webhook", url: u, body: payload, headers: headers}, true
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
