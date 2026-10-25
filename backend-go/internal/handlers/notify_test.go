package handlers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/workers"
)

// lockedBuffer collects log output written from several goroutines.
type lockedBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func TestBuildDeliveriesFormatsEachChannel(t *testing.T) {
	event := map[string]any{"event_type": "waf_block", "level": "error", "message": "blocked", "timestamp": "t", "client_ip": "1.2.3.4"}
	settings := map[string]string{
		"webhook_url": "https://hook.example/x",
		"gotify_url":  "https://gotify.example", "gotify_token": "tok",
		"teams_webhook_url":  "https://x.webhook.office.com/y",
		"telegram_bot_token": "bot", "telegram_chat_id": "42",
		"ntfy_url": "https://ntfy.example", "ntfy_topic": "alerts",
	}
	got := map[string]delivery{}
	for _, d := range buildDeliveries(settings, event) {
		got[d.channel] = d
	}
	if len(got) != 5 {
		t.Fatalf("got %d channels, want 5: %v", len(got), got)
	}
	if got["gotify"].url != "https://gotify.example/message?token=tok" {
		t.Errorf("gotify url = %q", got["gotify"].url)
	}
	if got["telegram"].url != "https://api.telegram.org/botbot/sendMessage" {
		t.Errorf("telegram url = %q", got["telegram"].url)
	}
	if got["ntfy"].url != "https://ntfy.example/alerts" || got["ntfy"].headers["Priority"] != "urgent" {
		t.Errorf("ntfy = %+v", got["ntfy"])
	}
	var hook map[string]any
	if err := json.Unmarshal(got["webhook"].body, &hook); err != nil || hook["event_type"] != "waf_block" {
		t.Errorf("webhook body = %s (%v)", got["webhook"].body, err)
	}
	var teams map[string]any
	_ = json.Unmarshal(got["teams"].body, &teams)
	if teams["themeColor"] != "FF0000" {
		t.Errorf("teams colour for an error = %v", teams["themeColor"])
	}

	// A channel with a missing half is not configured.
	if n := len(buildDeliveries(map[string]string{"gotify_url": "https://g", "ntfy_topic": "t"}, event)); n != 0 {
		t.Errorf("%d deliveries from half-configured channels, want 0", n)
	}
}

// waitForWorkers blocks until the tracked workers have returned, so a test does
// not leave one running into the next (or into its own cleanup).
func waitForWorkers(t *testing.T) {
	t.Helper()
	done := make(chan struct{})
	go func() { workers.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("notification workers did not stop")
	}
}

// fastNotify shortens the delivery budget and lets deliveries reach the
// httptest servers on loopback, which the production client refuses.
func fastNotify(t *testing.T, timeout time.Duration) {
	t.Helper()
	oldT, oldB, oldN, oldC := notifyTimeout, notifyBackoff, notifyMaxTries, notifyHTTPClient
	notifyTimeout, notifyMaxTries = timeout, 2
	notifyBackoff = func(int) time.Duration { return 5 * time.Millisecond }
	notifyHTTPClient = func() *http.Client { return &http.Client{Timeout: notifyTimeout} }
	t.Cleanup(func() { notifyTimeout, notifyBackoff, notifyMaxTries, notifyHTTPClient = oldT, oldB, oldN, oldC })
}

func TestWebhookCarriesTheBearerTokenOnlyWhenOneIsSet(t *testing.T) {
	event := map[string]any{"event_type": "waf_block", "level": "error", "message": "m"}
	with := buildDeliveries(map[string]string{"webhook_url": "https://hook.example/x", "webhook_bearer_token": "s3cr3t-token"}, event)
	if len(with) != 1 || with[0].headers["Authorization"] != "Bearer s3cr3t-token" {
		t.Fatalf("with a token: %+v", with)
	}
	without := buildDeliveries(map[string]string{"webhook_url": "https://hook.example/x"}, event)
	if _, ok := without[0].headers["Authorization"]; ok {
		t.Errorf("without a token the webhook still carries Authorization: %v", without[0].headers)
	}
	// The shared JSON header map must not have been modified by the first call.
	if _, ok := jsonHeader["Authorization"]; ok {
		t.Error("the token leaked into the header map every channel shares")
	}
}

// The token is stored encrypted, reaches the receiver as a header, and is
// written to no log line, even when the receiver refuses it.
func TestTheBearerTokenReachesTheWebhookAndNoLog(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	cfg.EncryptionKey = strings.Repeat("ab", 32)
	fastNotify(t, 2*time.Second)
	const token = "tok-7f3a9c-never-log-me"
	got := make(chan string, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.Header.Get("Authorization")
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	settings := NewSettingsHandlers(db, cfg)
	// The URL goes straight into the table: the settings API refuses a
	// loopback destination, which the httptest server is.
	_, _ = db.Exec("INSERT OR REPLACE INTO settings(setting_name,setting_value) VALUES('webhook_url',?)", srv.URL)
	body, _ := json.Marshal(map[string]string{"webhook_bearer_token": token})
	w := httptest.NewRecorder()
	settings.BulkUpdate(w, httptest.NewRequest("POST", "/api/settings", strings.NewReader(string(body))))
	if w.Code != http.StatusOK {
		t.Fatalf("saving the webhook: %d %s", w.Code, w.Body.String())
	}
	var stored string
	_ = db.QueryRow("SELECT setting_value FROM settings WHERE setting_name='webhook_bearer_token'").Scan(&stored)
	if !strings.HasPrefix(stored, "enc::") || strings.Contains(stored, token) {
		t.Errorf("the token is stored as %q, not encrypted", stored)
	}

	var logs lockedBuffer
	old := log.Logger
	log.Logger = zerolog.New(&logs)
	defer func() { log.Logger = old }()

	h := NewSecurityHandlers(db, nil, cfg, nil)
	rec := httptest.NewRecorder()
	h.TestNotification(rec, httptest.NewRequest("POST", "/api/notifications/test", nil))
	if auth := <-got; auth != "Bearer "+token {
		t.Errorf("the webhook received Authorization %q", auth)
	}
	if strings.Contains(logs.String(), token) || strings.Contains(rec.Body.String(), token) {
		t.Errorf("the token appears in the log or the response:\nlog: %s\nresponse: %s", logs.String(), rec.Body.String())
	}
	if !strings.Contains(logs.String(), `"channel":"webhook"`) {
		t.Errorf("the refused delivery was not logged at all: %s", logs.String())
	}
}

// The test endpoint answers for each channel, with the reason one failed,
// and tests the stored channels even while alerts are switched off.
func TestTestNotificationReportsEachChannel(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	fastNotify(t, 2*time.Second)
	ok := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer ok.Close()
	refused := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) }))
	defer refused.Close()
	for k, v := range map[string]string{
		"enable_notifications": "false", "webhook_url": ok.URL, "ntfy_url": refused.URL + "/", "ntfy_topic": "t",
	} {
		_, _ = db.Exec("INSERT OR REPLACE INTO settings(setting_name,setting_value) VALUES(?,?)", k, v)
	}
	h := NewSecurityHandlers(db, nil, cfg, nil)
	rec := httptest.NewRecorder()
	h.TestNotification(rec, httptest.NewRequest("POST", "/api/notifications/test", nil))
	var resp struct {
		Message string `json:"message"`
		Data    struct {
			Enabled  bool             `json:"notifications_enabled"`
			Channels []deliveryResult `json:"channels"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Data.Enabled {
		t.Error("notifications_enabled is true while alerts are off")
	}
	if len(resp.Data.Channels) != 2 {
		t.Fatalf("channels = %+v, want webhook and ntfy", resp.Data.Channels)
	}
	byName := map[string]deliveryResult{}
	for _, c := range resp.Data.Channels {
		byName[c.Channel] = c
	}
	if c := byName["webhook"]; !c.Delivered || c.Status != 200 {
		t.Errorf("webhook = %+v, want delivered with 200", c)
	}
	if c := byName["ntfy"]; c.Delivered || c.Status != 403 || !strings.Contains(c.Error, "refused the credentials") {
		t.Errorf("ntfy = %+v, want not delivered, 403, with the reason", c)
	}
	if resp.Message != "Delivered to 1 of 2 configured channels" {
		t.Errorf("message = %q", resp.Message)
	}
}

// With the production client (notifyHTTPClient as shipped), a channel
// pointed at this host is refused
// before anything is sent, and the result says why.
func TestADeliveryToThisHostIsRefused(t *testing.T) {
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit = true }))
	defer srv.Close()
	res := delivery{channel: "webhook", url: srv.URL, body: []byte("{}")}.sendTries(notifyHTTPClient(), 1)
	if res.Delivered || !strings.Contains(res.Error, "this host or to the proxy stack") {
		t.Errorf("result = %+v, want refused", res)
	}
	if hit {
		t.Error("the delivery reached the loopback server")
	}
	if strings.Contains(res.Error, srv.URL) || strings.Contains(res.Error, "127.0.0.1") {
		t.Errorf("the error names the destination: %q", res.Error)
	}
}

// One dead channel used to cost every other channel, and every event queued
// behind it, its whole retry budget: they were delivered by one worker in
// sequence.
func TestADeadChannelDoesNotDelayTheOthers(t *testing.T) {
	db, _, _, cleanup := setupTestDB(t)
	defer cleanup()
	fastNotify(t, 2*time.Second)

	release := make(chan struct{})
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-release }))
	defer dead.Close()

	var got atomic.Int32
	got2 := make(chan string, 4)
	live := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got.Add(1)
		got2 <- string(b)
	}))
	defer live.Close()

	for k, v := range map[string]string{
		"enable_notifications": "true", "webhook_url": dead.URL, "ntfy_url": live.URL + "/", "ntfy_topic": "t",
	} {
		if _, err := db.Exec("INSERT OR REPLACE INTO settings(setting_name,setting_value) VALUES(?,?)", k, v); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	q := NewNotifyQueue(ctx, db, "0000000000000000000000000000000000000000000000000000000000000000")
	// Unblock the stalled endpoint, stop the workers and wait for them, so none
	// outlives the test.
	defer func() { close(release); cancel(); waitForWorkers(t) }()

	start := time.Now()
	q <- map[string]any{"event_type": "e1", "message": "m", "level": "info"}
	q <- map[string]any{"event_type": "e2", "message": "m", "level": "info"}
	for i := 0; i < 2; i++ {
		select {
		case <-got2:
		case <-time.After(1500 * time.Millisecond):
			t.Fatalf("delivery %d to the live channel was held up by the dead one (%v)", i+1, time.Since(start))
		}
	}
	if time.Since(start) > time.Second {
		t.Errorf("the live channel took %v while the dead one stalled", time.Since(start))
	}
}

// What is queued when shutdown starts must still be delivered.
func TestQueuedAlertsAreDeliveredOnShutdown(t *testing.T) {
	db, _, _, cleanup := setupTestDB(t)
	defer cleanup()
	fastNotify(t, time.Second)

	var got atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got.Add(1) }))
	defer srv.Close()
	for k, v := range map[string]string{"enable_notifications": "true", "webhook_url": srv.URL} {
		_, _ = db.Exec("INSERT OR REPLACE INTO settings(setting_name,setting_value) VALUES(?,?)", k, v)
	}
	ctx, cancel := context.WithCancel(context.Background())
	q := NewNotifyQueue(ctx, db, "0000000000000000000000000000000000000000000000000000000000000000")
	for i := 0; i < 5; i++ {
		q <- map[string]any{"event_type": "e", "message": "m", "level": "info"}
	}
	cancel()

	waitForWorkers(t)
	if n := got.Load(); n != 5 {
		t.Errorf("%d of 5 queued alerts were delivered before shutdown completed", n)
	}
}

func TestSynchronousSendTakesAsLongAsTheSlowestChannelNotTheSum(t *testing.T) {
	db, _, _, cleanup := setupTestDB(t)
	defer cleanup()
	fastNotify(t, 2*time.Second)

	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
	}))
	defer slow.Close()
	for k, v := range map[string]string{
		"enable_notifications": "true", "webhook_url": slow.URL, "teams_webhook_url": slow.URL,
		"ntfy_url": slow.URL + "/", "ntfy_topic": "t",
	} {
		_, _ = db.Exec("INSERT OR REPLACE INTO settings(setting_name,setting_value) VALUES(?,?)", k, v)
	}
	start := time.Now()
	sendSecurityNotification(db, "0000000000000000000000000000000000000000000000000000000000000000",
		map[string]any{"event_type": "notification_test", "message": strings.Repeat("m", 3), "level": "info"})
	if d := time.Since(start); d > 800*time.Millisecond {
		t.Errorf("three 300ms channels took %v; delivered in sequence?", d)
	}
}
