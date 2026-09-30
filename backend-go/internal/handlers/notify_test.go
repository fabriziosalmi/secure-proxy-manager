package handlers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/workers"
)

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

func fastNotify(t *testing.T, timeout time.Duration) {
	t.Helper()
	oldT, oldB, oldN := notifyTimeout, notifyBackoff, notifyMaxTries
	notifyTimeout, notifyMaxTries = timeout, 2
	notifyBackoff = func(int) time.Duration { return 5 * time.Millisecond }
	t.Cleanup(func() { notifyTimeout, notifyBackoff, notifyMaxTries = oldT, oldB, oldN })
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
