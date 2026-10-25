package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/models"
)

// The notification limits (notify_limit.go) through the queue: a fake clock,
// a tick the test sends, and a recording webhook behind the production
// fan-out, fed through ReceiveAlert as the WAF feeds it.

// recorder is a webhook endpoint that keeps what it received.
type recorder struct {
	mu     sync.Mutex
	bodies []map[string]any
	srv    *httptest.Server
}

func newRecorder(t *testing.T) *recorder {
	r := &recorder{}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		r.mu.Lock()
		r.bodies = append(r.bodies, m)
		r.mu.Unlock()
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *recorder) received() []map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]map[string]any(nil), r.bodies...)
}

// queueRig is a notification queue with a fake clock and a tick the test
// sends, delivering to a recording webhook through the production fan-out.
type queueRig struct {
	q      NotifyQueue
	tick   chan time.Time
	clock  *fakeClock
	cancel context.CancelFunc
	hook   *recorder
}

func newQueueRig(t *testing.T, extra map[string]string) (*queueRig, *SecurityHandlers) {
	t.Helper()
	db, _, cfg, cleanup := setupTestDB(t)
	t.Cleanup(cleanup)
	// The production client refuses loopback (netguard.NotifyClient), and the
	// settings API refuses a loopback URL: fastNotify swaps the client for
	// this test only, and the URL goes straight into the table.
	fastNotify(t, 2*time.Second)
	hook := newRecorder(t)
	settings := map[string]string{"enable_notifications": "true", "webhook_url": hook.srv.URL}
	for k, v := range extra {
		settings[k] = v
	}
	for k, v := range settings {
		if _, err := db.Exec("INSERT OR REPLACE INTO settings(setting_name,setting_value) VALUES(?,?)", k, v); err != nil {
			t.Fatal(err)
		}
	}
	rig := &queueRig{tick: make(chan time.Time), clock: newFakeClock(), hook: hook}
	ctx, cancel := context.WithCancel(context.Background())
	rig.cancel = cancel
	rig.q = startNotifyQueue(ctx, db, "0000000000000000000000000000000000000000000000000000000000000000", rig.clock.Now, rig.tick, nil)
	t.Cleanup(func() { cancel(); waitForWorkers(t) })
	return rig, NewSecurityHandlers(db, nil, cfg, rig.q)
}

// sync returns once the dispatcher has handled everything queued before it:
// the first tick drains the queue, and the second is received only after the
// first one's work is done.
func (r *queueRig) sync() {
	r.tick <- r.clock.Now()
	r.tick <- r.clock.Now()
}

// stop shuts the queue down and waits until every delivery is made.
func (r *queueRig) stop(t *testing.T) []map[string]any {
	t.Helper()
	r.cancel()
	waitForWorkers(t)
	return r.hook.received()
}

func postAlert(t *testing.T, h *SecurityHandlers, a models.InternalAlert) {
	t.Helper()
	b, _ := json.Marshal(a)
	w := httptest.NewRecorder()
	h.ReceiveAlert(w, httptest.NewRequest("POST", "/api/internal/alert", bytes.NewReader(b)))
	if w.Code != http.StatusOK {
		t.Fatalf("ReceiveAlert answered %d", w.Code)
	}
}

func blockFrom(ip, category string) models.InternalAlert {
	return models.InternalAlert{EventType: "waf_block", Message: "WAF blocked URL", Level: "error",
		Details: map[string]any{"client_ip": ip, "category": category}}
}

// The WAF's 1,000 posts for one scanner reach the webhook as one alert and,
// when the window ends, one digest.
func TestAFloodThroughReceiveAlertReachesTheWebhookTwice(t *testing.T) {
	rig, h := newQueueRig(t, nil)
	for i, ev := range floodFrom("203.0.113.5") {
		postAlert(t, h, blockFrom(ev["client_ip"].(string), ev["category"].(string)))
		// The queue holds 256: let the dispatcher catch up, as it does in
		// production between the WAF's posts.
		if i%100 == 99 {
			rig.sync()
		}
		rig.clock.Advance(60 * time.Millisecond)
	}
	rig.sync()
	rig.clock.Advance(10 * time.Minute)
	rig.sync()
	got := rig.stop(t)
	if len(got) != 2 {
		t.Fatalf("the webhook received %d posts, want 2: %v", len(got), got)
	}
	if got[0]["event_type"] != "waf_block" || got[0]["client_ip"] != "203.0.113.5" {
		t.Errorf("first post = %v", got[0])
	}
	d := got[1]
	if d["event_type"] != "waf_block_digest" || d["count"] != float64(999) {
		t.Errorf("second post = %v, want the digest counting 999", d)
	}
	counts, _ := d["category_counts"].(map[string]any)
	for _, c := range floodCategories {
		if counts[c.name] != float64(c.n) {
			t.Errorf("category_counts[%s] = %v, want %d", c.name, counts[c.name], c.n)
		}
	}
}

// A graceful shutdown delivers the digest that was still counting.
func TestShutdownDeliversTheOpenDigest(t *testing.T) {
	rig, h := newQueueRig(t, nil)
	for i := 0; i < 3; i++ {
		postAlert(t, h, blockFrom("192.0.2.9", "XSS"))
	}
	rig.sync()
	got := rig.stop(t)
	if len(got) != 2 || got[1]["event_type"] != "waf_block_digest" || got[1]["count"] != float64(2) {
		t.Fatalf("posts = %v, want the alert and a digest counting 2", got)
	}
}

// The cap holds through the queue, the notice follows when the hour turns,
// and the test alert goes through regardless.
func TestTheCapHoldsThroughTheQueueAndTheTestAlertBypassesIt(t *testing.T) {
	rig, h := newQueueRig(t, map[string]string{settingMaxPerHour: "3"})
	for i := 0; i < 5; i++ {
		postAlert(t, h, blockFrom(fmt.Sprintf("192.0.2.%d", i+1), "SQLI"))
	}
	rig.sync()

	// The channel is at its cap and holding; the test alert, twice in a row
	// (so grouping would hold the second), is delivered both times.
	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		h.TestNotification(w, httptest.NewRequest("POST", "/api/notifications/test", nil))
		if !strings.Contains(w.Body.String(), `"delivered":true`) {
			t.Fatalf("test alert %d was not delivered: %s", i+1, w.Body.String())
		}
	}

	rig.clock.Advance(time.Hour + time.Second)
	rig.sync()
	got := rig.stop(t)
	var alerts, tests, notices int
	var notice map[string]any
	for _, b := range got {
		switch b["event_type"] {
		case "waf_block":
			alerts++
		case "notification_test":
			tests++
		case "alerts_held_back":
			notices++
			notice = b
		}
	}
	if alerts != 3 || tests != 2 || notices != 1 {
		t.Fatalf("alerts %d (want 3), tests %d (want 2), notices %d (want 1): %v", alerts, tests, notices, got)
	}
	if notice["message"] != "2 alerts held back in the last hour; see Analytics and the Audit log" {
		t.Errorf("notice = %v", notice["message"])
	}
}

// A digest is a delivery like any other: it counts towards the cap.
func TestDigestsCountTowardsTheCap(t *testing.T) {
	rig, h := newQueueRig(t, map[string]string{settingMaxPerHour: "1"})
	for i := 0; i < 2; i++ {
		postAlert(t, h, blockFrom("192.0.2.1", "SQLI"))
	}
	rig.sync()
	rig.clock.Advance(10 * time.Minute) // the digest is due, the hour is full
	rig.sync()
	rig.clock.Advance(time.Hour)
	rig.sync()
	got := rig.stop(t)
	if len(got) != 2 || got[0]["event_type"] != "waf_block" ||
		got[1]["event_type"] != "alerts_held_back" || got[1]["count"] != float64(1) {
		t.Fatalf("posts = %v, want the alert and a notice for the held digest", got)
	}
}

// Switched off, a type sends nothing and opens no group.
func TestAnEventTypeSwitchedOffSendsNothing(t *testing.T) {
	rig, h := newQueueRig(t, map[string]string{settingNotifyWAFBlock: "false"})
	postAlert(t, h, blockFrom("192.0.2.1", "SQLI"))
	rig.sync()
	if got := rig.stop(t); len(got) != 0 {
		t.Errorf("posts = %v, want none", got)
	}
}
