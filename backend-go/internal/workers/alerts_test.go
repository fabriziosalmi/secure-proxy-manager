package workers

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// captureAlerts sets a sink that keeps every raised event, for one test.
func captureAlerts(t *testing.T) func() []map[string]any {
	t.Helper()
	var mu sync.Mutex
	var got []map[string]any
	prev := alertSink.Load()
	SetAlertSink(func(e map[string]any) {
		mu.Lock()
		got = append(got, e)
		mu.Unlock()
	})
	t.Cleanup(func() { alertSink.Store(prev) })
	return func() []map[string]any {
		mu.Lock()
		defer mu.Unlock()
		return append([]map[string]any(nil), got...)
	}
}

// One alert when the proxy stops answering two checks in a row, one when it
// is back, and none on a single failed check or while the state holds.
func TestProxyWatchRaisesOnceOnEachChange(t *testing.T) {
	var w proxyWatch
	var events []string
	for _, up := range []bool{true, true, false, true, false, false, false, false, true, true} {
		if typ, level, msg := w.step(up, "proxy:3128"); typ != "" {
			events = append(events, typ+"/"+level)
			if !strings.Contains(msg, "proxy:3128") {
				t.Errorf("%s message %q does not name the proxy", typ, msg)
			}
		}
	}
	if strings.Join(events, ",") != "proxy_down/error,proxy_up/info" {
		t.Errorf("events = %v; want one proxy_down then one proxy_up", events)
	}
}

// A refresh that could not download a feed says so on the alert channels,
// with the counts and without the feeds' URLs; a clean run says nothing.
func TestARefreshWithAFailedFeedRaisesAnAlert(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	got := captureAlerts(t)
	orig := fetchRefreshFeed
	t.Cleanup(func() { fetchRefreshFeed = orig })

	fetchRefreshFeed = func(u string) (string, error) { return "0.0.0.0 a.example\n1.1.1.1\n", nil }
	runRefresh(db)
	if len(got()) != 0 {
		t.Fatalf("a clean refresh raised %v", got())
	}

	fetchRefreshFeed = func(u string) (string, error) {
		if u == defaultDomainLists[1] {
			return "", errors.New("HTTP 410")
		}
		return "0.0.0.0 a.example\n1.1.1.1\n", nil
	}
	runRefresh(db)
	ev := got()
	if len(ev) != 1 || ev[0]["event_type"] != "blocklist_refresh_failed" || ev[0]["level"] != "warning" {
		t.Fatalf("alerts = %v; want one blocklist_refresh_failed warning", ev)
	}
	msg := fmt.Sprint(ev[0]["message"])
	want := fmt.Sprintf("could not download 1 of %d feeds", len(defaultIPLists)+len(defaultDomainLists))
	if !strings.Contains(msg, want) || strings.Contains(msg, "http") {
		t.Errorf("message %q; want %q and no URL", msg, want)
	}
}

// A new version is announced once, not on every check; a newer one again.
func TestAnUpdateIsAnnouncedOncePerVersion(t *testing.T) {
	got := captureAlerts(t)
	updateMu.Lock()
	prev := updateInfo
	updateInfo = UpdateInfo{}
	updateMu.Unlock()
	t.Cleanup(func() { updateMu.Lock(); updateInfo = prev; updateMu.Unlock() })

	tag := "v9.9.9"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"tag_name": %q, "html_url": "https://github.example/release"}`, tag)
	}))
	defer ts.Close()
	check(ts.URL)
	check(ts.URL)
	tag = "v9.9.10"
	check(ts.URL)
	var versions []string
	for _, e := range got() {
		if e["event_type"] != "update_available" {
			t.Errorf("unexpected event %v", e)
			continue
		}
		versions = append(versions, strings.Fields(fmt.Sprint(e["message"]))[3])
	}
	if strings.Join(versions, ",") != "v9.9.9,v9.9.10" {
		t.Errorf("announced %v; want v9.9.9 once, then v9.9.10", versions)
	}
}
