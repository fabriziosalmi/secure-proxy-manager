package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/metrics"
)

// fakeClock is the limiter's clock in tests: it moves only when told to.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

var defaultLimits = limitsFrom(map[string]string{})

func wafBlock(ip, category string) map[string]any {
	return map[string]any{"event_type": "waf_block", "level": "error", "message": "WAF blocked URL", "client_ip": ip, "category": category}
}

// The categories of the 999 blocks after the first, in the test below.
var floodCategories = []struct {
	name string
	n    int
}{{"SQLI", 600}, {"XSS", 300}, {"LFI", 50}, {"RCE", 30}, {"SCAN", 19}}

// floodFrom is the first block (SQLI) and then 999 more from ip, in the order
// of floodCategories.
func floodFrom(ip string) []map[string]any {
	out := []map[string]any{wafBlock(ip, "SQLI")}
	for _, c := range floodCategories {
		for i := 0; i < c.n; i++ {
			out = append(out, wafBlock(ip, c.name))
		}
	}
	return out
}

// A scanner blocked 1,000 times in one minute is one alert at once and one
// digest when the window ends, with the count and the categories.
func TestAFloodFromOneAddressIsOneAlertAndOneDigest(t *testing.T) {
	clock := newFakeClock()
	lim := newNotifyLimiter(clock.Now)
	heldBefore := metrics.NotificationsHeldCount("grouped", metrics.HeldAllChannels)

	immediate := 0
	for _, ev := range floodFrom("203.0.113.5") {
		immediate += len(lim.admit(ev, defaultLimits))
		clock.Advance(60 * time.Millisecond) // 1,000 events in 60 s
	}
	if immediate != 1 {
		t.Fatalf("%d alerts delivered at once, want 1", immediate)
	}
	if got := metrics.NotificationsHeldCount("grouped", metrics.HeldAllChannels) - heldBefore; got != 999 {
		t.Errorf("held back (grouped, all) went up by %v, want 999", got)
	}
	// One second before the window closes: nothing yet.
	clock.Advance(10*time.Minute - 60*time.Second - time.Second)
	if d := lim.expire(); len(d) != 0 {
		t.Fatalf("a digest before the window closed: %v", d)
	}
	clock.Advance(time.Second)
	digests := lim.expire()
	if len(digests) != 1 {
		t.Fatalf("%d digests when the window closed, want 1", len(digests))
	}
	d := digests[0]
	if d["count"] != 999 || d["event_type"] != "waf_block_digest" || d["client_ip"] != "203.0.113.5" || d["level"] != "error" {
		t.Errorf("digest = %v", d)
	}
	want := "WAF blocked 999 more requests from 203.0.113.5 in the last 10 minutes: SQLI 600, XSS 300, LFI 50, other 49"
	if d["message"] != want {
		t.Errorf("message = %q\nwant      %q", d["message"], want)
	}
	counts, _ := d["category_counts"].(map[string]int)
	for _, c := range floodCategories {
		if counts[c.name] != c.n {
			t.Errorf("category_counts[%s] = %d, want %d", c.name, counts[c.name], c.n)
		}
	}
	// The group is forgotten: the next block from that address is new.
	if got := lim.admit(wafBlock("203.0.113.5", "XSS"), defaultLimits); len(got) != 1 {
		t.Errorf("after the digest the next block gave %d alerts, want 1", len(got))
	}
}

func TestTwoAddressesAreGroupedApart(t *testing.T) {
	clock := newFakeClock()
	lim := newNotifyLimiter(clock.Now)
	immediate := 0
	for i := 0; i < 10; i++ {
		immediate += len(lim.admit(wafBlock("198.51.100.1", "SQLI"), defaultLimits))
		immediate += len(lim.admit(wafBlock("198.51.100.2", "XSS"), defaultLimits))
		clock.Advance(time.Second)
	}
	if immediate != 2 {
		t.Fatalf("%d alerts at once, want one per address", immediate)
	}
	clock.Advance(10 * time.Minute)
	digests := lim.expire()
	if len(digests) != 2 {
		t.Fatalf("%d digests, want 2", len(digests))
	}
	for _, d := range digests {
		if d["count"] != 9 {
			t.Errorf("digest for %v counts %v, want 9", d["client_ip"], d["count"])
		}
	}
	if digests[0]["client_ip"] == digests[1]["client_ip"] {
		t.Errorf("both digests are for %v", digests[0]["client_ip"])
	}
}

// A failed sign-in groups by address, and its digest says what it counts.
func TestFailedSignInsAreGroupedByAddress(t *testing.T) {
	clock := newFakeClock()
	lim := newNotifyLimiter(clock.Now)
	ev := map[string]any{"event_type": "login_failure", "level": "warning", "message": "m", "client_ip": "192.0.2.7", "username": "admin"}
	n := 0
	for i := 0; i < 6; i++ {
		n += len(lim.admit(ev, defaultLimits))
	}
	clock.Advance(3 * time.Minute)
	d := lim.flushAll()
	if n != 1 || len(d) != 1 || d[0]["message"] != "5 more failed sign-ins from 192.0.2.7 in the last 3 minutes" {
		t.Errorf("immediate %d, digests %v", n, d)
	}
}

// At most 20 deliveries per channel in any hour; past that one notice, when
// the channel may send again, with the count.
func TestTheCapHoldsPerChannelWithOneNotice(t *testing.T) {
	clock := newFakeClock()
	lim := newNotifyLimiter(clock.Now)
	heldWebhook := metrics.NotificationsHeldCount("cap", "webhook")
	heldTelegram := metrics.NotificationsHeldCount("cap", "telegram")
	heldAll := metrics.NotificationsHeldCount("cap", metrics.HeldAllChannels)
	sent := map[string]int{}
	for i := 0; i < 50; i++ {
		for _, ev := range lim.admit(wafBlock(fmt.Sprintf("192.0.2.%d", i), "SQLI"), defaultLimits) {
			_ = ev
			for _, ch := range []string{"webhook", "telegram"} {
				if lim.allow(ch, defaultLimits) {
					sent[ch]++
				}
			}
		}
		clock.Advance(time.Second)
	}
	if sent["webhook"] != 20 || sent["telegram"] != 20 {
		t.Fatalf("sent %v, want 20 per channel", sent)
	}
	// Counted on the channel that held it, never on channel="all".
	if got := metrics.NotificationsHeldCount("cap", "webhook") - heldWebhook; got != 30 {
		t.Errorf("held back (cap, webhook) went up by %v, want 30", got)
	}
	if got := metrics.NotificationsHeldCount("cap", "telegram") - heldTelegram; got != 30 {
		t.Errorf("held back (cap, telegram) went up by %v, want 30", got)
	}
	if got := metrics.NotificationsHeldCount("cap", metrics.HeldAllChannels) - heldAll; got != 0 {
		t.Errorf("held back (cap, all) went up by %v, want 0", got)
	}
	clock.Advance(30 * time.Minute)
	if n := lim.notices(defaultLimits, false); len(n) != 0 {
		t.Fatalf("a notice while the hour is still full: %v", n)
	}
	// The first delivery was at +0 s; at +1 h 1 s it is more than an hour old.
	clock.Advance(time.Hour + time.Second - 50*time.Second - 30*time.Minute)
	n := lim.notices(defaultLimits, false)
	if len(n) != 2 || n["webhook"] != 30 || n["telegram"] != 30 {
		t.Fatalf("notices = %v, want 30 for each channel", n)
	}
	if again := lim.notices(defaultLimits, false); len(again) != 0 {
		t.Errorf("a second notice: %v", again)
	}
	msg := heldNotice(30, clock.Now())["message"]
	if msg != "30 alerts held back in the last hour; see Analytics and the Audit log" {
		t.Errorf("notice = %q", msg)
	}
	// The channel sends again, and the notice took a slot of the hour.
	if !lim.allow("webhook", defaultLimits) {
		t.Error("after the notice the channel still holds")
	}
	b := lim.budget("webhook", clock.Now())
	if len(b.sent) != 20 {
		t.Errorf("%d deliveries in the hour after the notice, want 20 (18 left, the notice, this one)", len(b.sent))
	}
}

// Once over the cap a channel sends nothing until its notice has gone out,
// even when a slot of the hour frees up first.
func TestAChannelHoldsEverythingUntilItsNotice(t *testing.T) {
	clock := newFakeClock()
	lim := newNotifyLimiter(clock.Now)
	limits := limitsFrom(map[string]string{settingMaxPerHour: "2"})
	for i := 0; i < 3; i++ {
		lim.allow("webhook", limits)
	}
	clock.Advance(time.Hour + time.Second)
	if lim.allow("webhook", limits) {
		t.Fatal("a delivery went out ahead of the held-back notice")
	}
	if n := lim.notices(limits, false); n["webhook"] != 2 {
		t.Errorf("notices = %v, want 2 held on the webhook", n)
	}
	if !lim.allow("webhook", limits) {
		t.Error("after the notice the channel still holds")
	}
}

// One channel at its cap does not hold another back.
func TestOneChannelAtItsCapDoesNotHoldAnother(t *testing.T) {
	clock := newFakeClock()
	lim := newNotifyLimiter(clock.Now)
	limits := limitsFrom(map[string]string{settingMaxPerHour: "2"})
	for i := 0; i < 3; i++ {
		lim.allow("webhook", limits)
	}
	if !lim.allow("ntfy", limits) {
		t.Error("ntfy was held because the webhook reached its cap")
	}
}

func TestOffTypesAndLowLevelsAreNotSent(t *testing.T) {
	off := limitsFrom(map[string]string{settingNotifyWAFBlock: "false"})
	if off.wants(wafBlock("192.0.2.1", "SQLI")) {
		t.Error("a WAF block was wanted with WAF blocks off")
	}
	login := map[string]any{"event_type": "login_failure", "level": "warning"}
	if !off.wants(login) {
		t.Error("turning WAF blocks off turned failed sign-ins off")
	}
	errorsOnly := limitsFrom(map[string]string{settingMinLevel: "error"})
	if errorsOnly.wants(login) || !errorsOnly.wants(wafBlock("192.0.2.1", "SQLI")) {
		t.Error("with errors only, a warning was wanted or an error was not")
	}
	if limitsFrom(map[string]string{settingNotifyLoginFailure: "false"}).wants(login) {
		t.Error("a failed sign-in was wanted with failed sign-ins off")
	}
}

// A value out of range in the database is read as the default, not as no
// limit.
func TestUnusableStoredLimitsFallBackToTheDefaults(t *testing.T) {
	l := limitsFrom(map[string]string{settingGroupWindow: "0", settingMaxPerHour: "99999"})
	if l.window != 10*time.Minute || l.maxPerHour != 20 {
		t.Errorf("limits = %+v, want the defaults", l)
	}
	l = limitsFrom(map[string]string{settingGroupWindow: "1440", settingMaxPerHour: "1000"})
	if l.window != 1440*time.Minute || l.maxPerHour != 1000 {
		t.Errorf("limits = %+v, want the stored bounds", l)
	}
}

// Past maxNotifyGroups addresses, a new one joins its type's overflow group,
// so a flood from many addresses costs bounded memory.
func TestManyAddressesShareAnOverflowGroup(t *testing.T) {
	clock := newFakeClock()
	lim := newNotifyLimiter(clock.Now)
	immediate := 0
	for i := 0; i < maxNotifyGroups+5; i++ {
		immediate += len(lim.admit(wafBlock(fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255), "SCAN"), defaultLimits))
	}
	if len(lim.groups) != maxNotifyGroups+1 {
		t.Errorf("%d groups, want %d", len(lim.groups), maxNotifyGroups+1)
	}
	if immediate != maxNotifyGroups+1 {
		t.Errorf("%d immediate, want one per group", immediate)
	}
	clock.Advance(10 * time.Minute)
	digests := lim.expire()
	if len(digests) != 1 || digests[0]["count"] != 4 || !strings.Contains(digests[0]["message"].(string), "from other addresses") {
		t.Errorf("digests = %v", digests)
	}
	if len(lim.groups) != 0 {
		t.Errorf("%d groups left after the window", len(lim.groups))
	}
}

func TestTheNotificationLimitsAreValidated(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewSettingsHandlers(db, cfg)
	post := func(body map[string]string) (int, map[string]string) {
		b, _ := json.Marshal(body)
		w := httptest.NewRecorder()
		h.BulkUpdate(w, httptest.NewRequest("POST", "/api/settings", bytes.NewReader(b)))
		var resp struct {
			Errors map[string]string `json:"errors"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		return w.Code, resp.Errors
	}
	for _, bad := range []map[string]string{
		{settingGroupWindow: "0"}, {settingGroupWindow: "1441"}, {settingGroupWindow: "10.5"}, {settingGroupWindow: "ten"}, {settingGroupWindow: ""},
		{settingMaxPerHour: "0"}, {settingMaxPerHour: "1001"}, {settingMaxPerHour: "-5"},
		{settingNotifyWAFBlock: "yes"}, {settingNotifyLoginFailure: "1"},
		{settingMinLevel: "debug"}, {settingMinLevel: ""},
	} {
		code, errs := post(bad)
		for k := range bad {
			if code != http.StatusBadRequest || errs[k] == "" {
				t.Errorf("%v: %d %v, want 400 naming %s", bad, code, errs, k)
			}
		}
	}
	code, errs := post(map[string]string{
		settingGroupWindow: "1440", settingMaxPerHour: "1000", settingNotifyWAFBlock: "false",
		settingNotifyLoginFailure: "true", settingMinLevel: "warning",
	})
	if code != http.StatusOK {
		t.Errorf("the bounds were refused: %d %v", code, errs)
	}
	if code, _ := post(map[string]string{settingGroupWindow: "1", settingMaxPerHour: "1"}); code != http.StatusOK {
		t.Errorf("the lower bounds were refused: %d", code)
	}
}

// Every install starts with the limits stored, so the page shows what applies.
func TestTheNotificationLimitsAreSeeded(t *testing.T) {
	db, _, _, cleanup := setupTestDB(t)
	defer cleanup()
	want := map[string]string{
		settingGroupWindow: "10", settingMaxPerHour: "20", settingNotifyWAFBlock: "true",
		settingNotifyLoginFailure: "true", settingMinLevel: "info",
	}
	for k, v := range want {
		var got string
		if err := db.QueryRow("SELECT setting_value FROM settings WHERE setting_name=?", k).Scan(&got); err != nil || got != v {
			t.Errorf("%s = %q (%v), want %q", k, got, err, v)
		}
		if validateSettingValue(k, v) != nil {
			t.Errorf("the seeded %s=%q does not pass its own validator", k, v)
		}
	}
}
