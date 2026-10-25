package handlers

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/metrics"
)

// Notification limits.
//
// Every WAF block and every failed sign-in used to become one alert to every
// channel, and the only brake was the queues overflowing, which drops at
// random: a scanner blocked 1,000 times sent 1,000 Telegram messages, and
// Telegram's own 429s then lost the ones that mattered. The queue's dispatcher
// is the one place both sources pass through, so the brakes live there:
//
//  1. Grouping. Events share a group when they have the same event_type and
//     client_ip. The first event of a group is delivered at once; the others
//     that arrive within the window are counted, not delivered (for a WAF
//     block, by category). When the window ends, one digest reports what was
//     counted, if anything was, and the group is forgotten: the next event
//     from that address is delivered at once again.
//  2. A cap per channel: at most notify_max_per_hour deliveries to one channel
//     in any rolling hour, digests included. Past it the channel holds
//     everything and counts it, and once one of its counted deliveries is an
//     hour old it sends a single notice with the count instead, then carries
//     on. Each channel has its own budget, so a channel that is configured
//     later, or one an operator reads less, is not starved by the others.
//
// The test alert does not travel this path (TestNotification delivers
// directly), so it is never grouped or capped.
//
// The state is in memory and owned by the dispatcher goroutine: nothing here
// locks. A graceful shutdown delivers the open digests and notices
// (notifyLimiter.flushAll); a crash loses them.

// The settings that tune the limits, and their defaults when nothing usable is
// stored (database.seedDefaultSettings stores the same values).
const (
	settingGroupWindow        = "notify_group_window_minutes"
	settingMaxPerHour         = "notify_max_per_hour"
	settingNotifyWAFBlock     = "notify_waf_block"
	settingNotifyLoginFailure = "notify_login_failure"
	settingMinLevel           = "notify_min_level"

	defaultGroupWindowMinutes = 10
	defaultMaxPerHour         = 20
	maxGroupWindowMinutes     = 1440
	maxMaxPerHour             = 1000
)

// alertLevels orders the levels an event carries. An event with no level, or
// one not listed, counts as info.
var alertLevels = map[string]int{"info": 0, "warning": 1, "error": 2}

// levelName is the inverse of alertLevels.
var levelName = []string{"info", "warning", "error"}

// eventTypeSwitch is the setting that switches an event type off, for the
// types that have one.
var eventTypeSwitch = map[string]string{
	"waf_block":     settingNotifyWAFBlock,
	"login_failure": settingNotifyLoginFailure,
}

// Bounds on what the limiter holds, so a flood from many addresses costs
// bounded memory. Past maxNotifyGroups, a new address joins its event type's
// overflow group, which reports "other addresses"; past maxGroupCategories, a
// new category is counted as other.
const (
	maxNotifyGroups    = 10000
	maxGroupCategories = 32
	// digestTopCategories is how many categories a digest names before it
	// sums the rest.
	digestTopCategories = 3
)

// notifyLimits are the limits in force, read from the settings on each event.
type notifyLimits struct {
	window     time.Duration
	maxPerHour int
	off        map[string]bool // event types switched off
	minLevel   int
}

// parseBoundedInt reads a whole number in [lo, hi], or reports false.
func parseBoundedInt(v string, lo, hi int) (int, bool) {
	if !digitsRE.MatchString(v) {
		return 0, false
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < lo || n > hi {
		return 0, false
	}
	return n, true
}

// limitsFrom reads the limits from the notification settings. A value that is
// missing or out of range (an older install, a hand-edited row) falls back to
// its default rather than switching the limit off.
func limitsFrom(settings map[string]string) notifyLimits {
	l := notifyLimits{
		window:     defaultGroupWindowMinutes * time.Minute,
		maxPerHour: defaultMaxPerHour,
		off:        map[string]bool{},
	}
	if n, ok := parseBoundedInt(settings[settingGroupWindow], 1, maxGroupWindowMinutes); ok {
		l.window = time.Duration(n) * time.Minute
	}
	if n, ok := parseBoundedInt(settings[settingMaxPerHour], 1, maxMaxPerHour); ok {
		l.maxPerHour = n
	}
	for eventType, key := range eventTypeSwitch {
		if settings[key] == "false" {
			l.off[eventType] = true
		}
	}
	l.minLevel = alertLevels[settings[settingMinLevel]]
	return l
}

// wants reports whether the operator asked for this event at all: its type is
// not switched off and its level reaches the minimum.
func (l notifyLimits) wants(event map[string]any) bool {
	if l.off[eventString(event, "event_type")] {
		return false
	}
	return alertLevels[eventString(event, "level")] >= l.minLevel
}

// eventString is an event field as text, empty when absent.
func eventString(event map[string]any, key string) string {
	v, ok := event[key]
	if !ok || v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}

// alertGroup counts the events of one event_type and client_ip after the
// first, until its window closes.
type alertGroup struct {
	eventType string
	clientIP  string
	overflow  bool // the group of addresses past maxNotifyGroups
	opened    time.Time
	closes    time.Time
	held      int
	level     int
	// categories counts the held WAF blocks by category.
	categories map[string]int
}

// channelBudget is one channel's deliveries in the last hour and what it is
// holding back.
type channelBudget struct {
	sent []time.Time // oldest first, pruned to the last hour
	held int
}

// notifyLimiter applies the grouping and the per-channel cap. It is used by
// one goroutine (the queue's dispatcher) and does not lock.
type notifyLimiter struct {
	now      func() time.Time
	groups   map[string]*alertGroup
	channels map[string]*channelBudget
}

func newNotifyLimiter(now func() time.Time) *notifyLimiter {
	return &notifyLimiter{now: now, groups: map[string]*alertGroup{}, channels: map[string]*channelBudget{}}
}

func groupKey(eventType, clientIP string) string { return eventType + "\x00" + clientIP }

// admit takes one event the operator wants and returns what to deliver now:
// the event itself when it opens a group, nothing when it is counted into an
// open one. A group whose window has closed is reported first (its digest),
// so the answer does not depend on when the last flush ran.
func (n *notifyLimiter) admit(event map[string]any, l notifyLimits) []map[string]any {
	now := n.now()
	eventType, clientIP := eventString(event, "event_type"), eventString(event, "client_ip")
	key := groupKey(eventType, clientIP)
	out := n.closeIfDue(key, now, nil)
	overflow := false
	if _, open := n.groups[key]; !open && len(n.groups) >= maxNotifyGroups {
		// One overflow group per event type that has a switch, and one for
		// every other type, so the overflow is bounded too.
		if _, known := eventTypeSwitch[eventType]; !known {
			eventType = "other"
		}
		key, overflow = groupKey(eventType, "\x00overflow"), true
		out = n.closeIfDue(key, now, out)
	}
	g, open := n.groups[key]
	if !open {
		g = &alertGroup{eventType: eventType, overflow: overflow, opened: now, closes: now.Add(l.window), categories: map[string]int{}}
		if !overflow {
			g.clientIP = clientIP
		}
		n.groups[key] = g
		return append(out, event)
	}
	g.count(event)
	metrics.NotificationHeld("grouped")
	return out
}

// closeIfDue appends the digest of the group at key when its window has
// closed, and forgets the group.
func (n *notifyLimiter) closeIfDue(key string, now time.Time, out []map[string]any) []map[string]any {
	g, ok := n.groups[key]
	if !ok || now.Before(g.closes) {
		return out
	}
	if g.held > 0 {
		out = append(out, g.digest(now))
	}
	delete(n.groups, key)
	return out
}

// count adds one held event to the group.
func (g *alertGroup) count(event map[string]any) {
	g.held++
	if lvl := alertLevels[eventString(event, "level")]; lvl > g.level {
		g.level = lvl
	}
	if g.eventType != "waf_block" {
		return
	}
	cat := eventString(event, "category")
	if cat == "" {
		cat = "UNKNOWN"
	}
	if _, seen := g.categories[cat]; !seen && len(g.categories) >= maxGroupCategories {
		cat = "other"
	}
	g.categories[cat]++
}

// expire returns the digests of the groups whose window has closed and forgets
// those groups, whether or not they held anything.
func (n *notifyLimiter) expire() []map[string]any {
	now := n.now()
	var out []map[string]any
	for _, key := range n.sortedGroupKeys() {
		out = n.closeIfDue(key, now, out)
	}
	return out
}

// flushAll returns the digest of every group that holds something and
// forgets every group: the shutdown path, so a restart does not lose them.
func (n *notifyLimiter) flushAll() []map[string]any {
	now := n.now()
	var out []map[string]any
	for _, key := range n.sortedGroupKeys() {
		if g := n.groups[key]; g.held > 0 {
			out = append(out, g.digest(now))
		}
	}
	n.groups = map[string]*alertGroup{}
	return out
}

// sortedGroupKeys keeps the digests of one flush in a stable order.
func (n *notifyLimiter) sortedGroupKeys() []string {
	keys := make([]string, 0, len(n.groups))
	for k := range n.groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// allow reports whether one delivery may go to channel now, and records it
// when it may. A channel at its cap, or one still holding deliveries back,
// holds this one too and counts it.
func (n *notifyLimiter) allow(channel string, l notifyLimits) bool {
	now := n.now()
	b := n.budget(channel, now)
	if b.held == 0 && len(b.sent) < l.maxPerHour {
		b.sent = append(b.sent, now)
		return true
	}
	b.held++
	metrics.NotificationHeld("cap")
	return false
}

// budget is channel's budget with the deliveries older than an hour removed.
func (n *notifyLimiter) budget(channel string, now time.Time) *channelBudget {
	b, ok := n.channels[channel]
	if !ok {
		b = &channelBudget{}
		n.channels[channel] = b
	}
	cutoff := now.Add(-time.Hour)
	i := 0
	for i < len(b.sent) && !b.sent[i].After(cutoff) {
		i++
	}
	b.sent = b.sent[i:]
	return b
}

// notices returns, by channel, the count of deliveries held back on each
// channel that may send again: one of its counted deliveries has turned an
// hour old. The notice takes that slot, so it counts towards the cap, and the
// channel stops holding. With final set (shutdown) every channel that holds
// something gets its notice, whether or not it has room.
func (n *notifyLimiter) notices(l notifyLimits, final bool) map[string]int {
	now := n.now()
	out := map[string]int{}
	for channel := range n.channels {
		b := n.budget(channel, now)
		if b.held == 0 || (!final && len(b.sent) >= l.maxPerHour) {
			continue
		}
		out[channel] = b.held
		b.held = 0
		b.sent = append(b.sent, now)
	}
	return out
}

// holding reports whether any channel holds deliveries back.
func (n *notifyLimiter) holding() bool {
	for _, b := range n.channels {
		if b.held > 0 {
			return true
		}
	}
	return false
}

// forgetHeld drops the held-back counts: alerts were switched off, so there is
// nothing to report them to.
func (n *notifyLimiter) forgetHeld() {
	for _, b := range n.channels {
		b.held = 0
	}
}

// digest is the event that reports what a group held.
func (g *alertGroup) digest(now time.Time) map[string]any {
	window := g.closes.Sub(g.opened)
	span := now.Sub(g.opened)
	if span > window {
		span = window
	}
	minutes := int(math.Ceil(span.Minutes()))
	if minutes < 1 {
		minutes = 1
	}
	from := "from " + g.clientIP
	switch {
	case g.overflow:
		from = "from other addresses"
	case g.clientIP == "":
		from = "from an unknown address"
	}
	period := fmt.Sprintf("in the last %d minutes", minutes)
	if minutes == 1 {
		period = "in the last minute"
	}
	var msg string
	switch g.eventType {
	case "waf_block":
		msg = fmt.Sprintf("WAF blocked %d more %s %s %s: %s",
			g.held, plural(g.held, "request", "requests"), from, period, categorySummary(g.categories))
	case "login_failure":
		msg = fmt.Sprintf("%d more failed %s %s %s", g.held, plural(g.held, "sign-in", "sign-ins"), from, period)
	default:
		msg = fmt.Sprintf("%d more %s %s %s %s", g.held, g.eventType, plural(g.held, "alert", "alerts"), from, period)
	}
	ev := map[string]any{
		"timestamp":      now.Format(time.RFC3339),
		"event_type":     g.eventType + "_digest",
		"message":        msg,
		"level":          levelName[g.level],
		"count":          g.held,
		"window_minutes": minutes,
	}
	if !g.overflow && g.clientIP != "" {
		ev["client_ip"] = g.clientIP
	}
	if len(g.categories) > 0 {
		counts := make(map[string]int, len(g.categories))
		for k, v := range g.categories {
			counts[k] = v
		}
		ev["category_counts"] = counts
	}
	return ev
}

// categorySummary names the most frequent categories with their counts and
// sums the rest: "SQLI 380, XSS 32, other 4".
func categorySummary(counts map[string]int) string {
	type kv struct {
		name string
		n    int
	}
	list := make([]kv, 0, len(counts))
	for k, v := range counts {
		list = append(list, kv{k, v})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].n != list[j].n {
			return list[i].n > list[j].n
		}
		return list[i].name < list[j].name
	})
	var parts []string
	rest := 0
	for i, c := range list {
		// With one category left over, naming it is as short as "other".
		if i < digestTopCategories || len(list) == digestTopCategories+1 {
			parts = append(parts, fmt.Sprintf("%s %d", c.name, c.n))
			continue
		}
		rest += c.n
	}
	if rest > 0 {
		parts = append(parts, fmt.Sprintf("other %d", rest))
	}
	return strings.Join(parts, ", ")
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// heldNotice is the event that reports a channel's held-back deliveries.
func heldNotice(count int, now time.Time) map[string]any {
	return map[string]any{
		"timestamp":  now.Format(time.RFC3339),
		"event_type": "alerts_held_back",
		"message":    fmt.Sprintf("%d %s held back in the last hour; see Analytics and the Audit log", count, plural(count, "alert", "alerts")),
		"level":      "warning",
		"count":      count,
	}
}
