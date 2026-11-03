package handlers

import (
	"net/http"
	"sync"
	"time"
)

// What became of the alerts, per channel. A failed delivery used to reach
// only a metric and a log line, so an alert channel could stop working (an
// expired token, a moved webhook) while the Alerts page still read "on".
//
// It is kept in memory: a restart starts it over, and the answer says since
// when it counts.

// channelStatus is one channel's deliveries since the backend started.
type channelStatus struct {
	LastAttempt   *time.Time `json:"last_attempt"`
	LastDelivered *time.Time `json:"last_delivered"`
	// LastError is why the last failed delivery failed, without the URL
	// (describeDeliveryError, describeDeliveryStatus).
	LastError   string     `json:"last_error,omitempty"`
	LastErrorAt *time.Time `json:"last_error_at"`
	// LastFailed is whether the last attempt failed: what a page warns about.
	LastFailed bool `json:"last_failed"`
	Delivered  int  `json:"delivered"`
	Failed     int  `json:"failed"`
}

var deliveries = struct {
	sync.Mutex
	since time.Time
	m     map[string]*channelStatus
}{since: time.Now(), m: map[string]*channelStatus{}}

// deliveryNow is the clock of recordDelivery; a test sets it.
var deliveryNow = time.Now

// recordDelivery notes one delivery's outcome for its channel.
func recordDelivery(channel string, delivered bool, reason string) {
	at := deliveryNow()
	deliveries.Lock()
	defer deliveries.Unlock()
	s := deliveries.m[channel]
	if s == nil {
		s = &channelStatus{}
		deliveries.m[channel] = s
	}
	s.LastAttempt = &at
	s.LastFailed = !delivered
	if delivered {
		s.LastDelivered = &at
		s.Delivered++
		return
	}
	s.Failed++
	s.LastError, s.LastErrorAt = reason, &at
}

// deliveryStatus is a copy of every channel's status, and since when they count.
func deliveryStatus() (time.Time, map[string]channelStatus) {
	deliveries.Lock()
	defer deliveries.Unlock()
	out := make(map[string]channelStatus, len(deliveries.m))
	for k, v := range deliveries.m {
		out[k] = *v
	}
	return deliveries.since, out
}

// NotificationStatus answers GET /api/notifications/status: for each channel
// that was used since the backend started, when it last delivered, when and
// why it last failed, and whether its last attempt failed. Test alerts count:
// they are deliveries to the same endpoint.
func (h *SecurityHandlers) NotificationStatus(w http.ResponseWriter, r *http.Request) {
	since, channels := deliveryStatus()
	writeOK(w, map[string]any{"since": since.UTC().Format(time.RFC3339), "channels": channels})
}
