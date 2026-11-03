package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// resetDeliveries empties the record for one test and puts it back after.
func resetDeliveries(t *testing.T) {
	t.Helper()
	deliveries.Lock()
	prev := deliveries.m
	deliveries.m = map[string]*channelStatus{}
	deliveries.Unlock()
	t.Cleanup(func() {
		deliveries.Lock()
		deliveries.m = prev
		deliveries.Unlock()
	})
}

// A channel that stops working shows on the status, with why, and a later
// success clears the flag but keeps the last error.
func TestNotificationStatusSaysWhichChannelFailedAndWhy(t *testing.T) {
	resetDeliveries(t)
	fastNotify(t, time.Second)
	var fail atomic.Bool
	fail.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	d := delivery{channel: "webhook", url: srv.URL, body: []byte(`{}`)}

	status := func() map[string]channelStatus {
		w := httptest.NewRecorder()
		(&SecurityHandlers{}).NotificationStatus(w, httptest.NewRequest("GET", "/api/notifications/status", nil))
		var body struct {
			Data struct {
				Since    string                   `json:"since"`
				Channels map[string]channelStatus `json:"channels"`
			} `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if _, err := time.Parse(time.RFC3339, body.Data.Since); err != nil {
			t.Errorf("since = %q: %v", body.Data.Since, err)
		}
		return body.Data.Channels
	}

	if len(status()) != 0 {
		t.Fatal("a channel is listed before any delivery")
	}
	d.sendTries(notifyHTTPClient(), 1)
	s := status()["webhook"]
	if !s.LastFailed || s.Failed != 1 || s.Delivered != 0 || s.LastError != describeDeliveryStatus(401) || s.LastErrorAt == nil || s.LastDelivered != nil {
		t.Errorf("after a 401: %+v", s)
	}
	fail.Store(false)
	d.sendTries(notifyHTTPClient(), 1)
	s = status()["webhook"]
	if s.LastFailed || s.Delivered != 1 || s.Failed != 1 || s.LastDelivered == nil || s.LastError == "" {
		t.Errorf("after a success: %+v; want last_failed false, the 401 kept as the last error", s)
	}
}

// A delivery dropped because the channel's queue is full is a failure too.
func TestADroppedDeliveryIsRecorded(t *testing.T) {
	resetDeliveries(t)
	f := &notifyFanout{queues: map[string]chan delivery{"gotify": make(chan delivery)}}
	f.submit(delivery{channel: "gotify"})
	_, m := deliveryStatus()
	if s := m["gotify"]; !s.LastFailed || s.Failed != 1 || s.LastError == "" {
		t.Errorf("dropped delivery = %+v; want a recorded failure", s)
	}
}
