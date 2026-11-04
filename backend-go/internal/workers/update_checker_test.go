package workers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// UPDATE_CHECK=false: the checker sends nothing. On, the same setup is asked
// within the wait, so the silence is not a test that never waited long enough.
func TestUpdateCheckOffSendsNoRequest(t *testing.T) {
	prev := updateFirstCheck
	updateFirstCheck = 0
	t.Cleanup(func() { updateFirstCheck = prev })

	asked := func(enabled bool) int32 {
		var hits atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			http.NotFound(w, r)
		}))
		defer srv.Close()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		StartUpdateChecker(ctx, srv.URL+"/releases/latest", enabled)
		deadline := time.Now().Add(2 * time.Second)
		for hits.Load() == 0 && time.Now().Before(deadline) {
			time.Sleep(20 * time.Millisecond)
		}
		return hits.Load()
	}

	if n := asked(true); n == 0 {
		t.Fatal("on: no request within 2s; the test cannot tell off from slow")
	}
	if n := asked(false); n != 0 {
		t.Errorf("off: %d request(s) sent; want none", n)
	}
}
