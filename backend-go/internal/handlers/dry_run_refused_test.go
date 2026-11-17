package handlers

import (
	"net/http"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
)

// snapshotWrapped lists every route r serves behind the snapshot middleware
// (snapshotBefore, snapshotBeforeFunc), as "METHOD /path".
func snapshotWrapped(t *testing.T, r chi.Router) []string {
	t.Helper()
	var out []string
	if err := chi.Walk(r, func(method, route string, _ http.Handler, mws ...func(http.Handler) http.Handler) error {
		for _, mw := range mws {
			if strings.Contains(runtime.FuncForPC(reflect.ValueOf(mw).Pointer()).Name(), "handlers.snapshotBeforeFunc.") {
				out = append(out, method+" "+chiParam.ReplaceAllString(route, "{$1}"))
				break
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	return out
}

// A settings change asked as a dry run is refused and changes nothing: the
// snapshot middleware skips the snapshot of a request that carries dry_run,
// so a handler that ignored it applied the change with no snapshot to go
// back to.
func TestASettingsDryRunChangesNothing(t *testing.T) {
	for _, c := range []struct{ method, path, body string }{
		{"PUT", "/api/settings/cache_size", `{"value":"1500"}`},
		{"POST", "/api/settings", `{"cache_size":"1500"}`},
	} {
		t.Run(c.method+" "+c.path, func(t *testing.T) {
			db, svc, cfg, cleanup := setupTestDB(t)
			defer cleanup()
			r := buildFullRouterOn(db, svc, cfg, func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					next.ServeHTTP(w, withUserContext(req, "admin"))
				})
			})
			value := func() string { return settingValue(t, db, "cache_size") }
			before, snaps := value(), snapshotCount(t, db)
			if before == "1500" {
				t.Fatal("cache_size is already 1500: the case proves nothing")
			}

			code, out := call(t, r, c.method, c.path+"?dry_run=true", c.body)
			if code != http.StatusBadRequest || out["code"] != "invalid_request" {
				t.Errorf("dry_run=true: %d %v, want 400 invalid_request", code, out)
			}
			if got := value(); got != before {
				t.Errorf("the dry run set cache_size from %q to %q", before, got)
			}
			if got := snapshotCount(t, db); got != snaps {
				t.Errorf("snapshots: %d before the dry run, %d after", snaps, got)
			}

			// The same call without dry_run is applied, after a snapshot.
			if code, out := call(t, r, c.method, c.path+"?dry_run=false", c.body); code != http.StatusOK {
				t.Fatalf("real call: %d %v", code, out)
			}
			if got := value(); got != "1500" {
				t.Errorf("the real call left cache_size at %q", got)
			}
			if got := snapshotCount(t, db); got != snaps+1 {
				t.Errorf("snapshots: %d before the real call, %d after, want one more", snaps, got)
			}
		})
	}
}

// Every route behind the snapshot middleware honours dry_run: the middleware
// takes no snapshot of a request that carries one, so the request must change
// nothing. A route that previews (dryRunOps) is held to that by
// TestADryRunChangesNothing; every other one refuses the request with 400
// invalid_request and changes nothing, not even a snapshot.
func TestEverySnapshottedRouteHonoursDryRun(t *testing.T) {
	saved := defaultAckTimeouts
	defaultAckTimeouts.reload, defaultAckTimeouts.clear = 50*time.Millisecond, 50*time.Millisecond
	t.Cleanup(func() { defaultAckTimeouts = saved })

	db0, svc0, cfg0, cleanup0 := setupTestDB(t)
	routes := snapshotWrapped(t, buildFullRouterOn(db0, svc0, cfg0, func(next http.Handler) http.Handler { return next }))
	cleanup0()
	if len(routes) != 13 {
		t.Errorf("%d routes take a snapshot first, want 13: %v", len(routes), routes)
	}
	previews := 0
	for _, key := range routes {
		if dryRunOps[key] {
			previews++
			continue
		}
		t.Run(key, func(t *testing.T) {
			c, ok := requestCases[key]
			if !ok {
				t.Fatalf("%s has no case in requestCases", key)
			}
			method, _, _ := strings.Cut(key, " ")
			db, svc, cfg, cleanup := setupTestDB(t)
			defer cleanup()
			cfg.EncryptionKey = testEncKey
			r := buildFullRouterOn(db, svc, cfg, func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					next.ServeHTTP(w, withUserContext(req, "admin"))
				})
			})
			if code, out := call(t, r, "POST", "/api/egress-allowlist", `{"entry":"z.example"}`); code != http.StatusOK {
				t.Fatalf("seed: %d %v", code, out)
			}
			if c.setup != nil {
				c.setup(t, r, nil)
			}
			before := fingerprint(t, db, cfg.ConfigDir)
			for _, v := range []string{"true", "1", "yes"} {
				code, out := call(t, r, method, withQuery(c.path, "dry_run="+v), c.body)
				if code != http.StatusBadRequest || out["code"] != "invalid_request" {
					t.Errorf("dry_run=%s: %d %v, want 400 invalid_request", v, code, out)
				}
			}
			if d := fingerprintDiff(before, fingerprint(t, db, cfg.ConfigDir)); len(d) > 0 {
				t.Errorf("a request carrying dry_run changed the state:\n%s", strings.Join(d, "\n"))
			}
			// dry_run=false runs the call, after its snapshot.
			snaps := snapshotCount(t, db)
			code, out := call(t, r, method, withQuery(c.path, "dry_run=false"), c.body)
			if got := snapshotCount(t, db); got != snaps+1 {
				t.Errorf("dry_run=false (%d %v): snapshots %d before, %d after, want one more", code, out, snaps, got)
			}
		})
	}
	if previews != 4 {
		t.Errorf("%d snapshotted routes preview a dry run, want 4", previews)
	}
}
