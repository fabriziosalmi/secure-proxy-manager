package handlers

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
)

// fingerprint is the state a destructive operation could change: every row of
// every table, and every file under the configuration directory but the
// database's own.
func fingerprint(t *testing.T, db *sql.DB, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	rows, err := db.Query("SELECT name FROM sqlite_master WHERE type = 'table'")
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, n)
	}
	rows.Close()
	for _, table := range tables {
		rs, err := db.Query(`SELECT * FROM "` + table + `"`) // slopless-disable-line VBC-004 -- the name comes from sqlite_master
		if err != nil {
			t.Fatalf("read %s: %v", table, err)
		}
		cols, _ := rs.Columns()
		var lines []string
		for rs.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rs.Scan(ptrs...); err != nil {
				t.Fatal(err)
			}
			lines = append(lines, fmt.Sprintf("%v", vals))
		}
		rs.Close()
		sort.Strings(lines)
		sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
		out["table "+table] = fmt.Sprintf("%d rows %s", len(lines), hex.EncodeToString(sum[:8]))
	}
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || strings.HasPrefix(d.Name(), "test.db") {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		rel, _ := filepath.Rel(dir, p)
		out["file "+rel] = hex.EncodeToString(sum[:8])
		return nil
	})
	return out
}

func fingerprintDiff(a, b map[string]string) []string {
	var d []string
	for k, v := range a {
		if b[k] != v {
			d = append(d, fmt.Sprintf("%s: %s -> %s", k, v, b[k]))
		}
	}
	for k, v := range b {
		if _, ok := a[k]; !ok {
			d = append(d, fmt.Sprintf("%s: (none) -> %s", k, v))
		}
	}
	sort.Strings(d)
	return d
}

// withQuery adds a query parameter to a path that may already carry some.
func withQuery(path, q string) string {
	if strings.Contains(path, "?") {
		return path + "&" + q
	}
	return path + "?" + q
}

// Every destructive operation that takes ?dry_run=true answers 200 with
// data.dry_run true and changes nothing: no row of any table (no entry, no
// audit line, no configuration snapshot) and no file under the configuration
// directory (no list export, no cache-clear trigger). A dry_run that is not
// true or false is refused and changes nothing either. The same call without
// dry_run then does change the state, so the case is not vacuous, and where
// both answers say how many rows go, they agree.
func TestADryRunChangesNothing(t *testing.T) {
	saved := defaultAckTimeouts
	defaultAckTimeouts.reload, defaultAckTimeouts.clear = 50*time.Millisecond, 50*time.Millisecond
	t.Cleanup(func() { defaultAckTimeouts = saved })

	var keys []string
	for k := range dryRunOps {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) != 21 {
		t.Errorf("%d operations take dry_run, want the 21 destructive ones", len(keys))
	}

	for _, key := range keys {
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
			// Something for each operation to remove.
			for _, q := range []struct{ path, body string }{
				{"/api/ip-blacklist", `{"ip":"203.0.113.1"}`}, {"/api/ip-blacklist", `{"ip":"203.0.113.2"}`},
				{"/api/ip-whitelist", `{"ip":"10.0.0.1"}`}, {"/api/domain-blacklist", `{"domain":"x.example"}`},
				{"/api/domain-whitelist", `{"domain":"y.example"}`}, {"/api/egress-allowlist", `{"entry":"z.example"}`},
				{"/api/client-groups", `{"name":"g1","members":["10.0.1.0/24"]}`},
			} {
				if code, out := call(t, r, "POST", q.path, q.body); code != http.StatusOK {
					t.Fatalf("seed %s: %d %v", q.path, code, out)
				}
			}
			// A source on every list, one entry of which another source lists too.
			for _, q := range []struct{ path, body string }{
				{"/api/blacklists/import", `{"type":"ip","content":"203.0.113.50\n203.0.113.51\n203.0.113.1","name":"feed"}`},
				{"/api/blacklists/import", `{"type":"domain","content":"a.example\nb.example\nx.example","name":"feed"}`},
				{"/api/ip-whitelist/import", `{"content":"10.0.0.20\n10.0.0.1"}`},
				{"/api/domain-whitelist/import", `{"content":"c.example\ny.example"}`},
				// A second feed: removing the first keeps the entry this one lists too.
				{"/api/blacklists/import", `{"type":"ip","content":"203.0.113.50\n203.0.113.60","name":"feed2"}`},
				{"/api/blacklists/import", `{"type":"domain","content":"a.example\nd.example","name":"feed2"}`},
			} {
				if code, out := call(t, r, "POST", q.path, q.body); code != http.StatusOK {
					t.Fatalf("seed %s: %d %v", q.path, code, out)
				}
			}
			_, tok, err := database.CreateAPIToken(db, "grafana", database.ScopeRead, "admin", nil, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			path := c.path
			switch {
			case strings.HasPrefix(key, "DELETE /api/tokens/"):
				path = "/api/tokens/" + tok.ID
			case strings.HasSuffix(key, "/sources/{id}"):
				list := strings.ReplaceAll(strings.Split(path, "/")[2], "-", "_")
				var id string
				// The first feed on a blacklist (the second source from the end),
				// the one import on a whitelist (the last).
				skip := 0
				if strings.Contains(list, "blacklist") {
					skip = 1
				}
				if err := db.QueryRow("SELECT id FROM list_sources WHERE list = ? ORDER BY id DESC LIMIT 1 OFFSET ?", list, skip).Scan(&id); err != nil {
					t.Fatalf("no source on %s: %v", list, err)
				}
				path = strings.Replace(path, "unrecorded", id, 1)
			}
			for _, age := range []time.Duration{time.Hour, 40 * 24 * time.Hour, 50 * 24 * time.Hour} {
				ts := time.Now().UTC().Add(-age)
				if _, err := db.Exec("INSERT INTO proxy_logs (timestamp, unix_timestamp, source_ip, destination) VALUES (?, ?, '10.0.0.5', 'http://a.example')",
					ts.Format("2006-01-02 15:04:05"), ts.Unix()); err != nil {
					t.Fatal(err)
				}
			}

			do := func(path string) (int, map[string]any) {
				t.Helper()
				return call(t, r, method, path, c.body)
			}
			before := fingerprint(t, db, cfg.ConfigDir)

			code, out := do(withQuery(path, "dry_run=true"))
			data, _ := out["data"].(map[string]any)
			if code != http.StatusOK || data["dry_run"] != true {
				t.Fatalf("dry run: %d %v, want 200 with data.dry_run true", code, out)
			}
			if d := fingerprintDiff(before, fingerprint(t, db, cfg.ConfigDir)); len(d) > 0 {
				t.Errorf("the dry run changed the state:\n%s", strings.Join(d, "\n"))
			}

			code, out = do(withQuery(path, "dry_run=maybe"))
			if code != http.StatusBadRequest || out["code"] != "invalid_request" {
				t.Errorf("dry_run=maybe: %d %v, want 400 invalid_request", code, out)
			}
			if d := fingerprintDiff(before, fingerprint(t, db, cfg.ConfigDir)); len(d) > 0 {
				t.Errorf("a refused dry_run changed the state:\n%s", strings.Join(d, "\n"))
			}

			rcode, rout := do(withQuery(path, "dry_run=false"))
			if d := fingerprintDiff(before, fingerprint(t, db, cfg.ConfigDir)); len(d) == 0 {
				t.Errorf("the real call (%d %v) changed nothing either: the case proves nothing", rcode, rout)
			}
			// Most answers carry their fields in data; restore-config at the top.
			rdata, _ := rout["data"].(map[string]any)
			if rdata == nil {
				rdata = rout
			}
			compared := 0
			for _, field := range []string{"removed", "kept", "revoked", "restored", "skipped", "logs_cleared", "members", "lists"} {
				want, inDry := data[field]
				got, inReal := rdata[field]
				if inDry && inReal && fmt.Sprint(want) != fmt.Sprint(got) {
					t.Errorf("%s: the dry run said %v, the real call %v", field, want, got)
				}
				if inDry && inReal {
					compared++
				}
			}
			// The real group delete and token revoke answer only a message: their
			// preview names what would go, the group and token seeded above.
			_, says := data["would"]
			says = says || data["removed"] == "g1" && key == "DELETE /api/client-groups/{id}" ||
				data["revoked"] == "grafana" && key == "DELETE /api/tokens/{id}"
			if strings.Contains(key, "blacklist/sources/") && (data["kept"] != float64(1) || data["removed"] != float64(1)) {
				t.Errorf("preview %v: the first feed has one entry no other source lists and one the second lists too", data)
			}
			if compared == 0 && !says {
				b, _ := json.Marshal(map[string]any{"dry": data, "real": rcode, "realData": rdata})
				t.Errorf("the dry run and the real call share no count, and the dry run says nothing it would do: %s", b)
			}
		})
	}
}
