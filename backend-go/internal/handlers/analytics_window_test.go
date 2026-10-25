package handlers

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"
)

// The Analytics page says its service, kind and file-type sections count
// client requests of the last 7 days with the stack's own addresses left out.
// These tests hold the endpoints to that sentence.

type shadowRow struct {
	Name     string `json:"name"`
	Requests int    `json:"requests"`
	Category string `json:"category"`
}

func shadowIT(t *testing.T, h *AnalyticsHandlers) map[string]int {
	t.Helper()
	var resp struct {
		Data []shadowRow `json:"data"`
	}
	getJSON(t, h.ShadowIT, "/api/analytics/shadow-it", &resp)
	out := map[string]int{}
	for _, r := range resp.Data {
		out[r.Name] = r.Requests
	}
	return out
}

type nameCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

func serviceTypes(t *testing.T, h *AnalyticsHandlers) map[string]int {
	t.Helper()
	var resp struct {
		Data struct {
			ServiceTypes []nameCount `json:"service_types"`
			Methods      []nameCount `json:"methods"`
		} `json:"data"`
	}
	getJSON(t, h.UserAgents, "/api/analytics/user-agents", &resp)
	out := map[string]int{}
	for _, r := range resp.Data.ServiceTypes {
		out[r.Name] = r.Count
	}
	return out
}

type fileTypes struct {
	Extensions []struct {
		Ext   string `json:"ext"`
		Count int    `json:"count"`
	} `json:"extensions"`
	Categories []struct {
		Category string `json:"category"`
		Count    int    `json:"count"`
	} `json:"categories"`
	Examined *int `json:"examined"`
	Limit    *int `json:"limit"`
}

func fileExtensions(t *testing.T, h *AnalyticsHandlers) fileTypes {
	t.Helper()
	var resp struct {
		Data fileTypes `json:"data"`
	}
	getJSON(t, h.FileExtensions, "/api/analytics/file-extensions", &resp)
	return resp.Data
}

func TestAnalyticsSectionsLeaveOutInternalSources(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	now := time.Now()
	// The default classifier knows loopback: 127.0.0.1 is the stack's own.
	for i := 0; i < 4; i++ {
		insertLogRow(t, db, now, "127.0.0.1", "GET", "http://www.facebook.com/a/setup.exe", 0, "none")
	}
	insertLogRow(t, db, now, lanClient, "GET", "http://www.facebook.com/b/setup.exe", 0, "none")
	insertLogRow(t, db, now, lanClient, "CONNECT", "cdn.example.net:443", 0, "none")
	// Older than the window, and a sinkhole answer: neither is counted.
	insertLogRow(t, db, now.Add(-8*24*time.Hour), lanClient, "GET", "http://www.facebook.com/old.zip", 0, "none")
	insertLogRow(t, db, now, proxyClient, "DNS", "www.facebook.com", 0, "none")
	h := NewAnalyticsHandlers(db, cfg)

	if got := shadowIT(t, h)["Facebook"]; got != 1 {
		t.Errorf("shadow-it counts %d Facebook requests, want 1 (the LAN client's)", got)
	}
	st := serviceTypes(t, h)
	if st["Other"] != 1 || st["CDN"] != 1 {
		t.Errorf("service types = %v, want Other 1 and CDN 1", st)
	}
	ft := fileExtensions(t, h)
	if len(ft.Extensions) != 1 || ft.Extensions[0].Ext != ".exe" || ft.Extensions[0].Count != 1 {
		t.Errorf("file extensions = %+v, want one .exe", ft.Extensions)
	}
}

// A service reached through many distinct URLs is still found: the list used
// to be the 500 most requested destinations, full URLs included.
func TestShadowITReadsEveryHostOfTheWindow(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	now := time.Now()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	ts, unix := now.UTC().Format("2006-01-02 15:04:05"), now.Unix()
	for i := 0; i < 501; i++ {
		for j := 0; j < 2; j++ {
			if _, err := tx.Exec(`INSERT INTO proxy_logs(timestamp, unix_timestamp, source_ip, method, destination, status, bytes, blocked, block_reason)
				VALUES(?, ?, ?, 'CONNECT', ?, 'TCP_TUNNEL/200', 0, 0, 'none')`, ts, unix, lanClient, fmt.Sprintf("site%03d.test:443", i)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/", "/login", "/photos"} {
		insertLogRow(t, db, now, lanClient, "GET", "http://www.facebook.com"+p, 0, "none")
	}
	h := NewAnalyticsHandlers(db, cfg)
	if got := shadowIT(t, h)["Facebook"]; got != 3 {
		t.Errorf("shadow-it counts %d Facebook requests, want 3", got)
	}
}

// The kind of service is read from the host: a path that contains "update"
// does not make a request to any site an update.
func TestServiceTypesReadTheHostOnly(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	now := time.Now()
	insertLogRow(t, db, now, lanClient, "GET", "http://example.org/update/check", 0, "none")
	insertLogRow(t, db, now, lanClient, "GET", "http://example.org/static/cdn/app.js", 0, "none")
	insertLogRow(t, db, now, lanClient, "CONNECT", "update.example.org:443", 0, "none")
	st := serviceTypes(t, NewAnalyticsHandlers(db, cfg))
	if st["Other"] != 2 || st["Updates"] != 1 || st["CDN"] != 0 {
		t.Errorf("service types = %v, want Other 2, Updates 1, no CDN", st)
	}
}

// A file type is read from a URL's path: the top-level domain of a host is
// not a file type.
func TestFileExtensionsReadTheURLPathOnly(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	now := time.Now()
	insertLogRow(t, db, now, lanClient, "GET", "http://example.it", 0, "none")
	insertLogRow(t, db, now, lanClient, "GET", "http://shop.example.de", 0, "none")
	insertLogRow(t, db, now, lanClient, "GET", "http://example.it/", 0, "none")
	insertLogRow(t, db, now, lanClient, "CONNECT", "host.example.fr:443", 0, "none")
	insertLogRow(t, db, now, lanClient, "GET", "http://files.test/a/report.PDF?x=1.zip", 0, "none")
	insertLogRow(t, db, now, lanClient, "GET", "https://files.test/b.v2/archive.tar.gz#part.txt", 0, "none")
	ft := fileExtensions(t, NewAnalyticsHandlers(db, cfg))

	got := map[string]int{}
	for _, e := range ft.Extensions {
		got[e.Ext] = e.Count
	}
	if len(got) != 2 || got[".pdf"] != 1 || got[".gz"] != 1 {
		t.Errorf("extensions = %v, want .pdf 1 and .gz 1", got)
	}
	cats := map[string]int{}
	for _, c := range ft.Categories {
		cats[c.Category] = c.Count
	}
	if len(cats) != 2 || cats["Documents"] != 1 || cats["Archives"] != 1 {
		t.Errorf("categories = %v, want Documents 1 and Archives 1", cats)
	}
	// Five rows are URLs (the CONNECT target is not), read under the limit.
	if ft.Examined == nil || *ft.Examined != 5 || ft.Limit == nil || *ft.Limit != fileExtensionsLimit {
		t.Errorf("examined %v of limit %v, want 5 of %d", ft.Examined, ft.Limit, fileExtensionsLimit)
	}
}

// A window with no request for a file has empty lists, not null: the
// Analytics page failed on null ("Cannot read properties of null").
func TestFileExtensionsOfAnEmptyWindowAreEmptyLists(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	insertLogRow(t, db, time.Now(), lanClient, "CONNECT", "host.test:443", 0, "none")
	w := httptest.NewRecorder()
	NewAnalyticsHandlers(db, cfg).FileExtensions(w, httptest.NewRequest("GET", "/api/analytics/file-extensions", nil))
	var resp struct {
		Data map[string]json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"extensions", "categories"} {
		if got := string(resp.Data[k]); got != "[]" {
			t.Errorf("%s = %s, want []", k, got)
		}
	}
}

func TestURLPath(t *testing.T) {
	for _, c := range []struct {
		in, want string
		ok       bool
	}{
		{"http://host/a/b.zip?x=1", "/a/b.zip", true},
		{"https://host:8443/p#f", "/p", true},
		{"http://host", "", false},
		{"host:443", "", false},
		{"host", "", false},
	} {
		got, ok := urlPath(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("urlPath(%q) = %q, %v; want %q, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}
