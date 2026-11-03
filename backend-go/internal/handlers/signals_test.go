package handlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

func signalReport(client string, signals ...map[string]any) []byte {
	b, _ := json.Marshal(map[string]any{
		"event_id": "e-1", "ts": "2026-11-03T10:00:00.123456789Z", "client_ip": client,
		"host": "paypa1.com", "blocked": false, "signals": signals,
	})
	return b
}

type signalRow struct {
	tsMS                                  int64
	client, host, category, rule, eventID string
	observed, blocked                     bool
}

func signalRows(t *testing.T, db *sql.DB) []signalRow {
	t.Helper()
	rows, err := db.Query("SELECT ts_ms, client_ip, host, category, rule, observed, blocked, event_id FROM waf_signals ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []signalRow
	for rows.Next() {
		var r signalRow
		if err := rows.Scan(&r.tsMS, &r.client, &r.host, &r.category, &r.rule, &r.observed, &r.blocked, &r.eventID); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

// A report becomes one row per signal and notifies nobody: a signal is not
// an alert. In GDPR mode the client is stored masked, as an alert's is.
func TestReceiveSignalsStoresRowsAndNotifiesNobody(t *testing.T) {
	for _, gdpr := range []bool{false, true} {
		t.Run(fmt.Sprintf("gdpr=%v", gdpr), func(t *testing.T) {
			db, _, _, cleanup := setupTestDB(t)
			defer cleanup()
			setGDPRMode(t, db, gdpr)
			notify := make(NotifyQueue, 4)
			h := NewSecurityHandlers(db, nil, nil, notify)
			body := signalReport("192.0.2.7",
				map[string]any{"category": "TYPOSQUATTING", "rule": "ML-TYPO-001", "observed": false},
				map[string]any{"category": "CLOUD_SECRETS", "rule": "SEC-AWS-1", "observed": true})
			w := httptest.NewRecorder()
			h.ReceiveSignals(w, httptest.NewRequest("POST", "/api/internal/signals", bytes.NewReader(body)))
			if w.Code != http.StatusOK {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			if len(notify) != 0 {
				t.Errorf("a signal report queued %d notifications", len(notify))
			}
			client := "192.0.2.7"
			if gdpr {
				client = "192.0.2.x"
			}
			want := []signalRow{
				{1793700000123, client, "paypa1.com", "TYPOSQUATTING", "ML-TYPO-001", "e-1", false, false},
				{1793700000123, client, "paypa1.com", "CLOUD_SECRETS", "SEC-AWS-1", "e-1", true, false},
			}
			got := signalRows(t, db)
			if len(got) != len(want) {
				t.Fatalf("rows = %+v, want %+v", got, want)
			}
			for i := range want {
				if got[i] != want[i] {
					t.Errorf("row %d = %+v, want %+v", i, got[i], want[i])
				}
			}
		})
	}
}

func TestReceiveSignalsRejectsMalformedReports(t *testing.T) {
	ok := map[string]any{"category": "DGA_DOMAIN", "rule": "ML-DGA-001"}
	many := make([]map[string]any, signalReportMax+1)
	for i := range many {
		many[i] = ok
	}
	report := func(edit func(m map[string]any)) []byte {
		m := map[string]any{"event_id": "e", "ts": "2026-11-03T10:00:00Z", "client_ip": "192.0.2.7", "host": "x.test",
			"signals": []map[string]any{ok}}
		edit(m)
		b, _ := json.Marshal(m)
		return b
	}
	for _, c := range []struct {
		name string
		body []byte
	}{
		{"not JSON", []byte("{")},
		{"no time", report(func(m map[string]any) { delete(m, "ts") })},
		{"bad time", report(func(m map[string]any) { m["ts"] = "yesterday" })},
		{"no client", report(func(m map[string]any) { m["client_ip"] = "unknown" })},
		{"no signals", report(func(m map[string]any) { m["signals"] = []map[string]any{} })},
		{"too many signals", report(func(m map[string]any) { m["signals"] = many })},
		{"lower-case category", report(func(m map[string]any) {
			m["signals"] = []map[string]any{{"category": "dga_domain", "rule": "x"}}
		})},
		{"category with markup", report(func(m map[string]any) {
			m["signals"] = []map[string]any{{"category": "<B>", "rule": "x"}}
		})},
		{"long rule", report(func(m map[string]any) {
			m["signals"] = []map[string]any{{"category": "DGA_DOMAIN", "rule": strings.Repeat("r", signalNameMax+1)}}
		})},
		{"long host", report(func(m map[string]any) { m["host"] = strings.Repeat("h", signalHostMax+1) })},
		// Every field is bounded, so only the body limit stops a report
		// padded with a field the decoder ignores.
		{"oversized body", report(func(m map[string]any) { m["pad"] = strings.Repeat("p", signalReportMaxBytes) })},
	} {
		t.Run(c.name, func(t *testing.T) {
			db, _, _, cleanup := setupTestDB(t)
			defer cleanup()
			h := NewSecurityHandlers(db, nil, nil, make(NotifyQueue, 1))
			w := httptest.NewRecorder()
			h.ReceiveSignals(w, httptest.NewRequest("POST", "/api/internal/signals", bytes.NewReader(c.body)))
			if w.Code != http.StatusBadRequest {
				t.Errorf("status %d, want 400", w.Code)
			}
			if n := len(signalRows(t, db)); n != 0 {
				t.Errorf("%d rows stored from a rejected report", n)
			}
		})
	}
}

// The route takes the WAF's service token, as /api/internal/alert does, and
// nothing else once a token is configured.
func TestReceiveSignalsRequiresServiceToken(t *testing.T) {
	acceptAll := func(next http.Handler) http.Handler { return next }
	post := func(t *testing.T, header string) int {
		t.Helper()
		db, svc, cfg, cleanup := setupTestDB(t)
		defer cleanup()
		cfg.AlertToken = "s3rv1ce-t0ken"
		r := chi.NewRouter()
		NewSecurityHandlers(db, svc, cfg, make(NotifyQueue, 1)).Register(r, acceptAll)
		req := httptest.NewRequest("POST", "/api/internal/signals",
			bytes.NewReader(signalReport("192.0.2.7", map[string]any{"category": "DGA_DOMAIN", "rule": "ML-DGA-001"})))
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}
	if code := post(t, "Bearer s3rv1ce-t0ken"); code != http.StatusOK {
		t.Errorf("the WAF's token: got %d, want 200", code)
	}
	if code := post(t, ""); code != http.StatusUnauthorized {
		t.Errorf("an admin session reached the signal route: got %d, want 401", code)
	}
	if code := post(t, "Bearer wrong"); code != http.StatusUnauthorized {
		t.Errorf("a wrong token: got %d, want 401", code)
	}
}
