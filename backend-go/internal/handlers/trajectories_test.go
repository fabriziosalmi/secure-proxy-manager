package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
)

func trajectoryRouter(h *TrajectoryHandlers) http.Handler {
	r := chi.NewRouter()
	h.Register(r, func(next http.Handler) http.Handler { return next })
	return r
}

func getTrajectoryJSON(t *testing.T, h http.Handler, path string, into any) int {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
	if into != nil && w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), into); err != nil {
			t.Fatal(err)
		}
	}
	return w.Code
}

func TestTrajectoryAPI(t *testing.T) {
	db, _, _, cleanup := setupTestDB(t)
	defer cleanup()
	start := time.Now().Add(-2 * time.Hour).Truncate(time.Millisecond).UTC()
	const c = "192.0.2.7"
	if err := database.StoreWAFSignals(db, []database.WAFSignal{
		{At: start, ClientIP: c, Host: "paypa1.com", Category: "TYPOSQUATTING", Rule: "ML-TYPO-001", EventID: "e1"},
		{At: start.Add(10 * time.Minute), ClientIP: c, Host: "c2.test", Category: "HEURISTIC_BEACONING", Rule: "H2-BEACON", EventID: "e2"},
		{At: start.Add(10 * time.Minute), ClientIP: "192.0.2.8", Host: "other.test", Category: "DGA_DOMAIN", EventID: "e3"},
		{At: start.Add(-time.Minute), ClientIP: c, Host: "before.test", Category: "DGA_DOMAIN", EventID: "e4"},
	}); err != nil {
		t.Fatal(err)
	}
	id, _, err := database.InsertWAFTrajectory(db, database.WAFTrajectory{ClientIP: c, Rule: "order", Start: start,
		Closed: start.Add(10 * time.Minute), End: start.Add(10 * time.Minute), Phases: []string{"arrival", "contact"},
		Categories: []string{"TYPOSQUATTING", "HEURISTIC_BEACONING"}, Hosts: []string{"paypa1.com", "c2.test"}, Signals: 2})
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-10 * 24 * time.Hour).Truncate(time.Millisecond).UTC()
	if _, _, err := database.InsertWAFTrajectory(db, database.WAFTrajectory{ClientIP: c, Rule: "breadth", Start: old, Closed: old, End: old}); err != nil {
		t.Fatal(err)
	}
	h := trajectoryRouter(NewTrajectoryHandlers(db))
	var month struct {
		Data []database.WAFTrajectory `json:"data"`
	}
	if code := getTrajectoryJSON(t, h, "/api/waf/trajectories?days=30", &month); code != http.StatusOK || len(month.Data) != 2 ||
		month.Data[0].ID != id {
		t.Fatalf("30 days: %d %+v, want both, latest first", code, month.Data)
	}

	var list struct {
		Data []database.WAFTrajectory `json:"data"`
	}
	if code := getTrajectoryJSON(t, h, "/api/waf/trajectories", &list); code != http.StatusOK || len(list.Data) != 1 ||
		list.Data[0].ID != id || list.Data[0].Rule != "order" || !list.Data[0].Start.Equal(start) {
		t.Fatalf("list: %d %+v", code, list.Data)
	}
	for _, q := range []string{"?days=0", "?days=91", "?days=x"} {
		if code := getTrajectoryJSON(t, h, "/api/waf/trajectories"+q, nil); code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", q, code)
		}
	}

	var one struct {
		Data struct {
			Trajectory database.WAFTrajectory `json:"trajectory"`
			Signals    []trajectorySignal     `json:"signals"`
			Truncated  bool                   `json:"truncated"`
		} `json:"data"`
	}
	path := "/api/waf/trajectories/" + jsonID(id)
	if code := getTrajectoryJSON(t, h, path, &one); code != http.StatusOK {
		t.Fatalf("get: %d", code)
	}
	// The default week leaves out the one that closed 10 days ago (checked
	// above with list); only this client's signals, from the start: not the other client's,
	// not the one before.
	s := one.Data.Signals
	if len(s) != 2 || s[0].Category != "TYPOSQUATTING" || s[0].Phase != "arrival" || s[1].Host != "c2.test" ||
		s[1].Phase != "contact" || one.Data.Truncated || one.Data.Trajectory.ClientIP != c {
		t.Errorf("detail: %+v", one.Data)
	}
	if code := getTrajectoryJSON(t, h, "/api/waf/trajectories/999", nil); code != http.StatusNotFound {
		t.Errorf("missing id: %d, want 404", code)
	}
	if code := getTrajectoryJSON(t, h, "/api/waf/trajectories/abc", nil); code != http.StatusBadRequest {
		t.Errorf("bad id: %d, want 400", code)
	}
}

func jsonID(id int64) string { b, _ := json.Marshal(id); return string(b) }
