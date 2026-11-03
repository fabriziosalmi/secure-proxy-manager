package handlers

import (
	"database/sql"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/trajectory"
)

// TrajectoryHandlers serve the trajectories the correlator stored from the
// WAF's client signals (workers.SweepTrajectories).
type TrajectoryHandlers struct{ db *sql.DB }

func NewTrajectoryHandlers(db *sql.DB) *TrajectoryHandlers { return &TrajectoryHandlers{db: db} }

func (h *TrajectoryHandlers) Register(r chi.Router, authMW func(http.Handler) http.Handler) {
	r.With(authMW).Get("/api/waf/trajectories", h.List)
	r.With(authMW).Get("/api/waf/trajectories/{id}", h.Get)
}

// trajectoryListMax bounds one list; trajectorySignalsMax the signals one
// trajectory shows (the WAF sends a client's category at most every 10
// minutes, so a day of one client is at most a couple of thousand).
const (
	trajectoryListMax    = 200
	trajectorySignalsMax = 500
)

// List answers GET /api/waf/trajectories?days=N (1 to 90, default 7): the
// trajectories that closed in the last N days, latest first.
func (h *TrajectoryHandlers) List(w http.ResponseWriter, r *http.Request) {
	days, err := 7, error(nil)
	if v := r.URL.Query().Get("days"); v != "" {
		days, err = strconv.Atoi(v)
	}
	if err != nil || days < 1 || days > 90 {
		writeError(w, http.StatusBadRequest, "days: 1 to 90")
		return
	}
	ts, err := database.ListWAFTrajectories(h.db, time.Now().Add(-time.Duration(days)*24*time.Hour), trajectoryListMax)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "trajectories not read")
		return
	}
	writeOK(w, ts)
}

// trajectorySignal is one signal of a trajectory's window, as the detail
// shows it.
type trajectorySignal struct {
	At       time.Time `json:"at"`
	Category string    `json:"category"`
	Phase    string    `json:"phase"`
	Host     string    `json:"host"`
	Rule     string    `json:"rule"`
	Observed bool      `json:"observed"`
	Blocked  bool      `json:"blocked"`
	EventID  string    `json:"event_id"`
}

// Get answers GET /api/waf/trajectories/{id}: the trajectory and the
// client's signals in its window (Start to Start+24h), in the order they
// came, at most trajectorySignalsMax.
func (h *TrajectoryHandlers) Get(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id < 1 {
		writeError(w, http.StatusBadRequest, "id: a positive integer")
		return
	}
	t, ok, err := database.GetWAFTrajectory(h.db, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "trajectory not read")
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "no such trajectory")
		return
	}
	rows, err := database.ClientSignals(h.db, t.ClientIP, t.Start, t.Start.Add(trajectory.Window))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "signals not read")
		return
	}
	truncated := len(rows) > trajectorySignalsMax
	if truncated {
		rows = rows[:trajectorySignalsMax]
	}
	sigs := make([]trajectorySignal, len(rows))
	for i, s := range rows {
		sigs[i] = trajectorySignal{At: s.At, Category: s.Category, Phase: trajectory.PhaseOf[s.Category].String(), Host: s.Host,
			Rule: s.Rule, Observed: s.Observed, Blocked: s.Blocked, EventID: s.EventID}
	}
	writeOK(w, map[string]any{"trajectory": t, "signals": sigs, "truncated": truncated})
}
