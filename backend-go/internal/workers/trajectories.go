package workers

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/metrics"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/trajectory"
)

// trajectoryEvery is how often the WAF's signals are read as trajectories; a
// test shortens it.
var trajectoryEvery = time.Minute

// StartTrajectoryWatch reads the WAF's signals as trajectories every minute
// (SweepTrajectories).
func StartTrajectoryWatch(ctx context.Context, db *sql.DB) {
	Track(func() {
		t := time.NewTicker(trajectoryEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			found, err := SweepTrajectories(db, time.Now())
			if err != nil {
				log.Warn().Err(err).Msg("trajectory sweep failed")
			}
			reportTrajectories(found)
			metrics.WorkerHeartbeat("trajectory_watch")
		}
	})
}

// reportTrajectories logs and raises waf_trajectory for each trajectory a
// sweep stored new: once each, since a row is found new only once.
func reportTrajectories(found []database.WAFTrajectory) {
	for _, tr := range found {
		log.Warn().Str("client", tr.ClientIP).Str("rule", tr.Rule).Strs("categories", tr.Categories).
			Msg("a client's signals read as a trajectory")
		raiseClientAlert("waf_trajectory", "warning",
			fmt.Sprintf("Client %s: its WAF signals since %s read as a compromised host (%s): %s. See Analytics, Client trajectories.",
				tr.ClientIP, tr.Start.UTC().Format("2006-01-02 15:04 UTC"), tr.Rule, strings.Join(tr.Categories, ", ")),
			tr.ClientIP, map[string]any{"trajectory_id": tr.ID, "rule": tr.Rule, "phases": tr.Phases, "categories": tr.Categories})
	}
}

// SweepTrajectories reads, for each client with a signal in the last day,
// its signals as trajectories, and returns those it stored new.
//
// A client has one trajectory per window: while the window of its latest
// trajectory (Start to Start+Window) is open, signals that arrive in it
// update that row (its end, categories, hosts and count); a new one is
// looked for only among signals after it. Signals are read from two windows
// back, so a trajectory that closes now is found whatever its start, and a
// row already stored is never found again: its start is the same instant.
//
// A client stored masked (a.b.c.x, from before signals were dropped in GDPR
// mode) is a whole network, not a client, and is not read.
func SweepTrajectories(db *sql.DB, now time.Time) ([]database.WAFTrajectory, error) {
	defer database.LockWAFRecords()()
	clients, err := database.SignalClientsSince(db, now.Add(-trajectory.Window))
	if err != nil {
		return nil, err
	}
	var found []database.WAFTrajectory
	for _, c := range clients {
		if net.ParseIP(c) == nil {
			continue
		}
		last, hasLast, err := database.LastWAFTrajectory(db, c)
		if err != nil {
			return found, err
		}
		from := now.Add(-2 * trajectory.Window)
		if hasLast && last.Start.Before(from) {
			// Its window ended over a day ago: nothing left to update.
			hasLast = false
			from = maxTime(from, last.Start.Add(trajectory.Window).Add(time.Millisecond))
		}
		if hasLast {
			from = last.Start
		}
		rows, err := database.ClientSignals(db, c, from, now)
		if err != nil {
			return found, err
		}
		sigs := make([]trajectory.Signal, len(rows))
		for i, r := range rows {
			sigs[i] = trajectory.Signal{At: r.At, Category: r.Category, Host: r.Host}
		}
		walk := sigs
		if hasLast {
			windowEnd := last.Start.Add(trajectory.Window)
			in, after := split(sigs, windowEnd)
			if s := trajectory.Summarize(in); len(in) > 0 && (s.Count != last.Signals || !in[len(in)-1].At.Equal(last.End)) {
				upd := rowOf(c, trajectory.Trajectory{Start: last.Start, End: in[len(in)-1].At, Summary: s})
				if err := database.UpdateWAFTrajectory(db, last.ID, upd); err != nil {
					return found, err
				}
			}
			walk = after
		}
		for {
			tr, ok := trajectory.First(walk)
			if !ok {
				break
			}
			row := rowOf(c, tr)
			id, inserted, err := database.InsertWAFTrajectory(db, row)
			if err != nil {
				return found, err
			}
			if inserted {
				row.ID = id
				found = append(found, row)
			}
			_, walk = split(walk, tr.Start.Add(trajectory.Window))
		}
	}
	return found, nil
}

// split cuts sigs (in time order) into those at or before t and those after.
func split(sigs []trajectory.Signal, t time.Time) (upTo, after []trajectory.Signal) {
	i := 0
	for i < len(sigs) && !sigs[i].At.After(t) {
		i++
	}
	return sigs[:i], sigs[i:]
}

func rowOf(client string, tr trajectory.Trajectory) database.WAFTrajectory {
	return database.WAFTrajectory{ClientIP: client, Rule: tr.Rule, Start: tr.Start, Closed: tr.Closed, End: tr.End,
		Phases: tr.Phases, Categories: tr.Categories, Hosts: tr.Hosts, Signals: tr.Count}
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}
