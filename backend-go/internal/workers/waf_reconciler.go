package workers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/metrics"
)

// heuristicKeys are the runtime-toggleable WAF heuristics. Keep in sync with
// waf-go's heuristicToggles; scripts/check-waf-keys.sh gates that.
var heuristicKeys = []string{
	"waf_h_entropy", "waf_h_beaconing", "waf_h_pii",
	"waf_h_sharding", "waf_h_ghosting", "waf_h_sequence",
}

// StartWAFReconciler pushes the stored heuristic configuration to the WAF at
// startup and whenever the WAF comes back after being unreachable.
//
// The WAF reads WAF_H_* from its environment once, at process start, and the
// backend pushed the database values only when settings were saved. Nothing
// re-pushed. So any WAF restart — an image upgrade, an OOM kill, a plain
// `docker compose up -d` — silently reverted the enforced heuristics to the
// compose defaults while the database and the Settings page went on showing
// the operator's choices (SECURE-CONF-02).
// reconcileEvery is how often the reconciler runs; a variable so tests can
// shorten it.
var reconcileEvery = 30 * time.Second

func StartWAFReconciler(ctx context.Context, db *sql.DB, wafURL, user, pass string) {
	Track(func() {
		ticker := time.NewTicker(reconcileEvery)
		defer ticker.Stop()
		// synced is true once the WAF is known to match the stored
		// configuration. Until then every pass pushes, so a push that failed
		// (the WAF answered but rejected the credential, or dropped the
		// connection) is retried in 30 s instead of waiting for the WAF to
		// restart.
		synced := false
		lastOutcome := reconcileOK
		for {
			// The heartbeat on every pass, reachable or not: it says the loop
			// is alive, which is what the worker-staleness alert reads.
			metrics.WorkerHeartbeat("waf_reconciler")
			outcome := reconcileWAF(ctx, db, wafURL, user, pass, !synced)
			synced = outcome == reconcileOK
			metrics.WAFReconcile(outcome.String())
			// Log the transitions, not every pass: the first failure after a
			// success (with what failed) and the recovery.
			if outcome != lastOutcome {
				if outcome == reconcileOK {
					log.Info().Msg("waf reconcile: WAF matches the stored configuration again")
				} else {
					log.Warn().Str("outcome", outcome.String()).Str("waf_url", wafURL).
						Msg("waf reconcile: WAF does not match the stored configuration; retrying every 30s")
				}
				lastOutcome = outcome
			}
			select {
			case <-ctx.Done():
				log.Info().Msg("waf reconciler stopping")
				return
			case <-ticker.C:
			}
		}
	})
	log.Info().Msg("waf reconciler started")
}

type reconcileOutcome int

const (
	reconcileOK reconcileOutcome = iota
	reconcileUnreachable
	reconcilePushFailed
)

func (o reconcileOutcome) String() string {
	switch o {
	case reconcileOK:
		return "success"
	case reconcileUnreachable:
		return "unreachable"
	default:
		return "push_failed"
	}
}

// reconcileWAF makes one pass. It reports reconcileUnreachable when the WAF
// cannot be reached or is unhealthy, reconcilePushFailed when it was reached
// but at least one stored toggle could not be applied, and reconcileOK
// otherwise. It only pushes when force is set, so a healthy, matching WAF is not
// rewritten every 30 seconds.
func reconcileWAF(ctx context.Context, db *sql.DB, wafURL, user, pass string, force bool) reconcileOutcome {
	hc := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wafURL+"/health", nil)
	if err != nil {
		return reconcileUnreachable
	}
	resp, err := hc.Do(req)
	if err != nil {
		return reconcileUnreachable
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return reconcileUnreachable
	}
	if !force {
		return reconcileOK
	}

	pushed, failed := 0, 0
	for _, key := range heuristicKeys {
		var val string
		if err := db.QueryRow("SELECT setting_value FROM settings WHERE setting_name = ?", key).Scan(&val); err != nil {
			continue // not configured: the WAF's env default stands
		}
		enabled := val == "true" || val == "1"
		body, err := json.Marshal(map[string]any{"heuristic": key, "enabled": enabled})
		if err != nil {
			continue
		}
		r, err := http.NewRequestWithContext(ctx, http.MethodPost, wafURL+"/heuristics/toggle", bytes.NewReader(body))
		if err != nil {
			continue
		}
		r.Header.Set("Content-Type", "application/json")
		r.SetBasicAuth(user, pass)
		rs, err := hc.Do(r)
		if err != nil {
			log.Warn().Str("heuristic", key).Err(err).Msg("waf reconcile: push failed")
			failed++
			continue
		}
		_ = rs.Body.Close()
		if rs.StatusCode == http.StatusOK {
			pushed++
		} else {
			// A rejected push (401 after a credential change, 400 for an unknown
			// key) used to be ignored, and the pass still reported success, so
			// the WAF stayed on its compose defaults with nothing to say so.
			log.Warn().Str("heuristic", key).Int("status", rs.StatusCode).Msg("waf reconcile: push rejected")
			failed++
		}
	}
	if pushed > 0 {
		log.Info().Int("heuristics", pushed).Msg("waf reconciled to the stored configuration")
	}
	if failed > 0 {
		return reconcilePushFailed
	}
	return reconcileOK
}
