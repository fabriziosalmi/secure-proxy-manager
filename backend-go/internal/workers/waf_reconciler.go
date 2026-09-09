package workers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
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
func StartWAFReconciler(ctx context.Context, db *sql.DB, wafURL, user, pass string) {
	Track(func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		wasReachable := false
		for {
			reachable := reconcileWAF(ctx, db, wafURL, user, pass, !wasReachable)
			wasReachable = reachable
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

// reconcileWAF reports whether the WAF was reachable. It only pushes when
// force is set — i.e. on the first pass and on each failing→passing edge — so
// a healthy WAF is not rewritten every 30 seconds.
func reconcileWAF(ctx context.Context, db *sql.DB, wafURL, user, pass string, force bool) bool {
	hc := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wafURL+"/health", nil)
	if err != nil {
		return false
	}
	resp, err := hc.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	if !force {
		return true
	}

	pushed := 0
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
			continue
		}
		_ = rs.Body.Close()
		if rs.StatusCode == http.StatusOK {
			pushed++
		}
	}
	if pushed > 0 {
		log.Info().Int("heuristics", pushed).Msg("waf reconciled to the stored configuration")
	}
	return true
}
