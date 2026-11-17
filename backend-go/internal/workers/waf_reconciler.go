package workers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
// startup, and on every later pass compares the heuristics the WAF runs with
// the stored ones and pushes those that differ.
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

// WAFAuth is how the backend authenticates to the WAF management API. The
// shipped compose gives the WAF INTERNAL_ALERT_TOKEN, the backend/WAF service
// credential, and not the admin credential (SECURE-AUTH-02), so the token is
// what it checks. Basic with the WAF service credentials is sent only when no
// token is configured. Sending Basic unconditionally is why every management
// call was refused with 403 on real deployments.
type WAFAuth struct {
	Token      string
	User, Pass string
}

// Apply sets the Authorization header on a request to the WAF.
func (a WAFAuth) Apply(r *http.Request) {
	if a.Token != "" {
		r.Header.Set("Authorization", "Bearer "+a.Token)
		return
	}
	r.SetBasicAuth(a.User, a.Pass)
}

func StartWAFReconciler(ctx context.Context, db *sql.DB, wafURL string, auth WAFAuth) {
	Track(func() {
		ticker := time.NewTicker(reconcileEvery)
		defer ticker.Stop()
		// synced is true once the WAF is known to match the stored
		// configuration. Until then every pass pushes every stored value, so
		// a push that failed (the WAF answered but rejected the credential, or
		// dropped the connection) is retried in 30 s. Once synced, a pass
		// pushes only what the WAF runs differently, which is how a WAF
		// restart between two passes is caught.
		synced := false
		lastOutcome := reconcileOK
		for {
			// The heartbeat on every pass, reachable or not: it says the loop
			// is alive, which is what the worker-staleness alert reads.
			metrics.WorkerHeartbeat("waf_reconciler")
			outcome := reconcileWAF(ctx, db, wafURL, auth, !synced)
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
// otherwise. When force is set it pushes every stored heuristic. Otherwise it
// reads the heuristics the WAF runs (GET /heuristics) and pushes only those
// that differ from the stored ones, so a WAF that restarted between two passes
// and came back on its WAF_H_* defaults is corrected, and a matching WAF is not
// rewritten every 30 seconds. A WAF whose running heuristics cannot be read is
// not taken as matching: every stored value is pushed.
func reconcileWAF(ctx context.Context, db *sql.DB, wafURL string, auth WAFAuth, force bool) reconcileOutcome {
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
	stored := storedHeuristics(db)
	if !force {
		running, err := runningHeuristics(ctx, hc, wafURL, auth)
		if err != nil {
			log.Debug().Err(err).Msg("waf reconcile: running heuristics not readable; pushing every stored value")
		} else {
			stored = differing(stored, running)
		}
	}

	pushed, failed := 0, 0
	for _, hs := range stored {
		key := hs.key
		body, err := json.Marshal(map[string]any{"heuristic": key, "enabled": hs.enabled})
		if err != nil {
			continue
		}
		r, err := http.NewRequestWithContext(ctx, http.MethodPost, wafURL+"/heuristics/toggle", bytes.NewReader(body))
		if err != nil {
			continue
		}
		r.Header.Set("Content-Type", "application/json")
		auth.Apply(r)
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

// heuristicState is one stored heuristic toggle.
type heuristicState struct {
	key     string
	enabled bool
}

// storedHeuristics reads the stored heuristic toggles, in heuristicKeys order.
// A heuristic with no row is left out: the WAF's env default stands.
func storedHeuristics(db *sql.DB) []heuristicState {
	out := make([]heuristicState, 0, len(heuristicKeys))
	for _, key := range heuristicKeys {
		var val string
		if err := db.QueryRow("SELECT setting_value FROM settings WHERE setting_name = ?", key).Scan(&val); err != nil {
			continue
		}
		// "true" only, as the Settings page and every other reader of a
		// boolean setting read it; "1" used to switch on here a heuristic
		// the page showed as off.
		out = append(out, heuristicState{key: key, enabled: val == "true"})
	}
	return out
}

// runningHeuristics asks the WAF which heuristics it runs: GET /heuristics
// answers {"data": {"waf_h_pii": true, ...}}.
func runningHeuristics(ctx context.Context, hc *http.Client, wafURL string, auth WAFAuth) (map[string]bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wafURL+"/heuristics", nil)
	if err != nil {
		return nil, err
	}
	auth.Apply(req)
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET /heuristics answered HTTP %d", resp.StatusCode)
	}
	var body struct {
		Data map[string]bool `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&body); err != nil {
		return nil, err
	}
	if body.Data == nil {
		return nil, errors.New("GET /heuristics carried no data")
	}
	return body.Data, nil
}

// differing keeps the stored toggles the WAF does not run as stored. A
// heuristic the WAF does not report counts as differing.
func differing(stored []heuristicState, running map[string]bool) []heuristicState {
	out := []heuristicState{}
	for _, hs := range stored {
		if on, ok := running[hs.key]; !ok || on != hs.enabled {
			out = append(out, hs)
		}
	}
	return out
}
