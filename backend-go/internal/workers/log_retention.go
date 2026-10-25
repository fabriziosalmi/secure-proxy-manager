package workers

import (
	"context"
	"database/sql"
	"strconv"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/metrics"
)

// StartLogRetention runs a daily cleanup of aged-out proxy_logs rows.
func StartLogRetention(ctx context.Context, db *sql.DB) {
	Track(func() {
		// Run once at startup.
		_ = database.StartupStep("log_retention", func() error { runRetention(db); return nil })
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				log.Info().Msg("log retention worker stopping")
				return
			case <-ticker.C:
				runRetention(db)
			}
		}
	})
	log.Info().Msg("log retention worker started")
}

// AuditRetentionDays bounds audit_log, which nothing pruned: unauthenticated
// failed logins write to it, so it grew without limit. A year, independent of
// log_retention_days, because an audit trail shorter than the traffic logs it
// explains is not much of one.
const AuditRetentionDays = 365

func pruneAuditLog(db *sql.DB) {
	res, err := db.Exec("DELETE FROM audit_log WHERE timestamp < datetime('now', ?)", "-"+strconv.Itoa(AuditRetentionDays)+" days")
	if err != nil {
		log.Warn().Err(err).Msg("audit log retention cleanup failed")
		return
	}
	if n, _ := res.RowsAffected(); n > 0 {
		log.Info().Int64("deleted", n).Int("days", AuditRetentionDays).Msg("audit log retention cleanup done")
	}
}

func runRetention(db *sql.DB) {
	metrics.WorkerHeartbeat("log_retention")
	pruneAuditLog(db)
	var val string
	if err := db.QueryRow("SELECT setting_value FROM settings WHERE setting_name='log_retention_days'").Scan(&val); err != nil {
		// Retention is the ONLY bound on the growth of proxy_logs, the one table
		// whose size tracks traffic. Silence here meant it could be switched off
		// by a typo with no signal: the heartbeat still fired, and the success
		// log line lives inside `if deleted > 0`, so a disabled run and a
		// healthy one looked identical (SECURE-SCAL-03).
		log.Warn().Err(err).Msg("log retention: setting unreadable, NOT pruning; proxy_logs will grow without bound")
		metrics.RetentionDisabled()
		return
	}
	days, err := strconv.Atoi(val)
	if err != nil || days <= 0 {
		log.Warn().Str("log_retention_days", val).
			Msg("log retention: value is not a positive number, NOT pruning; proxy_logs will grow without bound")
		metrics.RetentionDisabled()
		return
	}
	res, err := db.Exec(
		"DELETE FROM proxy_logs WHERE timestamp < datetime('now', ?)",
		"-"+strconv.Itoa(days)+" days",
	)
	if err != nil {
		log.Warn().Err(err).Msg("log retention cleanup failed")
		return
	}
	deleted, _ := res.RowsAffected()
	metrics.RetentionRan(days)
	if deleted > 0 {
		log.Info().Int64("deleted", deleted).Int("days", days).Msg("log retention cleanup done")
	}
}
