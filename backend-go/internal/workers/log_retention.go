package workers

import (
	"database/sql"
	"strconv"
	"time"

	"github.com/rs/zerolog/log"
)

// StartLogRetention runs a daily cleanup of aged-out proxy_logs rows.
func StartLogRetention(db *sql.DB) {
	go func() {
		// Run once at startup.
		runRetention(db)
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			runRetention(db)
		}
	}()
	log.Info().Msg("log retention worker started")
}

func runRetention(db *sql.DB) {
	var val string
	if err := db.QueryRow("SELECT setting_value FROM settings WHERE setting_name='log_retention_days'").Scan(&val); err != nil {
		return
	}
	days, err := strconv.Atoi(val)
	if err != nil || days <= 0 {
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
	if deleted > 0 {
		log.Info().Int64("deleted", deleted).Int("days", days).Msg("log retention cleanup done")
	}
}
