package workers

import (
	"context"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/metrics"
)

// IntegrityCheckDelay is how long after start-up the full integrity check
// begins, so it does not compete with the first requests at 0.25 CPU.
var IntegrityCheckDelay = 30 * time.Second

// StartIntegrityCheck runs the full PRAGMA integrity_check of the database at
// dbPath once, IntegrityCheckDelay after start-up, on a connection of its own
// (database.IntegrityCheck). It used to run before serving, where on a 400 MB
// database it took over a minute at the compose CPU limit and filled a 50 MB
// page cache. Init still runs quick_check, fatally, before serving.
//
// A failure is reported as loudly as the process can while it keeps running:
// an error line, spm_db_integrity_ok 0 and a 503 from /readyz, so the
// container's healthcheck reports it unhealthy.
func StartIntegrityCheck(ctx context.Context, dbPath string) {
	Track(func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(IntegrityCheckDelay):
		}
		RunIntegrityCheck(ctx, dbPath)
	})
	log.Info().Dur("delay", IntegrityCheckDelay).Msg("integrity check worker started")
}

// RunIntegrityCheck runs one full check and records its outcome.
func RunIntegrityCheck(ctx context.Context, dbPath string) {
	start := time.Now()
	err := database.IntegrityCheck(ctx, dbPath)
	if ctx.Err() != nil {
		// Cut short by shutdown: not an outcome.
		return
	}
	database.RecordIntegrity(err)
	metrics.IntegrityChecked(err == nil)
	if err != nil {
		log.Error().Err(err).Str("path", dbPath).Dur("took", time.Since(start)).
			Msg("DATABASE INTEGRITY CHECK FAILED: the database is damaged; /readyz reports unready. " +
				"Stop the stack and restore the last good backup (scripts/restore.sh)")
		return
	}
	log.Info().Dur("took", time.Since(start)).Msg("database integrity check passed")
}
