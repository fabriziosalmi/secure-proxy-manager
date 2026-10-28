package database

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
)

// ReasonDNSReconstructed is the block reason this step writes. It is defined
// here, where the step runs, and workers.ReasonDomainBlacklistDNSReconstructed
// is this value, so the vocabulary and its labels have one source.
const ReasonDNSReconstructed = "domain_blacklist_dns_reconstructed"

// The rule, for a row logged before reasons were recorded (unclassified):
//   - its status ends in /503: Squid's answer when it connected to the
//     sinkhole's 0.0.0.0 or :: (TCP_TUNNEL/503, TCP_MISS_ABORTED/503, ...);
//   - it is a client request: the dnsmasq rows (method DNS) are not touched;
//   - its host (HostKey, lower case) is a name the sinkhole answers: a
//     domain_blacklist entry stored as "name" or "*.name" (the hosts file
//     holds the exact name either way, writeDnsmasqBlocklist), compared in
//     lower case as DNS does, and not excluded by the domain whitelist;
//   - it was logged at or after that entry was added (added_date): a 503
//     from before the listing was an origin or network failure, not the
//     sinkhole. A name stored in both forms counts from the earlier entry.
const sinkholeCandidate = `block_reason = 'unclassified' AND status LIKE '%/503' AND IFNULL(method, '') != 'DNS'`

// The bound on memory: the backend runs in 128 MiB, temp_store is MEMORY (a
// temporary table lives in RAM) and, when this step was written, the
// start-up integrity check of a 400 MB database took the process to about
// 118 MiB, by filling a 50 MB page cache (now PageCacheKiB, db.go). So
// nothing here is held in memory in proportion to the blacklist or to
// proxy_logs:
//   - a lower-case entry is found through the UNIQUE index on
//     domain_blacklist.domain, two probes per candidate row, with no copy;
//   - the entries that hold an upper-case letter, which that index cannot
//     find from a lower-case host (imports and the auto-refresh keep the
//     feed's case), are copied lower-cased into spm_reconstruct_mixed, a
//     table in the database file, so its pages go through the page cache
//     like any other; it is created and dropped inside the transaction;
//   - the rows are updated in id ranges of reconstructBatch, so one
//     statement's journal covers one range, not the table.
//
// Measured on 1,000,000 rows and 640,000 names, in a container with the
// backend's limits: start-up peaks at 120 MiB of anonymous memory with the
// step and 118 MiB without it. A temporary table of 640,000 upper-case
// entries took the step to 170 MiB, and an all-in-RAM first version to 400.
// The step also adds no page cache of its own: it runs on the pool's most
// recently used connection, the one the start-up check just filled.
var (
	loggedAt SQLText = `COALESCE(unix_timestamp, CAST(strftime('%s', timestamp) AS INTEGER))`
	rowHost          = `lower(` + HostKey("destination") + `)`
	listed   SQLText = `strftime('%s', b.added_date) IS NOT NULL
	   AND NOT EXISTS (SELECT 1 FROM domain_whitelist w WHERE w.type = 'fqdn' AND w.domain = b.domain)`

	createMixedCase = `CREATE TABLE main.spm_reconstruct_mixed (name TEXT PRIMARY KEY, added_unix INTEGER NOT NULL) WITHOUT ROWID`
	fillMixedCase   = `INSERT INTO main.spm_reconstruct_mixed(name, added_unix)
	 SELECT lower(CASE WHEN b.domain LIKE '*.%' THEN substr(b.domain, 3) ELSE b.domain END),
	        CAST(strftime('%s', b.added_date) AS INTEGER)
	 FROM domain_blacklist b
	 WHERE b.domain != lower(b.domain) AND ` + listed + `
	 ON CONFLICT(name) DO UPDATE SET added_unix = MIN(added_unix, excluded.added_unix)`
	// The reason and the id range are bound; every fragment is a constant.
	reconstructRange = `UPDATE proxy_logs SET blocked = 1, block_reason = ?
	 WHERE id > ? AND id <= ? AND ` + sinkholeCandidate + `
	   AND (EXISTS (SELECT 1 FROM domain_blacklist b
	                WHERE b.domain IN (` + rowHost + `, '*.' || ` + rowHost + `)
	                  AND ` + listed + `
	                  AND ` + loggedAt + ` >= CAST(strftime('%s', b.added_date) AS INTEGER))
	        OR ` + loggedAt + ` >= (SELECT m.added_unix FROM main.spm_reconstruct_mixed m WHERE m.name = ` + rowHost + `))`
)

// reconstructBatch is the id range one UPDATE covers.
const reconstructBatch = 2000

// reconstructSinkholedBlocks is schema version 3: the client requests the DNS
// sinkhole blocked before block reasons were recorded, which were logged as a
// /503 with blocked = 0 and so counted as not blocked, are given the reason
// domain_blacklist_dns_reconstructed and blocked = 1, by the rule above.
//
// It runs once: every UPDATE and PRAGMA user_version = 3 commit in one
// transaction, so a database that has the version never runs it again, and a
// failure leaves both the rows and the version as they were. Init runs it
// before any worker starts, so no row written by this release can be reached.
func reconstructSinkholedBlocks(db *sql.DB) error {
	start := time.Now()
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op once committed

	for _, s := range []string{createMixedCase, string(fillMixedCase)} {
		if _, err := tx.Exec(s); err != nil {
			return fmt.Errorf("blacklist entries with upper-case letters: %w", err)
		}
	}
	var mixed int
	var lo, hi sql.NullInt64
	if err := tx.QueryRow(`SELECT (SELECT COUNT(*) FROM main.spm_reconstruct_mixed),
		(SELECT MIN(id) FROM proxy_logs), (SELECT MAX(id) FROM proxy_logs)`).Scan(&mixed, &lo, &hi); err != nil {
		return err
	}
	var rows int64
	if lo.Valid {
		for from := lo.Int64 - 1; from < hi.Int64; from += reconstructBatch {
			res, err := tx.Exec(string(reconstructRange), ReasonDNSReconstructed, from, from+reconstructBatch)
			if err != nil {
				return fmt.Errorf("reconstruct sinkholed requests: %w", err)
			}
			n, err := res.RowsAffected()
			if err != nil {
				return err
			}
			rows += n
		}
	}
	if _, err := tx.Exec(`DROP TABLE main.spm_reconstruct_mixed`); err != nil {
		return err
	}
	if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", 3)); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	log.Info().Int("version", 3).Int64("rows", rows).Int("upper_case_entries", mixed).Dur("took", time.Since(start)).
		Msg("schema migration: requests the DNS sinkhole blocked before reasons were recorded are counted as blocked, reason " + ReasonDNSReconstructed)
	return nil
}
