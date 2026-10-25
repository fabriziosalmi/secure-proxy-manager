package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"
)

// egressRewriteListed caps how many rewritten entries the audit row names.
const egressRewriteListed = 50

// rewriteEgressWildcards is schema version 5. The egress allowlist goes to
// Squid as a dstdomain list, where ".example.com" is the domain and every name
// under it and "*.example.com" is a literal name that matches nothing. The add
// and restore paths refuse "*." since this release; this step rewrites the
// entries stored before, so an allowlist that was meant to let a domain
// through does so. An entry whose ".name" form is already listed is removed
// instead, since the list holds each entry once. One audit row by "system"
// names what changed; the startup export then writes the list Squid reads.
func rewriteEgressWildcards(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op once committed

	rows, err := tx.Query(`SELECT id, entry FROM dst_allowlist WHERE type = 'domain' AND entry LIKE '*.%'`)
	if err != nil {
		return err
	}
	type wildcard struct {
		id    int64
		entry string
	}
	var found []wildcard
	for rows.Next() {
		var w wildcard
		if err := rows.Scan(&w.id, &w.entry); err != nil {
			rows.Close()
			return err
		}
		found = append(found, w)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	var rewritten, dropped int
	var named []string
	for _, w := range found {
		dotted := strings.TrimPrefix(w.entry, "*")
		if dotted == "." {
			// "*." names no domain at all: nothing to rewrite it to.
			if _, err := tx.Exec(`DELETE FROM dst_allowlist WHERE id = ?`, w.id); err != nil {
				return err
			}
			dropped++
			continue
		}
		var exists int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM dst_allowlist WHERE entry = ?`, dotted).Scan(&exists); err != nil {
			return err
		}
		if exists > 0 {
			if _, err := tx.Exec(`DELETE FROM dst_allowlist WHERE id = ?`, w.id); err != nil {
				return err
			}
			dropped++
			continue
		}
		if _, err := tx.Exec(`UPDATE dst_allowlist SET entry = ? WHERE id = ?`, dotted, w.id); err != nil {
			return err
		}
		rewritten++
		if len(named) < egressRewriteListed {
			named = append(named, w.entry+" > "+dotted)
		}
	}

	if rewritten+dropped > 0 {
		details, err := json.Marshal(map[string]any{"rewritten": rewritten, "dropped": dropped, "entries": named})
		if err != nil {
			return err
		}
		if _, err := tx.Exec(
			"INSERT INTO audit_log(username,action,target,details) VALUES('system','rewrite_egress_wildcards','egress_allowlist',?)",
			string(details),
		); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", 5)); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	log.Info().Int("version", 5).Int("rewritten", rewritten).Int("dropped", dropped).
		Msg("schema migrated: egress entries written as *.name now read .name")
	return nil
}
