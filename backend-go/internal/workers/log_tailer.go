// Package workers contains background goroutines for the proxy manager.
package workers

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/metrics"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/websocket"
)

// StartLogTailer tails the Squid access log and inserts rows into proxy_logs.
// It also broadcasts a JSON representation to the WebSocket hub. stateDir is a
// backend-writable directory (e.g. /data) where the tail offset is persisted —
// the log directory itself is typically not writable by the backend's user.
func StartLogTailer(ctx context.Context, db *sql.DB, logPath, stateDir string, hub *websocket.Hub) {
	posPath := filepath.Join(stateDir, filepath.Base(logPath)+".pos")
	go func() {
		// Restore the persisted byte offset so a backend restart does not re-read
		// the whole file from the start and re-insert every still-present line.
		offset := readOffset(posPath)
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				log.Info().Msg("log tailer stopping")
				return
			case <-ticker.C:
			}
			metrics.WorkerHeartbeat("log_tailer")
			// #nosec G304
			f, err := os.Open(logPath)
			if err != nil {
				continue
			}
			fi, err := f.Stat()
			if err != nil {
				f.Close()
				continue
			}
			// Detect log rotation / truncation.
			if fi.Size() < offset {
				offset = 0
			}
			if fi.Size() == offset {
				f.Close()
				continue
			}
			if _, err := f.Seek(offset, io.SeekStart); err != nil {
				f.Close()
				continue
			}
			scanner := bufio.NewScanner(f)
			scanner.Buffer(make([]byte, 64*1024), 256*1024) // 64KB default, 256KB max line
			batch := make([]map[string]any, 0, 256)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" {
					continue
				}
				if entry := parseSquidLine(line); entry != nil {
					batch = append(batch, entry)
				}
			}
			newOffset, seekErr := f.Seek(0, io.SeekCurrent)
			f.Close()

			// Insert the whole tick in one transaction. If it fails, leave the
			// offset where it was and retry next tick rather than silently
			// dropping rows (and advancing past them).
			if err := insertLogBatch(db, batch); err != nil {
				log.Warn().Err(err).Int("lines", len(batch)).Msg("log tailer: batch insert failed, will retry")
				continue
			}
			// Broadcast only committed rows, so a retry does not double-emit.
			for _, entry := range batch {
				if msg, err := json.Marshal(entry); err == nil {
					select {
					case hub.Broadcast <- msg:
					default:
					}
				}
			}

			if seekErr == nil {
				offset = newOffset
			} else {
				offset = fi.Size()
			}
			writeOffset(posPath, offset)
		}
	}()
	log.Info().Str("path", logPath).Msg("log tailer started")
}

func readOffset(posPath string) int64 {
	data, err := os.ReadFile(posPath) // #nosec G304 — derived from configured data dir
	if err != nil {
		return 0
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

func writeOffset(posPath string, offset int64) {
	tmp := posPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(strconv.FormatInt(offset, 10)), 0o600); err != nil {
		log.Warn().Err(err).Msg("log tailer: cannot persist offset (will re-read on restart)")
		return
	}
	if err := os.Rename(tmp, posPath); err != nil {
		log.Warn().Err(err).Msg("log tailer: cannot move offset file into place")
	}
}

// squid native access log format:
// {unix_ts}.{ms}  {elapsed}  {client_ip}  {action}/{code}  {bytes}  {method}  {url}  {ident}  {peer}/{dest}  {type}
// Fields are separated by whitespace (one or more spaces).
func parseSquidLine(line string) map[string]any {
	fields := strings.Fields(line)
	if len(fields) < 10 {
		return nil
	}
	// Field 0: unix timestamp with ms.
	tsParts := strings.SplitN(fields[0], ".", 2)
	unixSec, _ := strconv.ParseInt(tsParts[0], 10, 64)
	timestamp := time.Unix(unixSec, 0).UTC().Format("2006-01-02 15:04:05")

	// Field 2: client IP.
	clientIP := fields[2]

	// Field 3: action/status  (TCP_MISS/200).
	actionStatus := fields[3]
	acStatus := strings.SplitN(actionStatus, "/", 2)
	action := acStatus[0]
	statusCode := ""
	if len(acStatus) > 1 {
		statusCode = acStatus[1]
	}

	// Field 4: bytes.
	bytesInt, _ := strconv.ParseInt(fields[4], 10, 64)

	// Field 5: method.
	method := fields[5]

	// Field 6: URL / destination.
	destination := fields[6]

	// Field 1: elapsed.
	elapsed, _ := strconv.ParseInt(fields[1], 10, 64)

	statusStr := action + "/" + statusCode

	blocked := 0
	if isBlockedStatus(statusStr) {
		blocked = 1
	}

	return map[string]any{
		"timestamp":      timestamp,
		"unix_timestamp": unixSec,
		"client_ip":      clientIP,
		"source_ip":      clientIP, // kept for DB insert compatibility
		"method":         method,
		"destination":    destination,
		"status":         statusStr,
		"bytes":          bytesInt,
		"elapsed_ms":     elapsed,
		"blocked":        blocked,
	}
}

// isBlockedStatus reports whether a Squid "action/code" status string denotes a
// blocked request. It mirrors the SQL backfill predicate
// (status LIKE '%DENIED%' OR '%403%' OR '%BLOCKED%'). SQLite LIKE is
// ASCII-case-insensitive, so we upper-case here to match it byte-for-byte —
// then a row's flag is identical whether it was written at insert or by the
// one-time backfill, even for a non-standard lowercase action tag.
func isBlockedStatus(status string) bool {
	up := strings.ToUpper(status)
	return strings.Contains(up, "DENIED") ||
		strings.Contains(up, "403") ||
		strings.Contains(up, "BLOCKED")
}

// insertLogBatch inserts a tick's worth of entries in a single transaction.
// Populating unix_timestamp (and elapsed_ms) is what makes idx_proxy_logs_unix_ts
// usable for time-window analytics — both columns were previously never written.
func insertLogBatch(db *sql.DB, entries []map[string]any) error {
	if len(entries) == 0 {
		return nil
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(
		`INSERT INTO proxy_logs(timestamp, unix_timestamp, source_ip, method, destination, status, bytes, elapsed_ms, blocked)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, e := range entries {
		// blocked is NOT NULL; coalesce a missing/partial entry to 0 so an
		// incomplete map can't violate the constraint (parseSquidLine always
		// sets it, but insertLogBatch stays robust to partial maps).
		blocked := e["blocked"]
		if blocked == nil {
			blocked = 0
		}
		if _, err := stmt.Exec(
			e["timestamp"], e["unix_timestamp"], e["source_ip"], e["method"],
			e["destination"], e["status"], e["bytes"], e["elapsed_ms"], blocked,
		); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}
