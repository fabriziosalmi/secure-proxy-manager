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
	Track(func() {
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
			var persist bool
			offset, persist = tailOnce(db, hub, logPath, offset, squidTail)
			if persist {
				writeOffset(posPath, offset)
			}
		}
	})
	log.Info().Str("path", logPath).Msg("log tailer started")
}

// tailSpec is what differs between the tailers that share tailOnce: how a line
// is parsed, how many lines one tick may take, and what to do with each parsed
// entry.
type tailSpec struct {
	name     string // for log messages
	parse    func(line string) map[string]any
	maxLines int                        // lines per tick; the memory bound
	onEntry  func(entry map[string]any) // may be nil
}

// squidTail is the Squid access-log tailer.
var squidTail = tailSpec{
	name:     "log tailer",
	parse:    parseSquidLine,
	maxLines: maxBatchLines,
	// The proxy's own outcome, counted where every line is already parsed — one
	// Inc on a path that is doing a DB write anyway (SECURE-OBS-01).
	onEntry: func(entry map[string]any) { metrics.ProxyRequest(entry["blocked"] == 1) },
}

// tailOnce reads what has been appended to the log since offset, stores it, and
// returns the offset to continue from. persist is true only when the offset
// moved because rows were committed; on any failure the offset is left where it
// was (or reset to 0 on rotation) and persist is false, so the next tick tries
// again rather than skipping records.
func tailOnce(db *sql.DB, hub *websocket.Hub, logPath string, offset int64, spec tailSpec) (newOffset int64, persist bool) {
	// #nosec G304
	f, err := os.Open(logPath)
	if err != nil {
		return offset, false
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return offset, false
	}
	// Detect log rotation / truncation.
	if fi.Size() < offset {
		offset = 0
	}
	if fi.Size() == offset {
		return offset, false
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return offset, false
	}

	batch, next, seekErr := readBatch(f, fi.Size(), offset, spec)

	// Insert the whole tick in one transaction. If it fails, leave the
	// offset where it was and retry next tick rather than silently
	// dropping rows (and advancing past them).
	if err := insertLogBatch(db, batch); err != nil {
		log.Warn().Err(err).Int("lines", len(batch)).Msg(spec.name + ": batch insert failed, will retry")
		return offset, false
	}
	// Broadcast only committed rows, so a retry does not double-emit.
	broadcastBatch(hub, batch)

	if seekErr != nil {
		return fi.Size(), true
	}
	return next, true
}

// readBatch parses up to maxBatchLines lines from f, which is positioned at
// offset, and returns them with the offset to resume from. seekErr is non-nil
// when the position could not be read back after a complete scan.
func readBatch(f *os.File, size, offset int64, spec tailSpec) (batch []map[string]any, next int64, seekErr error) {
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 256*1024) // 64KB default, 256KB max line

	batch = make([]map[string]any, 0, 256)
	// Bytes consumed by lines we actually processed. Needed because
	// bufio.Scanner reads AHEAD: after an early break, the file position
	// is past the last line we handled, so seeking would skip records.
	var consumed int64
	truncated := false
	for scanner.Scan() {
		raw := scanner.Bytes()
		consumed += int64(len(raw)) + 1 // +1 for the newline the scanner strips
		line := strings.TrimSpace(string(raw))
		if line == "" {
			continue
		}
		entry := spec.parse(line)
		if entry == nil {
			continue
		}
		batch = append(batch, entry)
		if spec.onEntry != nil {
			spec.onEntry(entry)
		}
		if len(batch) >= spec.maxLines {
			truncated = true
			break
		}
	}

	if !truncated {
		next, seekErr = f.Seek(0, io.SeekCurrent)
		return batch, next, seekErr
	}
	// Resume exactly after the last line we processed.
	next = offset + consumed
	if next > size {
		next = size
	}
	log.Debug().Int("lines", len(batch)).Int64("offset", next).
		Msg(spec.name + ": batch capped, continuing next tick")
	return batch, next, nil
}

// broadcastBatch streams committed rows to the WebSocket hub. The hub is
// optional: nil means nothing is streaming. A full hub drops the message.
func broadcastBatch(hub *websocket.Hub, batch []map[string]any) {
	if hub == nil {
		return
	}
	for _, entry := range batch {
		msg, err := json.Marshal(entry)
		if err != nil {
			continue
		}
		select {
		case hub.Broadcast <- msg:
		default:
		}
	}
}

// maxBatchLines bounds the memory a single tailer tick can consume. Without it
// the batch was sized by the BACKLOG: a backend down for an hour, or a traffic
// burst, read every line since the saved offset into one slice of maps against
// a 128M container limit — an OOM kill during recovery, which on restart
// re-read the same backlog and looped. The offset is persisted per batch, so a
// backlog now catches up over successive ticks (SECURE-SCAL-02).
//
// At roughly 500 bytes per parsed entry this caps a tick near 2.5MB, comfortably
// inside the container budget even with the transaction and the dedupe on top.
const maxBatchLines = 5000

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

	// Field 10 (11th): WAF correlation id, present only when the custom `spm`
	// logformat is active AND the WAF stamped X-WAF-Event-Id on a blocked reply.
	// Squid logs '-' when the header is absent (allowed requests, or the stock
	// logformat), which we normalize to empty. Guarded by length so a stock
	// 10-field line still parses with no regression (#107).
	eventID := ""
	if len(fields) >= 11 && fields[10] != "-" {
		eventID = fields[10]
	}

	return map[string]any{
		"timestamp":      timestamp,
		"unix_timestamp": unixSec,
		// One name for one concept. The address used to be carried twice in the
		// same map — client_ip for the WebSocket payload and source_ip for the
		// DB insert — and appeared as a third name, ip_address, in the clients
		// endpoint. source_ip is what the schema and the highest-volume insert
		// already use (SECURE-DOM-08).
		"source_ip":   clientIP,
		"method":      method,
		"destination": destination,
		"status":      statusStr,
		"bytes":       bytesInt,
		"elapsed_ms":  elapsed,
		"blocked":     blocked,
		"event_id":    eventID,
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
		`INSERT INTO proxy_logs(timestamp, unix_timestamp, source_ip, method, destination, status, bytes, elapsed_ms, blocked, event_id)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
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
			e["event_id"],
		); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}
