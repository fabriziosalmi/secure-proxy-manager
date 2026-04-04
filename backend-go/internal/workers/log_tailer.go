// Package workers contains background goroutines for the proxy manager.
package workers

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/websocket"
)

// StartLogTailer tails the Squid access log and inserts rows into proxy_logs.
// It also broadcasts a JSON representation to the WebSocket hub.
func StartLogTailer(ctx context.Context, db *sql.DB, logPath string, hub *websocket.Hub) {
	go func() {
		var offset int64
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				log.Info().Msg("log tailer stopping")
				return
			case <-ticker.C:
			}
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
			// Detect log rotation.
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
			buf, err := io.ReadAll(f)
			f.Close()
			if err != nil {
				continue
			}
			offset += int64(len(buf))
			lines := strings.Split(string(buf), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				entry := parseSquidLine(line)
				if entry == nil {
					continue
				}
				insertLogEntry(db, entry)
				if msg, err := json.Marshal(entry); err == nil {
					select {
					case hub.Broadcast <- msg:
					default:
					}
				}
			}
		}
	}()
	log.Info().Str("path", logPath).Msg("log tailer started")
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

	return map[string]any{
		"timestamp":   timestamp,
		"client_ip":   clientIP,
		"source_ip":   clientIP, // kept for DB insert compatibility
		"method":      method,
		"destination": destination,
		"status":      statusStr,
		"bytes":       bytesInt,
		"elapsed_ms":  elapsed,
	}
}

func insertLogEntry(db *sql.DB, entry map[string]any) {
	_, err := db.Exec(
		`INSERT INTO proxy_logs(timestamp, source_ip, method, destination, status, bytes)
		 VALUES(?, ?, ?, ?, ?, ?)`,
		entry["timestamp"], entry["source_ip"], entry["method"],
		entry["destination"], entry["status"], entry["bytes"],
	)
	if err != nil {
		log.Debug().Err(err).Msg("insert log entry failed")
	}
}
