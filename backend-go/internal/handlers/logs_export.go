package handlers

import (
	"database/sql"
	"encoding/csv"
	"net/http"
	"strconv"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/workers"
)

// exportPage is how many rows one query of the export reads. The export walks
// the log in id order one page at a time, so no read transaction stays open
// while a slow client downloads, and each page is the same indexed query
// GET /api/logs runs.
const exportPage = 2000

// exportPageDeadline is how long the export may take to write one page. The
// server's WriteTimeout (60 s) covers a whole response, which a large export
// outlasts; the deadline is moved forward as each page goes out instead.
const exportPageDeadline = 60 * time.Second

var exportHeader = []string{
	"id", "timestamp_utc", "source_ip", "internal", "kind", "method", "destination",
	"status", "bytes", "blocked", "reason", "reason_label",
}

// Export streams the rows GET /api/logs would list for the same filters, all
// of them, newest first, as CSV. limit, offset and sort do not apply.
func (h *LogHandlers) Export(w http.ResponseWriter, r *http.Request) {
	f, err := parseLogFilter(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	gdpr := h.gdprEnabled()
	f, err = f.resolveSource(h.db, gdpr)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	internal := h.src.Present()
	rc := http.NewResponseController(w)

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="access-log-`+time.Now().UTC().Format("2006-01-02")+`.csv"`)
	w.Header().Set("Cache-Control", "no-store")
	cw := csv.NewWriter(w)
	if err := cw.Write(exportHeader); err != nil {
		return
	}

	for {
		_ = rc.SetWriteDeadline(time.Now().Add(exportPageDeadline))
		where, args := f.where(internal, true)
		// The conditions are constants with placeholders; every value is bound.
		// #nosec G202
		rows, err := h.db.QueryContext(r.Context(),
			string("SELECT "+logColumns+" FROM proxy_logs WHERE "+where+" ORDER BY id DESC LIMIT ?"), // slopless-disable-line VBC-004 -- SQL text is SQLText from constants and placeholders, values are bound (database/sqltext.go)
			append(args, exportPage)...)
		if err != nil {
			// The header and earlier rows are already sent: the status cannot
			// change any more, so the cut is logged and the file ends short.
			log.Error().Err(err).Msg("logs export: query failed, the file is incomplete")
			break
		}
		n, last, err := writeExportRows(cw, rows, h.src, gdpr)
		rows.Close()
		if err != nil {
			log.Error().Err(err).Msg("logs export: write failed, the file is incomplete")
			break
		}
		cw.Flush()
		if cw.Error() != nil {
			break
		}
		_ = rc.Flush()
		if n < exportPage {
			break
		}
		f.beforeID = last
	}
	cw.Flush()
}

func writeExportRows(cw *csv.Writer, rows *sql.Rows, src *InternalSources, gdpr bool) (n int, last int64, err error) {
	for rows.Next() {
		l, err := scanLogRow(rows)
		if err != nil {
			return n, last, err
		}
		ip := l.srcIP.String
		internal, kind := src.Classify(ip)
		if gdpr {
			ip = maskIP(ip)
		}
		rec := []string{
			strconv.FormatInt(l.id, 10), l.ts.String, ip, strconv.FormatBool(internal), kind,
			l.method.String, l.dest.String, l.status.String, strconv.FormatInt(l.bytes.Int64, 10),
			strconv.FormatBool(l.blocked.Int64 == 1), l.reason.String, workers.ReasonLabel(l.reason.String),
		}
		for i := range rec {
			rec[i] = csvText(rec[i])
		}
		if err := cw.Write(rec); err != nil {
			return n, last, err
		}
		n, last = n+1, l.id
	}
	return n, last, rows.Err()
}

// csvText keeps a cell from being read as a formula. A cell that starts with
// = + - @ (or a tab or carriage return) is a formula to Excel, LibreOffice
// and Sheets, and these fields come from the traffic: a destination, a method
// ("-" on a request Squid could not parse). A leading apostrophe makes the
// spreadsheet show the text as text. The same rule as the audit log export
// (ui/src/pages/Audit.tsx).
func csvText(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}
