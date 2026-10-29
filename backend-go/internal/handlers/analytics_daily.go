package handlers

import (
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
	"net/http"
	"sort"
	"strings"
	"time"
	// The runtime image has no zoneinfo; this embeds the IANA database so a
	// viewer's zone ("Europe/Rome") resolves the same on every image.
	_ "time/tzdata"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/privacy"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/workers"
)

// blockedByDayDays is how many calendar days BlockedByDay returns: today and
// the days before it.
const blockedByDayDays = 7

// analyticsNow is the clock of BlockedByDay; tests replace it.
var analyticsNow = time.Now

// dayReasons is one calendar day of BlockedByDay.
type dayReasons struct {
	// Date is the day in the requested zone, YYYY-MM-DD.
	Date string `json:"date"`
	// Start and End are the Unix times of its midnights: rows with Start <=
	// unix_timestamp < End are in the day. A day is 23 or 25 hours long when
	// the zone changes its clock.
	Start   int64            `json:"start"`
	End     int64            `json:"end"`
	Blocked int              `json:"blocked"`
	Reasons []map[string]any `json:"reasons"`
}

// dayBounds returns the midnights of the n calendar days in loc that end with
// the day containing now, oldest first, and the midnight after the last.
func dayBounds(now time.Time, loc *time.Location, n int) []time.Time {
	local := now.In(loc)
	y, m, d := local.Date()
	out := make([]time.Time, 0, n+1)
	for i := n - 1; i >= -1; i-- {
		// time.Date normalises the day and resolves the zone's offset on that
		// date, so a day across a clock change keeps its true length.
		out = append(out, time.Date(y, m, d-i, 0, 0, 0, 0, loc))
	}
	return out
}

// viewerZone reads ?tz=, an IANA zone name, UTC when absent. ok is false for
// a name that is not one, and for "Local", which is the server's zone, not
// the viewer's.
func viewerZone(r *http.Request) (*time.Location, bool) {
	name := strings.TrimSpace(r.URL.Query().Get("tz"))
	if name == "" {
		name = "UTC"
	}
	if len(name) > 64 || name == "Local" {
		return nil, false
	}
	loc, err := time.LoadLocation(name)
	if err != nil {
		return nil, false
	}
	return loc, true
}

// BlockedByDay counts the blocked client requests, from sources other than
// internal, of each of the last 7 calendar days (today included) in the zone
// tz (an IANA name, default UTC), by the rule that blocked them. Every day is
// returned, a day without blocks with blocked 0 and no reasons. reasons are
// the totals of the 7 days, largest first; each carries the API's label.
// internal_sources is how many internal sources sent client requests in
// those 7 days (networks in GDPR mode), the requests the days leave out.
func (h *AnalyticsHandlers) BlockedByDay(w http.ResponseWriter, r *http.Request) {
	loc, ok := viewerZone(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "tz must be an IANA time zone name such as Europe/Rome")
		return
	}

	bounds := dayBounds(analyticsNow(), loc, blockedByDayDays)
	internal := h.src.Present()
	ext, extArgs := notInternal(internal)

	// One CASE arm per day, newest first: a row is in the first day whose
	// midnight it is not before. The midnight and the day's index are both
	// bound, so the text is constants and placeholders only.
	var bucket database.SQLText = "CASE"
	args := make([]any, 0, 2*blockedByDayDays+2+len(extArgs))
	for i := blockedByDayDays - 1; i > 0; i-- {
		bucket += " WHEN unix_timestamp >= ? THEN ?"
		args = append(args, bounds[i].Unix(), i)
	}
	bucket += " ELSE 0 END"
	args = append(args, bounds[0].Unix(), bounds[blockedByDayDays].Unix())
	args = append(args, extArgs...)

	days := make([]dayReasons, blockedByDayDays)
	for i := range days {
		days[i] = dayReasons{
			Date:    bounds[i].Format("2006-01-02"),
			Start:   bounds[i].Unix(),
			End:     bounds[i+1].Unix(),
			Reasons: []map[string]any{},
		}
	}
	totals := map[string]int{}

	// #nosec G202 -- the CASE is built from constants and placeholders, clientRows and ext are constants and placeholders; values are bound.
	rows, err := h.db.Query(string(`SELECT `+bucket+` AS day, block_reason, COUNT(*) AS cnt FROM proxy_logs
		WHERE blocked = 1 AND unix_timestamp >= ? AND unix_timestamp < ? AND `+clientRows+` AND `+ext+`
		GROUP BY day, block_reason ORDER BY day, cnt DESC, block_reason`), args...)
	if err != nil {
		writeInternalError(w, "blocked_by_day", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var day, cnt int
		var reason string
		if rows.Scan(&day, &reason, &cnt) != nil || day < 0 || day >= blockedByDayDays {
			continue
		}
		days[day].Blocked += cnt
		days[day].Reasons = append(days[day].Reasons, map[string]any{"reason": reason, "label": workers.ReasonLabel(reason), "count": cnt})
		totals[reason] += cnt
	}
	if err := rows.Err(); err != nil {
		writeInternalError(w, "blocked_by_day", err)
		return
	}

	keys := make([]string, 0, len(totals))
	for k := range totals {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if totals[keys[i]] != totals[keys[j]] {
			return totals[keys[i]] > totals[keys[j]]
		}
		return keys[i] < keys[j]
	})
	reasons := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		reasons = append(reasons, map[string]any{"reason": k, "label": workers.ReasonLabel(k), "count": totals[k]})
	}

	writeOK(w, map[string]any{
		"tz":      loc.String(),
		"days":    days,
		"reasons": reasons,
		// The internal sources that sent client requests in these 7 days and
		// that no day counts. It used to be every internal address ever seen
		// in the log, sinkhole rows included, so the page said 4 where the
		// Clients page, counting the same 7 days, said 2.
		"internal_sources": h.internalInWindow(bounds[0].Unix(), bounds[blockedByDayDays].Unix(), internal),
	})
}

// internalInWindow counts the internal sources with client rows (clientRows)
// logged at or after start and before end: distinct addresses, or distinct
// networks in GDPR mode, as clients/statistics counts them.
func (h *AnalyticsHandlers) internalInWindow(start, end int64, internal []string) int {
	in, inArgs := onlyInternal(internal)
	if privacy.Enabled(h.db) {
		return h.countDistinctNetworksBetween(start, end, in, inArgs)
	}
	var n int
	args := append([]any{start, end}, inArgs...)
	// #nosec G202 -- clientRows and in are constants and placeholders; values are bound.
	if err := h.db.QueryRow(string(`SELECT COUNT(DISTINCT source_ip) FROM proxy_logs
		WHERE unix_timestamp >= ? AND unix_timestamp < ? AND source_ip != '' AND `+clientRows+` AND `+in), args...).Scan(&n); err != nil {
		return 0
	}
	return n
}
