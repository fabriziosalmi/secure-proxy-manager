package handlers

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
	// The runtime image has no zoneinfo; this embeds the IANA database so a
	// viewer's zone ("Europe/Rome") resolves the same on every image.
	_ "time/tzdata"

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

// BlockedByDay counts the blocked client requests, from sources other than
// internal, of each of the last 7 calendar days (today included) in the zone
// tz (an IANA name, default UTC), by the rule that blocked them. Every day is
// returned, a day without blocks with blocked 0 and no reasons. reasons are
// the totals of the 7 days, largest first; each carries the API's label.
func (h *AnalyticsHandlers) BlockedByDay(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.URL.Query().Get("tz"))
	if name == "" {
		name = "UTC"
	}
	// "Local" is the server's zone, not the viewer's.
	if len(name) > 64 || name == "Local" {
		writeError(w, http.StatusBadRequest, "tz must be an IANA time zone name such as Europe/Rome")
		return
	}
	loc, err := time.LoadLocation(name)
	if err != nil {
		writeError(w, http.StatusBadRequest, "tz must be an IANA time zone name such as Europe/Rome")
		return
	}

	bounds := dayBounds(analyticsNow(), loc, blockedByDayDays)
	internal := h.src.Present()
	ext, extArgs := notInternal(internal)

	// One CASE arm per day, newest first: a row is in the first day whose
	// midnight it is not before.
	var bucket strings.Builder
	bucket.WriteString("CASE")
	args := make([]any, 0, blockedByDayDays+2+len(extArgs))
	for i := blockedByDayDays - 1; i > 0; i-- {
		bucket.WriteString(" WHEN unix_timestamp >= ? THEN ")
		bucket.WriteString(strconv.Itoa(i))
		args = append(args, bounds[i].Unix())
	}
	bucket.WriteString(" ELSE 0 END")
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
	rows, err := h.db.Query(`SELECT `+bucket.String()+` AS day, block_reason, COUNT(*) AS cnt FROM proxy_logs
		WHERE blocked = 1 AND unix_timestamp >= ? AND unix_timestamp < ? AND `+clientRows+` AND `+ext+`
		GROUP BY day, block_reason ORDER BY day, cnt DESC, block_reason`, args...)
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
		// The internal sources whose rows no day counts.
		"internal_sources": len(internal),
	})
}
