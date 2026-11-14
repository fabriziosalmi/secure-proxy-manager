package handlers

import (
	"net/http"
	"time"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/metrics"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/workers"
)

// cacheByDayDays is how many calendar days CacheByDay returns, as
// BlockedByDay: today and the days before it.
const cacheByDayDays = 7

// cacheCounts is one count per cache outcome (workers.CacheOutcomes), every
// outcome present.
type cacheCounts map[string]int64

func newCacheCounts() cacheCounts {
	c := make(cacheCounts, len(workers.CacheOutcomes))
	for _, o := range workers.CacheOutcomes {
		c[o] = 0
	}
	return c
}

// cacheDay is one calendar day of CacheByDay.
type cacheDay struct {
	Date     string      `json:"date"`
	Start    int64       `json:"start"`
	End      int64       `json:"end"`
	Requests cacheCounts `json:"requests"`
	Bytes    cacheCounts `json:"bytes"`
}

// CacheByDay says what the proxy's cache did with the client requests of
// each of the last 7 calendar days (today included) in the zone tz (an IANA
// name, default UTC): requests and bytes sent to the clients, by outcome
// (workers.CacheOutcome). It counts the rows BlockedByDay counts: client
// requests, no DNS sinkhole rows, nothing from the stack's own addresses.
// It reads the access log rows, not Squid's counters, so a restart of the
// proxy does not empty it.
func (h *AnalyticsHandlers) CacheByDay(w http.ResponseWriter, r *http.Request) {
	loc, ok := viewerZone(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "tz must be an IANA time zone name such as Europe/Rome")
		return
	}

	bounds := dayBounds(analyticsNow(), loc, cacheByDayDays)
	internal := h.src.Present()
	ext, extArgs := notInternal(internal)
	bucket, args := dayBucket(bounds)
	args = append(args, bounds[0].Unix(), bounds[cacheByDayDays].Unix())
	args = append(args, extArgs...)

	days := make([]cacheDay, cacheByDayDays)
	for i := range days {
		days[i] = cacheDay{
			Date:     bounds[i].Format("2006-01-02"),
			Start:    bounds[i].Unix(),
			End:      bounds[i+1].Unix(),
			Requests: newCacheCounts(),
			Bytes:    newCacheCounts(),
		}
	}
	totalRequests, totalBytes := newCacheCounts(), newCacheCounts()

	// Grouped by the status as stored: a few dozen distinct values a week,
	// classified here so the classes are the ones the metrics use.
	// #nosec G202 -- the CASE is built from constants and placeholders, clientRows and ext are constants and placeholders; values are bound.
	rows, err := h.db.Query(string(`SELECT `+bucket+` AS day, IFNULL(status, ''), IFNULL(blocked, 0), COUNT(*), IFNULL(SUM(bytes), 0)
		FROM proxy_logs
		WHERE unix_timestamp >= ? AND unix_timestamp < ? AND `+clientRows+` AND `+ext+`
		GROUP BY day, status, blocked`), args...)
	if err != nil {
		writeInternalError(w, "cache_by_day", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var day, blocked int
		var status string
		var n, b int64
		if rows.Scan(&day, &status, &blocked, &n, &b) != nil || day < 0 || day >= cacheByDayDays {
			continue
		}
		o := workers.CacheOutcome(status, blocked == 1)
		days[day].Requests[o] += n
		days[day].Bytes[o] += b
		totalRequests[o] += n
		totalBytes[o] += b
	}
	if err := rows.Err(); err != nil {
		writeInternalError(w, "cache_by_day", err)
		return
	}

	outcomes := make([]map[string]string, 0, len(workers.CacheOutcomes))
	for _, o := range workers.CacheOutcomes {
		outcomes = append(outcomes, map[string]string{"outcome": o, "label": workers.CacheOutcomeLabel(o)})
	}
	writeOK(w, map[string]any{
		"tz":               loc.String(),
		"outcomes":         outcomes,
		"days":             days,
		"totals":           map[string]cacheCounts{"requests": totalRequests, "bytes": totalBytes},
		"internal_sources": h.internalInWindow(bounds[0].Unix(), bounds[cacheByDayDays].Unix(), internal),
	})
}

// CacheStoreReader reads the proxy's last cache statistics from configDir
// for /metrics: false when there is no readable record.
func CacheStoreReader(configDir string) func() (metrics.CacheStore, bool) {
	return func() (metrics.CacheStore, bool) {
		r := readCacheStats(configDir, time.Now())
		if r.State != cacheStatsCurrent && r.State != cacheStatsStale {
			return metrics.CacheStore{}, false
		}
		var age int64
		if r.AgeS != nil {
			age = *r.AgeS
		}
		return metrics.CacheStore{
			AgeS:           age,
			DiskUsedKB:     r.DiskUsedKB,
			DiskCapacityKB: r.DiskCapacityKB,
			MemoryUsedKB:   r.MemoryUsedKB,
			Objects:        r.StoreEntries,
		}, true
	}
}
