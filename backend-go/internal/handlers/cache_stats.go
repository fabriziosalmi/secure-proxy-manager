package handlers

import (
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/rs/zerolog/log"
)

// cacheStatsFile is written by the proxy's watchdog (collect_cache_stats in
// proxy/blacklist_watchdog.py) once a minute, from Squid's cache manager info
// and storedir pages read on localhost. It used to be cache_stats.txt, meant
// for squidclient output that no part of the image could produce, so it was
// never written and the endpoint answered zeros marked simulated.
const cacheStatsFile = "cache_stats.json"

const (
	// A file is out of date after this many missed collections: the watchdog
	// or Squid has stopped answering, and its numbers describe the past.
	cacheStatsStaleIntervals = 3
	// The interval the file states, within these bounds; 60 s otherwise.
	cacheStatsDefaultInterval = 60
	cacheStatsMaxInterval     = 3600
)

// The states of GET /api/cache/statistics.
const (
	cacheStatsCurrent      = "current"       // collected within the last cacheStatsStaleIntervals intervals
	cacheStatsStale        = "stale"         // collected, but not since then: the values are the last ones
	cacheStatsNotCollected = "not_collected" // no file: a proxy older than it, or one that has not collected yet
	cacheStatsUnreadable   = "unreadable"    // a file this backend cannot read: no values
)

// cacheStatsValues are the numbers as Squid printed them, field for field. A
// field Squid did not print, or printed before it had measured anything (its
// hit ratios in the first minute after it starts), is null, never 0.
// Percentages stay percentages: 64.7 is "64.7%".
type cacheStatsValues struct {
	RequestHitRatio5minPct  *float64 `json:"request_hit_ratio_5min_pct"`
	RequestHitRatio60minPct *float64 `json:"request_hit_ratio_60min_pct"`
	ByteHitRatio5minPct     *float64 `json:"byte_hit_ratio_5min_pct"`
	ByteHitRatio60minPct    *float64 `json:"byte_hit_ratio_60min_pct"`
	DiskUsedKB              *int64   `json:"disk_used_kb"`
	DiskCapacityKB          *int64   `json:"disk_capacity_kb"`
	DiskUsedPct             *float64 `json:"disk_used_pct"`
	MemoryUsedKB            *int64   `json:"memory_used_kb"`
	MemoryUsedPct           *float64 `json:"memory_used_pct"`
	UptimeS                 *float64 `json:"uptime_s"`
	StoreEntries            *int64   `json:"store_entries"`
	MemoryObjects           *int64   `json:"memory_objects"`
	DiskObjects             *int64   `json:"disk_objects"`
}

// CacheStatsReport is the body of GET /api/cache/statistics: the state, when
// the values were collected (UTC, "2006-01-02 15:04:05") and how long ago,
// and the values themselves.
type CacheStatsReport struct {
	State       string  `json:"state"`
	CollectedAt *string `json:"collected_at"`
	AgeS        *int64  `json:"age_s"`
	IntervalS   *int64  `json:"interval_s"`
	StaleAfterS *int64  `json:"stale_after_s"`
	cacheStatsValues
}

// readCacheStats reports the proxy's last collection as of now.
func readCacheStats(configDir string, now time.Time) CacheStatsReport {
	raw, err := os.ReadFile(filepath.Join(configDir, cacheStatsFile)) // #nosec G304 -- fixed name in the config dir
	if errors.Is(err, fs.ErrNotExist) {
		return CacheStatsReport{State: cacheStatsNotCollected}
	}
	if err != nil {
		log.Debug().Err(err).Msg("cache_stats.json exists but cannot be read")
		return CacheStatsReport{State: cacheStatsUnreadable}
	}
	var f struct {
		Version     int    `json:"version"`
		CollectedAt *int64 `json:"collected_at"`
		IntervalS   *int64 `json:"interval_s"`
		cacheStatsValues
	}
	if err := json.Unmarshal(raw, &f); err != nil || f.Version != 1 || f.CollectedAt == nil || *f.CollectedAt <= 0 {
		log.Debug().Err(err).Int("version", f.Version).Msg("cache_stats.json is not a version 1 record")
		return CacheStatsReport{State: cacheStatsUnreadable}
	}
	interval := int64(cacheStatsDefaultInterval)
	if f.IntervalS != nil && *f.IntervalS >= 1 && *f.IntervalS <= cacheStatsMaxInterval {
		interval = *f.IntervalS
	}
	staleAfter := cacheStatsStaleIntervals * interval
	// The proxy and the backend share the host clock; a record from the future
	// is at most a rounding of collected_at, not a fresher one.
	age := max(now.Unix()-*f.CollectedAt, 0)
	at := time.Unix(*f.CollectedAt, 0).UTC().Format("2006-01-02 15:04:05")
	state := cacheStatsCurrent
	if age > staleAfter {
		state = cacheStatsStale
	}
	return CacheStatsReport{
		State: state, CollectedAt: &at, AgeS: &age, IntervalS: &interval, StaleAfterS: &staleAfter,
		cacheStatsValues: f.cacheStatsValues,
	}
}

// cacheStatsResponse adds the fields this endpoint answered with before
// collection worked, so a caller written against them keeps working for one
// release (X-API-Version stays 1). They are deprecated: hit_rate and
// byte_hit_rate are the 5-minute ratios, cache_size and max_cache_size the
// disk figures as text, objects_cached the store entries, simulated is true
// whenever the values are not current. hits, misses and requests were never
// measured and are null.
type cacheStatsResponse struct {
	CacheStatsReport
	HitRate       *float64 `json:"hit_rate"`
	ByteHitRate   *float64 `json:"byte_hit_rate"`
	CacheSize     string   `json:"cache_size"`
	MaxCacheSize  string   `json:"max_cache_size"`
	ObjectsCached *int64   `json:"objects_cached"`
	Hits          *int64   `json:"hits"`
	Misses        *int64   `json:"misses"`
	Requests      *int64   `json:"requests"`
	Simulated     bool     `json:"simulated"`
}

func kbText(kb *int64) string {
	if kb == nil {
		return "N/A"
	}
	return strconv.FormatInt(*kb, 10) + " KB"
}

func withLegacyFields(r CacheStatsReport) cacheStatsResponse {
	return cacheStatsResponse{
		CacheStatsReport: r,
		HitRate:          r.RequestHitRatio5minPct,
		ByteHitRate:      r.ByteHitRatio5minPct,
		CacheSize:        kbText(r.DiskUsedKB),
		MaxCacheSize:     kbText(r.DiskCapacityKB),
		ObjectsCached:    r.StoreEntries,
		Simulated:        r.State != cacheStatsCurrent,
	}
}

// CacheStats answers GET /api/cache/statistics from the proxy's last
// collection. No file is "not_collected", never zeros.
func (h *AnalyticsHandlers) CacheStats(w http.ResponseWriter, r *http.Request) {
	writeOK(w, withLegacyFields(readCacheStats(h.cfg.ConfigDir, time.Now())))
}
