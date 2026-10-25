package handlers

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// What the watchdog wrote for the Squid 7.7 info and storedir pages in
// tests/python/fixtures (collect_cache_stats, json.dumps with sort_keys).
const watchdogCacheStats = `{"byte_hit_ratio_5min_pct": 91.6, "byte_hit_ratio_60min_pct": 91.6, "collected_at": 1792930528, "disk_capacity_kb": 51200, "disk_objects": 11, "disk_used_kb": 252, "disk_used_pct": 0.5, "interval_s": 60, "memory_objects": 11, "memory_used_kb": 468, "memory_used_pct": 0.2, "request_hit_ratio_5min_pct": 64.7, "request_hit_ratio_60min_pct": 64.7, "store_entries": 64, "uptime_s": 210.475, "version": 1}` + "\n"

const watchdogCollectedAt = 1792930528 // 2026-10-25 12:15:28 UTC

var valueKeys = []string{
	"request_hit_ratio_5min_pct", "request_hit_ratio_60min_pct", "byte_hit_ratio_5min_pct", "byte_hit_ratio_60min_pct",
	"disk_used_kb", "disk_capacity_kb", "disk_used_pct", "memory_used_kb", "memory_used_pct",
	"uptime_s", "store_entries", "memory_objects", "disk_objects",
}

func writeCacheStats(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, cacheStatsFile), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// cacheStatsBody is the data object of the endpoint, as JSON values.
func cacheStatsBody(t *testing.T, h *AnalyticsHandlers) map[string]any {
	t.Helper()
	var r struct {
		Data map[string]any `json:"data"`
	}
	getJSON(t, h.CacheStats, "/api/cache/statistics", &r)
	return r.Data
}

// The file was never written (squidclient is not in the image), and the
// endpoint answered zeros marked simulated, which the UI had to know were not
// a 0% hit rate. No file is now a state, with every value null.
func TestCacheStatsWithoutAFileIsNotCollectedAndHasNoValues(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	got := cacheStatsBody(t, NewAnalyticsHandlers(db, cfg))
	if got["state"] != "not_collected" {
		t.Fatalf("state = %v, want not_collected", got["state"])
	}
	for _, k := range append([]string{"collected_at", "age_s"}, valueKeys...) {
		if v, ok := got[k]; !ok || v != nil {
			t.Errorf("%s = %v (present %v), want null", k, v, ok)
		}
	}
	if _, ok := got["simulated"]; ok {
		t.Error("simulated is gone: the state says what there is")
	}
}

func TestCacheStatsReportsTheWatchdogsRecordAsItWasWritten(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	writeCacheStats(t, cfg.ConfigDir, watchdogCacheStats)

	got := readCacheStats(cfg.ConfigDir, time.Unix(watchdogCollectedAt+42, 0))
	if got.State != "current" || *got.CollectedAt != "2026-10-25 12:15:28" || *got.AgeS != 42 || *got.StaleAfterS != 180 {
		t.Fatalf("state %s at %v age %v stale after %v, want current at 2026-10-25 12:15:28, 42 s, 180 s",
			got.State, *got.CollectedAt, *got.AgeS, *got.StaleAfterS)
	}
	if *got.RequestHitRatio60minPct != 64.7 || *got.ByteHitRatio5minPct != 91.6 || *got.DiskUsedKB != 252 ||
		*got.DiskCapacityKB != 51200 || *got.MemoryUsedKB != 468 || *got.MemoryUsedPct != 0.2 ||
		*got.UptimeS != 210.475 || *got.StoreEntries != 64 || *got.DiskObjects != 11 {
		t.Errorf("values changed on the way: %+v", got.cacheStatsValues)
	}

	// And on the wire: every value is a field of data.
	body := cacheStatsBody(t, NewAnalyticsHandlers(db, cfg))
	for _, k := range valueKeys {
		if _, ok := body[k].(float64); !ok {
			t.Errorf("%s = %v, want a number", k, body[k])
		}
	}
}

// Squid prints no hit ratio in its first minute; the watchdog writes null and
// so does the endpoint: never a 0 that reads as an idle cache.
func TestCacheStatsKeepsAnAbsentValueNull(t *testing.T) {
	_, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	writeCacheStats(t, cfg.ConfigDir, `{"version": 1, "collected_at": 1792930528, "interval_s": 60, "request_hit_ratio_60min_pct": null, "disk_used_kb": 220, "uptime_s": 8.365}`)
	got := readCacheStats(cfg.ConfigDir, time.Unix(watchdogCollectedAt, 0))
	if got.State != "current" || got.RequestHitRatio60minPct != nil || got.DiskCapacityKB != nil || *got.DiskUsedKB != 220 {
		t.Fatalf("got %s %+v, want current with the ratio and capacity null", got.State, got.cacheStatsValues)
	}
	raw, _ := json.Marshal(got)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	if v, ok := m["request_hit_ratio_60min_pct"]; !ok || v != nil {
		t.Errorf("request_hit_ratio_60min_pct = %v (present %v), want null", v, ok)
	}
}

// Three missed collections and the values describe the past: they are still
// sent, as the last ones, under state stale.
func TestCacheStatsIsStaleAfterThreeMissedIntervals(t *testing.T) {
	_, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	writeCacheStats(t, cfg.ConfigDir, watchdogCacheStats)
	for _, c := range []struct {
		age  int64
		want string
	}{{0, "current"}, {180, "current"}, {181, "stale"}, {86400, "stale"}} {
		got := readCacheStats(cfg.ConfigDir, time.Unix(watchdogCollectedAt+c.age, 0))
		if got.State != c.want || *got.AgeS != c.age {
			t.Errorf("age %d s: state %s, age %d, want %s", c.age, got.State, *got.AgeS, c.want)
		}
		if got.RequestHitRatio60minPct == nil {
			t.Errorf("age %d s: the last values must still be reported", c.age)
		}
	}
	// A record a second in the future is current, not negative in age.
	if got := readCacheStats(cfg.ConfigDir, time.Unix(watchdogCollectedAt-1, 0)); got.State != "current" || *got.AgeS != 0 {
		t.Errorf("future record: %s, age %d", got.State, *got.AgeS)
	}
}

func TestCacheStatsStaleAfterFollowsTheIntervalInTheFile(t *testing.T) {
	_, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	for interval, want := range map[string]int64{"120": 360, "0": 180, "-5": 180, "86400": 180} {
		writeCacheStats(t, cfg.ConfigDir, `{"version": 1, "collected_at": 1792930528, "interval_s": `+interval+`}`)
		if got := readCacheStats(cfg.ConfigDir, time.Unix(watchdogCollectedAt, 0)); *got.StaleAfterS != want {
			t.Errorf("interval_s %s: stale after %d, want %d", interval, *got.StaleAfterS, want)
		}
	}
}

// A file this backend does not understand has no values: not zeros, and not
// the numbers of some other format.
func TestCacheStatsAFileItCannotReadIsUnreadable(t *testing.T) {
	_, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	for _, bad := range []string{
		"not json",
		"Squid Object Cache: Version 7.7\n\tHits as % of all requests:\t5min: 64.7%, 60min: 64.7%\n",
		`{"version": 2, "collected_at": 1792930528}`,
		`{"version": 1}`,
		`{"version": 1, "collected_at": 0}`,
		`{"version": 1, "collected_at": 1792930528, "disk_used_kb": "252 KB"}`,
	} {
		writeCacheStats(t, cfg.ConfigDir, bad)
		got := readCacheStats(cfg.ConfigDir, time.Unix(watchdogCollectedAt, 0))
		if got.State != "unreadable" || got.CollectedAt != nil || got.DiskUsedKB != nil || got.RequestHitRatio5minPct != nil {
			t.Errorf("%q: %s %+v, want unreadable with no values", bad, got.State, got.cacheStatsValues)
		}
	}
	_ = os.Remove(filepath.Join(cfg.ConfigDir, cacheStatsFile))
	if err := os.Mkdir(filepath.Join(cfg.ConfigDir, cacheStatsFile), 0o750); err != nil {
		t.Fatal(err)
	}
	if got := readCacheStats(cfg.ConfigDir, time.Now()); got.State != "unreadable" {
		t.Errorf("a directory in its place: %s, want unreadable", got.State)
	}
}
