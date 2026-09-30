package handlers

import "testing"

// parseSquidInfo had no test. This is the shape of the cache manager's info
// report it reads, and what each line becomes.
func TestParseSquidInfo(t *testing.T) {
	raw := "Squid Object Cache: Version 7.2\n" +
		"\tRequest Hit Ratios:\t5min: 42.3%, 60min: 38.1%\n" +
		"\tByte Hit Ratios:\t5min: 10.5%, 60min: 9.0%\n" +
		"\tStorage Swap size:\t1234 KB\n" +
		"\tMaximum Swap Size:\t1024000 KB\n" +
		"\tStoreEntries                : 900\n" +
		"\tcache.client_http.requests = 200\n" +
		"\tcache.client_http.hits = 80\n" +
		"\tsomething unrelated = 1\n"
	got := parseSquidInfo(raw)

	if f := got["hit_rate"].(float64); f < 0.4229 || f > 0.4231 {
		t.Errorf("hit_rate = %v, want 0.423", f)
	}
	if f := got["byte_hit_rate"].(float64); f < 0.1049 || f > 0.1051 {
		t.Errorf("byte_hit_rate = %v, want 0.105", f)
	}
	for key, want := range map[string]any{
		"cache_size": "1234 KB", "max_cache_size": "1024000 KB",
		"objects_cached": 900, "requests": 200, "hits": 80, "misses": 120, "simulated": false,
	} {
		if got[key] != want {
			t.Errorf("%s = %v (%T), want %v", key, got[key], got[key], want)
		}
	}
	if _, ok := got["hit_ratio"]; ok {
		t.Error("hit_ratio must not be emitted: hit_rate is the single definition")
	}
}

func TestParseSquidInfoKeepsDefaultsForUnparsableLines(t *testing.T) {
	got := parseSquidInfo("Request Hit Ratios: nothing here\nStoreEntries : many\nclient_http.hits = x\n")
	if got["hit_rate"] != 0.0 || got["objects_cached"] != 0 || got["hits"] != 0 || got["misses"] != 0 {
		t.Errorf("unparsable lines changed the defaults: %v", got)
	}
	if got["cache_size"] != "N/A" {
		t.Errorf("cache_size default lost: %v", got["cache_size"])
	}
}
