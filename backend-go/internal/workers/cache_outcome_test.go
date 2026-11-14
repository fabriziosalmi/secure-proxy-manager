package workers

import "testing"

func TestCacheOutcomeClassifiesSquidResultCodes(t *testing.T) {
	cases := []struct {
		status  string
		blocked bool
		want    string
	}{
		{"TCP_HIT/200", false, CacheHit},
		{"TCP_MEM_HIT/200", false, CacheHit},
		{"TCP_IMS_HIT/304", false, CacheHit},
		{"TCP_INM_HIT/304", false, CacheHit},
		{"TCP_NEGATIVE_HIT/404", false, CacheHit},
		{"TCP_OFFLINE_HIT/200", false, CacheHit},
		{"TCP_CF_HIT/200", false, CacheHit},
		{"TCP_HIT_ABORTED/200", false, CacheHit},
		{"TCP_REFRESH_IGNORED/200", false, CacheHit},
		{"TCP_REFRESH_UNMODIFIED/200", false, CacheRevalidated},
		{"TCP_REFRESH_UNMODIFIED/304", false, CacheRevalidated},
		{"TCP_REFRESH_FAIL_OLD/200", false, CacheRevalidated},
		{"TCP_REFRESH_MODIFIED/200", false, CacheMiss},
		{"TCP_REFRESH_FAIL_ERR/502", false, CacheMiss},
		{"TCP_MISS/200", false, CacheMiss},
		{"TCP_MISS_ABORTED/200", false, CacheMiss},
		{"TCP_CLIENT_REFRESH_MISS/200", false, CacheMiss},
		{"TCP_SWAPFAIL_MISS/200", false, CacheMiss},
		{"TCP_TUNNEL/200", false, CacheTunnel},
		{"TCP_TUNNEL_ABORTED/200", false, CacheTunnel},
		{"TCP_TUNNEL/503", false, CacheTunnel},
		{"TCP_DENIED/403", false, CacheRefused},
		{"TCP_DENIED_REPLY/403", false, CacheRefused},
		// A blocked row is refused whatever Squid printed: a WAF block is a
		// TCP_MISS/403 in the access log.
		{"TCP_MISS/403", true, CacheRefused},
		{"TCP_TUNNEL/200", true, CacheRefused},
		{"NONE_NONE/000", false, CacheOther},
		{"NONE_NONE/400", false, CacheOther},
		{"TCP_REDIRECT/302", false, CacheOther},
		{"", false, CacheOther},
		{"tcp_mem_hit/200", false, CacheHit},
	}
	for _, c := range cases {
		if got := CacheOutcome(c.status, c.blocked); got != c.want {
			t.Errorf("CacheOutcome(%q, %v) = %q, want %q", c.status, c.blocked, got, c.want)
		}
	}
}

func TestEveryCacheOutcomeHasALabel(t *testing.T) {
	for _, o := range CacheOutcomes {
		if CacheOutcomeLabel(o) == o {
			t.Errorf("%q has no label", o)
		}
	}
}
