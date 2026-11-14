package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func i64(v int64) *int64 { return &v }

func gather(t *testing.T, c prometheus.Collector) map[string]float64 {
	t.Helper()
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(c)
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]float64{}
	for _, mf := range mfs {
		for _, m := range mf.GetMetric() {
			out[mf.GetName()] = m.GetGauge().GetValue()
		}
	}
	return out
}

func TestCacheStoreGaugesAreBytesAndAbsentWhenNothingWasRead(t *testing.T) {
	got := gather(t, &cacheStoreCollector{read: func() (CacheStore, bool) {
		return CacheStore{AgeS: 30, DiskUsedKB: i64(2), DiskCapacityKB: i64(4), MemoryUsedKB: nil, Objects: i64(808)}, true
	}})
	want := map[string]float64{
		"spm_squid_cache_stats_age_seconds":   30,
		"spm_squid_cache_disk_used_bytes":     2048,
		"spm_squid_cache_disk_capacity_bytes": 4096,
		"spm_squid_cache_objects":             808,
	}
	if len(got) != len(want) {
		t.Errorf("series = %v, want %v (memory left out: Squid did not print it)", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
	if n := len(gather(t, &cacheStoreCollector{read: func() (CacheStore, bool) { return CacheStore{}, false }})); n != 0 {
		t.Errorf("%d series with nothing read, want 0", n)
	}
}

func counterValue(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	m := &dto.Metric{}
	if err := c.Write(m); err != nil {
		t.Fatal(err)
	}
	return m.GetCounter().GetValue()
}

func TestProxyCacheCountsRequestsAndBytes(t *testing.T) {
	InitProxyCache([]string{"test-outcome"})
	if v := counterValue(t, proxyCacheRequests.WithLabelValues("test-outcome")); v != 0 {
		t.Fatalf("initialised at %v", v)
	}
	ProxyCache("test-outcome", 1500)
	ProxyCache("test-outcome", 0)
	if v := counterValue(t, proxyCacheRequests.WithLabelValues("test-outcome")); v != 2 {
		t.Errorf("requests = %v, want 2", v)
	}
	if v := counterValue(t, proxyCacheBytes.WithLabelValues("test-outcome")); v != 1500 {
		t.Errorf("bytes = %v, want 1500", v)
	}
}
