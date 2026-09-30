package handlers

import (
	"reflect"
	"testing"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/config"
)

func TestNormaliseCountryCodes(t *testing.T) {
	got := normaliseCountryCodes([]string{" CN", "cn", "", "RU ", "ru", "  "})
	if want := []string{"cn", "ru"}; !reflect.DeepEqual(got, want) {
		t.Errorf("normaliseCountryCodes = %v, want %v", got, want)
	}
}

func TestParseGeoZoneKeepsOnlyNewPublicRanges(t *testing.T) {
	existing := map[string]struct{}{"203.0.113.0/24": {}}
	zone := "# comment\n203.0.113.0/24\n198.51.100.0/24\n\n10.0.0.0/8\nnot-a-range\n198.51.100.0/24\n192.0.2.7\n"
	got := parseGeoZone(zone, "cn", existing)
	want := [][2]string{{"198.51.100.0/24", "GeoIP: CN"}, {"192.0.2.7", "GeoIP: CN"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseGeoZone = %v, want %v", got, want)
	}
	if _, ok := existing["198.51.100.0/24"]; !ok {
		t.Error("the returned rows were not recorded in the dedupe set")
	}
}

func TestGeoFeedURLs(t *testing.T) {
	h := &BlacklistHandlers{cfg: &config.Config{}}
	if u := h.geoFeedURLs("cn"); len(u) != 2 || u[0] != "https://www.ipdeny.com/ipblocks/data/countries/cn.zone" {
		t.Errorf("default feeds = %v", u)
	}
	h.cfg.GeoIPURL = "http://mirror.lan/geo"
	if u := h.geoFeedURLs("cn"); len(u) != 1 || u[0] != "http://mirror.lan/geo?cc=cn" {
		t.Errorf("operator feed = %v", u)
	}
}
