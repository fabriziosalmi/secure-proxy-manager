package handlers

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// domainACLStatusFile is written by the proxy's watchdog (refresh_domain_acl
// in proxy/blacklist_watchdog.py) every time it derives Squid's own copy of
// the domain blacklist, at boot and after every list sync.
const domainACLStatusFile = "domain_acl_status.json"

// DomainACLStatus is what the proxy decided about Squid's domain ACL: the
// blacklist has Names names (after removing duplicates and the "*." prefix),
// SPM_SQUID_DOMAIN_ACL_MAX is Limit, and Held says whether Squid holds them.
// When it does not, only the DNS sinkhole blocks those domains.
//
// The limit is the proxy's setting, not the backend's, so the backend reports
// the proxy's own record instead of comparing its list count with a copy of
// the limit that could differ.
type DomainACLStatus struct {
	Names     int   `json:"names"`
	Limit     int   `json:"limit"`
	Held      bool  `json:"held"`
	WrittenAt int64 `json:"written_at"`
}

// readDomainACLStatus returns the proxy's record, or nil when there is none
// (a proxy older than this file, or one that has not started) or it cannot be
// read: no record is not a record that says "held".
func readDomainACLStatus(configDir string) *DomainACLStatus {
	raw, err := os.ReadFile(filepath.Join(configDir, domainACLStatusFile)) // #nosec G304 -- fixed name in the config dir
	if err != nil {
		return nil
	}
	var s struct {
		Version   int   `json:"version"`
		Names     *int  `json:"names"`
		Limit     *int  `json:"limit"`
		Held      *bool `json:"held"`
		WrittenAt int64 `json:"written_at"`
	}
	if json.Unmarshal(raw, &s) != nil || s.Version != 1 || s.Names == nil || s.Limit == nil || s.Held == nil {
		return nil
	}
	return &DomainACLStatus{Names: *s.Names, Limit: *s.Limit, Held: *s.Held, WrittenAt: s.WrittenAt}
}
