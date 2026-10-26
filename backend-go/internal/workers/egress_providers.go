package workers

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/metrics"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/netguard"
)

const (
	defaultEgressCommitsURL = "https://api.github.com/repos/lord-alfred/ipranges/commits/main"
	defaultEgressRawBaseURL = "https://raw.githubusercontent.com/lord-alfred/ipranges"

	// MaxEgressProviderEntries is the maximum number of CIDR entries (IPv4 + IPv6)
	// accepted for a single egress provider.
	MaxEgressProviderEntries = 50000

	// maxEgressFeedBytes bounds the response body read from any provider feed.
	maxEgressFeedBytes = 20 << 20 // 20 MiB

	// DefaultEgressRefreshHours is the default refresh interval in hours.
	DefaultEgressRefreshHours = 24
	// MinEgressRefreshHours is the minimum refresh interval in hours.
	MinEgressRefreshHours = 6
)

var (
	// EgressCommitsURL and EgressRawBaseURL are variables so tests can point
	// catalog fetches at a local httptest.Server without touching the network.
	EgressCommitsURL = defaultEgressCommitsURL
	EgressRawBaseURL = defaultEgressRawBaseURL

	// EgressHTTPClient returns the HTTP client used to fetch egress provider feeds.
	// It always returns an SSRF-safe client; Go unit tests that use a loopback
	// httptest.Server override EgressHTTPClient directly.
	EgressHTTPClient = func() *http.Client {
		c := netguard.SSRFSafeClient()
		c.Timeout = 30 * time.Second
		return c
	}

	// EgressCheckURL validates that a custom URL provider does not target an SSRF address.
	EgressCheckURL = netguard.IsSSRFTarget

	egressWorkerMu  sync.Mutex
	egressWorkerCtx context.Context
)

func init() {
	// SPM_EGRESS_COMMITS_URL and SPM_EGRESS_RAW_BASE_URL are used by integration
	// tests (where the feed server runs on a public test IP) and do not alter
	// the SSRF protection in EgressHTTPClient.
	if v := strings.TrimSpace(os.Getenv("SPM_EGRESS_COMMITS_URL")); v != "" {
		EgressCommitsURL = v
	}
	if v := strings.TrimSpace(os.Getenv("SPM_EGRESS_RAW_BASE_URL")); v != "" {
		EgressRawBaseURL = strings.TrimRight(v, "/")
	}
}

// CatalogProvider describes one built-in egress provider from lord-alfred/ipranges.
type CatalogProvider struct {
	Name          string `json:"name"`
	Dir           string `json:"dir"`
	Source        string `json:"source"`
	SharedNetwork bool   `json:"shared_network"`
}

var catalogProviders = []CatalogProvider{
	{Name: "amazon", Dir: "amazon", Source: "ip-ranges.amazonaws.com", SharedNetwork: true},
	{Name: "cloudflare", Dir: "cloudflare", Source: "cloudflare.com/ips", SharedNetwork: true},
	{Name: "digitalocean", Dir: "digitalocean", Source: "geo csv", SharedNetwork: true},
	{Name: "facebook", Dir: "facebook", Source: "ASN", SharedNetwork: false},
	{Name: "github", Dir: "github", Source: "api.github.com/meta", SharedNetwork: true},
	{Name: "google", Dir: "google", Source: "goog.json and cloud.json", SharedNetwork: true},
	{Name: "linode", Dir: "linode", Source: "geoip.linode.com", SharedNetwork: true},
	{Name: "microsoft", Dir: "microsoft", Source: "Azure service tags and M365", SharedNetwork: true},
	{Name: "oracle", Dir: "oracle", Source: "public_ip_ranges.json", SharedNetwork: true},
	{Name: "telegram", Dir: "telegram", Source: "core.telegram.org/resources/cidr.txt", SharedNetwork: false},
	{Name: "twitter", Dir: "twitter", Source: "ASN", SharedNetwork: false},
	{Name: "vultr", Dir: "vultr", Source: "geofeed", SharedNetwork: true},
	{Name: "all", Dir: "all", Source: "all upstream directories", SharedNetwork: true},
}

var catalogByName = func() map[string]CatalogProvider {
	m := make(map[string]CatalogProvider, len(catalogProviders))
	for _, p := range catalogProviders {
		m[p.Name] = p
	}
	return m
}()

// CatalogProviders returns a copy of the fixed catalog.
func CatalogProviders() []CatalogProvider {
	out := make([]CatalogProvider, len(catalogProviders))
	copy(out, catalogProviders)
	return out
}

// LookupCatalogProvider looks up a catalog provider by name.
func LookupCatalogProvider(name string) (CatalogProvider, bool) {
	p, ok := catalogByName[name]
	return p, ok
}

type nonPublicRange struct {
	prefix netip.Prefix
	class  string
}

var nonPublicRanges = func() []nonPublicRange {
	specs := []struct {
		cidr  string
		class string
	}{
		// Private (RFC 1918)
		{"10.0.0.0/8", "private"},
		{"172.16.0.0/12", "private"},
		{"192.168.0.0/16", "private"},
		// Loopback
		{"127.0.0.0/8", "loopback"},
		{"::1/128", "loopback"},
		// Link-local
		{"169.254.0.0/16", "link-local"},
		{"fe80::/10", "link-local"},
		// Multicast
		{"224.0.0.0/4", "multicast"},
		{"ff00::/8", "multicast"},
		// Reserved / unspecified / benchmarking / protocol assignments / 6to4
		{"0.0.0.0/8", "reserved"},
		{"192.0.0.0/24", "reserved"},
		{"192.88.99.0/24", "reserved"},
		{"198.18.0.0/15", "reserved"},
		{"240.0.0.0/4", "reserved"},
		{"::/128", "reserved"},
		{"::ffff:0:0/96", "reserved"},
		{"64:ff9b::/96", "reserved"},
		{"64:ff9b:1::/48", "reserved"},
		{"100::/64", "reserved"},
		{"2001::/23", "reserved"},
		{"2002::/16", "reserved"},
		// Documentation
		{"192.0.2.0/24", "documentation"},
		{"198.51.100.0/24", "documentation"},
		{"203.0.113.0/24", "documentation"},
		{"2001:db8::/32", "documentation"},
		{"3fff::/20", "documentation"},
		// CGNAT (RFC 6598)
		{"100.64.0.0/10", "cgnat"},
		// ULA (RFC 4193)
		{"fc00::/7", "ula"},
	}
	out := make([]nonPublicRange, 0, len(specs))
	for _, s := range specs {
		out = append(out, nonPublicRange{
			prefix: netip.MustParsePrefix(s.cidr),
			class:  s.class,
		})
	}
	return out
}()

var globalUnicastV6 = netip.MustParsePrefix("2000::/3")

// IsNonPublicPrefix reports whether p falls within or overlaps any non-public
// IPv4 or IPv6 range (private, loopback, link-local, multicast, reserved,
// documentation, CGNAT, ULA, or unassigned IPv6 outside 2000::/3), returning
// the matched class name.
func IsNonPublicPrefix(p netip.Prefix) (bool, string) {
	if !p.IsValid() {
		return true, "invalid"
	}
	p = p.Masked()
	if p.Addr().Is4In6() {
		return true, "reserved"
	}
	for _, r := range nonPublicRanges {
		if p.Overlaps(r.prefix) {
			return true, r.class
		}
	}
	if p.Addr().Is6() && (p.Bits() < 3 || !globalUnicastV6.Contains(p.Addr())) {
		return true, "unassigned"
	}
	return false, ""
}

// ValidatedProviderList holds the validated, normalized, deduplicated prefixes
// and their merged coverage counts.
type ValidatedProviderList struct {
	V4            []string
	V6            []string
	IPv4Covered   uint64
	IPv664Covered uint64
}

// ValidateAndMeasureProviderList validates raw IPv4 and IPv6 lines according to
// all egress provider protection rules and computes covered address counts.
func ValidateAndMeasureProviderList(v4Lines, v6Lines []string) (*ValidatedProviderList, error) {
	v4Prefixes, v4Strings, err := parseFamilyLines(v4Lines, 4)
	if err != nil {
		return nil, err
	}
	v6Prefixes, v6Strings, err := parseFamilyLines(v6Lines, 6)
	if err != nil {
		return nil, err
	}
	total := len(v4Strings) + len(v6Strings)
	if total > MaxEgressProviderEntries {
		return nil, fmt.Errorf("entry count %d exceeds maximum of %d", total, MaxEgressProviderEntries)
	}
	return &ValidatedProviderList{
		V4:            v4Strings,
		V6:            v6Strings,
		IPv4Covered:   CoveredIPv4Addresses(v4Prefixes),
		IPv664Covered: CoveredIPv664Blocks(v6Prefixes),
	}, nil
}

func parseFamilyLines(lines []string, wantFamily int) ([]netip.Prefix, []string, error) {
	seen := make(map[string]struct{}, len(lines))
	var prefixes []netip.Prefix
	var strs []string

	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p, err := netip.ParsePrefix(line)
		if err != nil || !p.IsValid() {
			return nil, nil, fmt.Errorf("invalid CIDR %q", line)
		}
		if p.Addr().Is4In6() {
			return nil, nil, fmt.Errorf("IPv4-mapped IPv6 prefix %q is not allowed", line)
		}
		p = p.Masked()
		if wantFamily == 4 {
			if !p.Addr().Is4() {
				return nil, nil, fmt.Errorf("expected IPv4 CIDR, got %q", line)
			}
			if p.Bits() < 8 {
				return nil, nil, fmt.Errorf("IPv4 prefix %q is wider than /8", line)
			}
		} else {
			if !p.Addr().Is6() {
				return nil, nil, fmt.Errorf("expected IPv6 CIDR, got %q", line)
			}
			if p.Bits() < 16 {
				return nil, nil, fmt.Errorf("IPv6 prefix %q is wider than /16", line)
			}
		}
		if nonPub, class := IsNonPublicPrefix(p); nonPub {
			return nil, nil, fmt.Errorf("non-public (%s) prefix %q is not allowed", class, line)
		}
		s := p.String()
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		prefixes = append(prefixes, p)
		strs = append(strs, s)
	}
	sort.Strings(strs)
	return prefixes, strs, nil
}

type u64Interval struct {
	start, end uint64
}

func sumMergedIntervals(iv []u64Interval) uint64 {
	if len(iv) == 0 {
		return 0
	}
	sort.Slice(iv, func(i, j int) bool {
		if iv[i].start != iv[j].start {
			return iv[i].start < iv[j].start
		}
		return iv[i].end < iv[j].end
	})
	var total uint64
	cur := iv[0]
	for _, next := range iv[1:] {
		if next.start <= cur.end || (cur.end < math.MaxUint64 && next.start == cur.end+1) {
			if next.end > cur.end {
				cur.end = next.end
			}
		} else {
			total += cur.end - cur.start + 1
			cur = next
		}
	}
	total += cur.end - cur.start + 1
	return total
}

// CoveredIPv4Addresses returns the total number of distinct IPv4 addresses
// covered by prefixes after merging overlapping ranges.
func CoveredIPv4Addresses(prefixes []netip.Prefix) uint64 {
	if len(prefixes) == 0 {
		return 0
	}
	iv := make([]u64Interval, 0, len(prefixes))
	for _, p := range prefixes {
		p = p.Masked()
		if !p.Addr().Is4() {
			continue
		}
		b := p.Addr().As4()
		bits := p.Bits()
		if bits < 0 || bits > 32 {
			continue
		}
		start := uint64(binary.BigEndian.Uint32(b[:]))
		size := uint64(1) << (32 - bits)
		iv = append(iv, u64Interval{start: start, end: start + size - 1})
	}
	return sumMergedIntervals(iv)
}

// CoveredIPv664Blocks returns the total number of distinct /64 blocks covered
// by prefixes after merging overlapping ranges.
func CoveredIPv664Blocks(prefixes []netip.Prefix) uint64 {
	if len(prefixes) == 0 {
		return 0
	}
	iv := make([]u64Interval, 0, len(prefixes))
	for _, p := range prefixes {
		p = p.Masked()
		if !p.Addr().Is6() || p.Addr().Is4In6() {
			continue
		}
		b := p.Addr().As16()
		hi := binary.BigEndian.Uint64(b[:8])
		bits := p.Bits()
		if bits < 0 || bits > 128 {
			continue
		}
		if bits >= 64 {
			iv = append(iv, u64Interval{start: hi, end: hi})
		} else {
			size := uint64(1) << (64 - bits)
			iv = append(iv, u64Interval{start: hi, end: hi + size - 1})
		}
	}
	return sumMergedIntervals(iv)
}

// HeldUpdate is serialized in egress_providers.held_json when an update grows
// covered addresses by more than 25% compared to the current good list.
type HeldUpdate struct {
	Commit        string   `json:"commit"`
	V4Count       int      `json:"v4_count"`
	V6Count       int      `json:"v6_count"`
	IPv4Covered   uint64   `json:"ipv4_covered"`
	IPv664Covered uint64   `json:"ipv6_64_covered"`
	GrowthPct     float64  `json:"growth_pct"`
	Reason        string   `json:"reason"`
	HeldAt        string   `json:"held_at"`
	EntriesV4     []string `json:"entries_v4,omitempty"`
	EntriesV6     []string `json:"entries_v6,omitempty"`
}

// HeldSummary is the public view of a held update returned by GET /api/egress-providers.
type HeldSummary struct {
	Commit        string  `json:"commit"`
	V4Count       int     `json:"v4_count"`
	V6Count       int     `json:"v6_count"`
	IPv4Covered   uint64  `json:"ipv4_covered"`
	IPv664Covered uint64  `json:"ipv6_64_covered"`
	GrowthPct     float64 `json:"growth_pct"`
	Reason        string  `json:"reason"`
	HeldAt        string  `json:"held_at"`
}

// EgressProviderState is the status of one catalog or URL egress provider.
type EgressProviderState struct {
	ID            int64        `json:"id"`
	Kind          string       `json:"kind"`
	Name          string       `json:"name"`
	URL           string       `json:"url"`
	Source        string       `json:"source,omitempty"`
	Enabled       bool         `json:"enabled"`
	SharedNetwork bool         `json:"shared_network"`
	V4Count       int          `json:"v4_count"`
	V6Count       int          `json:"v6_count"`
	IPv4Covered   uint64       `json:"ipv4_covered"`
	IPv664Covered uint64       `json:"ipv6_64_covered"`
	LastRefresh   string       `json:"last_refresh"`
	LastCommit    string       `json:"last_commit"`
	LastError     string       `json:"last_error"`
	Held          *HeldSummary `json:"held"`
	Created       string       `json:"created,omitempty"`
}

func fetchBytes(url string) ([]byte, int, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", "SecureProxyManager-EgressProvider")
	resp, err := EgressHTTPClient().Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxEgressFeedBytes+1))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if len(data) > maxEgressFeedBytes {
		return nil, resp.StatusCode, fmt.Errorf("response from %s exceeds %d bytes", url, maxEgressFeedBytes)
	}
	return data, http.StatusOK, nil
}

func fetchCatalogRaw(dir string) (commit string, v4Lines, v6Lines []string, err error) {
	commitBody, _, err := fetchBytes(EgressCommitsURL)
	if err != nil {
		return "", nil, nil, fmt.Errorf("fetch commit sha: %w", err)
	}
	var commitResp struct {
		SHA string `json:"sha"`
	}
	if err := json.Unmarshal(commitBody, &commitResp); err != nil || strings.TrimSpace(commitResp.SHA) == "" {
		return "", nil, nil, errors.New("invalid commit response from upstream API")
	}
	commit = strings.TrimSpace(commitResp.SHA)

	base := strings.TrimRight(EgressRawBaseURL, "/") + "/" + commit + "/" + dir
	v4Body, _, err := fetchBytes(base + "/ipv4_merged.txt")
	if err != nil {
		return commit, nil, nil, fmt.Errorf("fetch ipv4_merged.txt: %w", err)
	}
	v4Lines = strings.Split(string(v4Body), "\n")

	v6Body, code, err := fetchBytes(base + "/ipv6_merged.txt")
	if err != nil {
		if code == http.StatusNotFound {
			v6Lines = nil
		} else {
			return commit, nil, nil, fmt.Errorf("fetch ipv6_merged.txt: %w", err)
		}
	} else {
		v6Lines = strings.Split(string(v6Body), "\n")
	}
	return commit, v4Lines, v6Lines, nil
}

func fetchURLRaw(rawURL string) (commit string, v4Lines, v6Lines []string, err error) {
	if ssrf, err := EgressCheckURL(rawURL); err != nil || ssrf {
		if err != nil {
			return "", nil, nil, fmt.Errorf("disallowed URL: %w", err)
		}
		return "", nil, nil, errors.New("disallowed URL: private or reserved target")
	}
	body, _, err := fetchBytes(rawURL)
	if err != nil {
		return "", nil, nil, err
	}
	sum := sha256.Sum256(body)
	commit = hex.EncodeToString(sum[:])

	for _, raw := range strings.Split(string(body), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p, parseErr := netip.ParsePrefix(line)
		if parseErr != nil {
			// Pass to v4Lines so ValidateAndMeasureProviderList fails with a uniform error.
			v4Lines = append(v4Lines, line)
			continue
		}
		if p.Addr().Is6() && !p.Addr().Is4In6() {
			v6Lines = append(v6Lines, line)
		} else {
			v4Lines = append(v4Lines, line)
		}
	}
	return commit, v4Lines, v6Lines, nil
}

func ensureProviderRow(db *sql.DB, kind, name, url string) (int64, error) {
	if _, err := db.Exec(
		`INSERT OR IGNORE INTO egress_providers(kind, name, url) VALUES(?, ?, ?)`,
		kind, name, url,
	); err != nil {
		return 0, err
	}
	var id int64
	if err := db.QueryRow(`SELECT id FROM egress_providers WHERE kind = ? AND name = ?`, kind, name).Scan(&id); err != nil {
		return 0, err
	}
	return id, nil
}

func loadProviderCoverage(db *sql.DB, providerID int64) (v4Count, v6Count int, v4Covered, v664Covered uint64, err error) {
	rows, err := db.Query(`SELECT cidr, family FROM egress_provider_entries WHERE provider_id = ?`, providerID)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	defer rows.Close()
	var v4p, v6p []netip.Prefix
	for rows.Next() {
		var cidr string
		var fam int
		if err := rows.Scan(&cidr, &fam); err != nil {
			return 0, 0, 0, 0, err
		}
		p, err := netip.ParsePrefix(cidr)
		if err != nil {
			continue
		}
		if fam == 4 {
			v4Count++
			v4p = append(v4p, p)
		} else {
			v6Count++
			v6p = append(v6p, p)
		}
	}
	if err := rows.Err(); err != nil {
		return 0, 0, 0, 0, err
	}
	return v4Count, v6Count, CoveredIPv4Addresses(v4p), CoveredIPv664Blocks(v6p), nil
}

func writeAuditJSON(db *sql.DB, user, action, target string, details map[string]any) {
	b, _ := json.Marshal(details)
	database.Audit(db, user, action, target, string(b))
}

// RefreshEgressProvider fetches, validates, and either applies, holds (>25% growth),
// or rejects an update for the given provider.
func RefreshEgressProvider(db *sql.DB, configDir, kind, name, user string) (*EgressProviderState, bool, error) {
	var dir, rawURL string
	if kind == "catalog" {
		cat, ok := LookupCatalogProvider(name)
		if !ok {
			return nil, false, fmt.Errorf("unknown catalog provider %q", name)
		}
		dir = cat.Dir
	} else {
		if err := db.QueryRow(`SELECT url FROM egress_providers WHERE kind = 'url' AND name = ?`, name).Scan(&rawURL); err != nil {
			return nil, false, fmt.Errorf("unknown URL provider %q", name)
		}
	}

	pid, err := ensureProviderRow(db, kind, name, rawURL)
	if err != nil {
		return nil, false, err
	}

	oldV4, oldV6, oldV4Cov, oldV6Cov, err := loadProviderCoverage(db, pid)
	if err != nil {
		return nil, false, err
	}

	var commit string
	var v4Lines, v6Lines []string
	if kind == "catalog" {
		commit, v4Lines, v6Lines, err = fetchCatalogRaw(dir)
	} else {
		commit, v4Lines, v6Lines, err = fetchURLRaw(rawURL)
	}
	if err != nil {
		recordRefreshFailure(db, pid, kind, name, user, err.Error())
		return nil, false, err
	}

	validated, err := ValidateAndMeasureProviderList(v4Lines, v6Lines)
	if err != nil {
		recordRefreshFailure(db, pid, kind, name, user, err.Error())
		return nil, false, err
	}

	// Growth check: only when the provider already has a good list stored.
	if oldV4+oldV6 > 0 {
		var v4Growth, v6Growth float64
		var holdReason string
		if oldV4Cov == 0 && validated.IPv4Covered > 0 {
			holdReason = fmt.Sprintf("IPv4 appeared: 0 to %d addresses", validated.IPv4Covered)
			v4Growth = 100.0
		} else if oldV4Cov > 0 && validated.IPv4Covered > oldV4Cov {
			v4Growth = float64(validated.IPv4Covered-oldV4Cov) * 100.0 / float64(oldV4Cov)
		}
		if oldV6Cov == 0 && validated.IPv664Covered > 0 {
			holdReason = fmt.Sprintf("IPv6 appeared: 0 to %d /64 blocks", validated.IPv664Covered)
			v6Growth = 100.0
		} else if oldV6Cov > 0 && validated.IPv664Covered > oldV6Cov {
			v6Growth = float64(validated.IPv664Covered-oldV6Cov) * 100.0 / float64(oldV6Cov)
		}
		growthPct := v4Growth
		if v6Growth > growthPct {
			growthPct = v6Growth
		}
		if holdReason != "" || growthPct > 25.0 {
			roundedGrowth := math.Round(growthPct*100) / 100
			if holdReason == "" {
				holdReason = fmt.Sprintf("covered addresses grew by %.2f%% (threshold 25%%)", roundedGrowth)
			}
			held := HeldUpdate{
				Commit:        commit,
				V4Count:       len(validated.V4),
				V6Count:       len(validated.V6),
				IPv4Covered:   validated.IPv4Covered,
				IPv664Covered: validated.IPv664Covered,
				GrowthPct:     roundedGrowth,
				Reason:        holdReason,
				HeldAt:        time.Now().UTC().Format(time.RFC3339),
				EntriesV4:     validated.V4,
				EntriesV6:     validated.V6,
			}
			hb, _ := json.Marshal(held)
			if _, err := db.Exec(`UPDATE egress_providers SET held_json = ?, last_error = '' WHERE id = ?`, string(hb), pid); err != nil {
				return nil, false, err
			}
			metrics.EgressProviderRefresh("held")
			writeAuditJSON(db, user, "egress_provider_held", name, map[string]any{
				"commit":                 commit,
				"growth_pct":             roundedGrowth,
				"reason":                 holdReason,
				"v4_before":              oldV4,
				"v4_after":               len(validated.V4),
				"v6_before":              oldV6,
				"v6_after":               len(validated.V6),
				"ipv4_covered_before":    oldV4Cov,
				"ipv4_covered_after":     validated.IPv4Covered,
				"ipv6_64_covered_before": oldV6Cov,
				"ipv6_64_covered_after":  validated.IPv664Covered,
			})
			st, err := GetEgressProviderState(db, kind, name)
			return st, true, err
		}
	}

	if err := applyValidatedProviderList(db, pid, commit, validated); err != nil {
		recordRefreshFailure(db, pid, kind, name, user, err.Error())
		return nil, false, err
	}
	metrics.EgressProviderRefresh("success")
	metrics.SetEgressProviderEntries(name, len(validated.V4), len(validated.V6))
	writeAuditJSON(db, user, "egress_provider_refreshed", name, map[string]any{
		"commit":              commit,
		"v4_before":           oldV4,
		"v4_after":            len(validated.V4),
		"v6_before":           oldV6,
		"v6_after":            len(validated.V6),
		"ipv4_covered_before": oldV4Cov,
		"ipv4_covered_after":  validated.IPv4Covered,
	})
	if configDir != "" {
		if err := database.ExportBlacklistsToFiles(db, configDir); err == nil {
			metrics.ExportSuccess()
		} else {
			metrics.ExportFailure()
		}
	}
	RequestExport()
	st, err := GetEgressProviderState(db, kind, name)
	return st, false, err
}

func recordRefreshFailure(db *sql.DB, pid int64, kind, name, user, reason string) {
	_, _ = db.Exec(`UPDATE egress_providers SET last_error = ? WHERE id = ?`, reason, pid)
	metrics.EgressProviderRefresh("failure")
	writeAuditJSON(db, user, "egress_provider_refresh_failed", name, map[string]any{
		"kind":   kind,
		"reason": reason,
	})
}

func applyValidatedProviderList(db *sql.DB, pid int64, commit string, v *ValidatedProviderList) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	if _, err := tx.Exec(`DELETE FROM egress_provider_entries WHERE provider_id = ?`, pid); err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO egress_provider_entries(provider_id, cidr, family) VALUES(?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, c := range v.V4 {
		if _, err := stmt.Exec(pid, c, 4); err != nil {
			return err
		}
	}
	for _, c := range v.V6 {
		if _, err := stmt.Exec(pid, c, 6); err != nil {
			return err
		}
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := tx.Exec(
		`UPDATE egress_providers SET last_refresh = ?, last_commit = ?, last_error = '', held_json = '' WHERE id = ?`,
		now, commit, pid,
	); err != nil {
		return err
	}
	return tx.Commit()
}

// ApplyHeldEgressProvider applies the held update stored in held_json for a provider.
func ApplyHeldEgressProvider(db *sql.DB, configDir, kind, name, user string) (*EgressProviderState, error) {
	var pid int64
	var heldRaw string
	err := db.QueryRow(`SELECT id, COALESCE(held_json,'') FROM egress_providers WHERE kind = ? AND name = ?`, kind, name).Scan(&pid, &heldRaw)
	if err != nil {
		return nil, fmt.Errorf("provider %q not found", name)
	}
	if strings.TrimSpace(heldRaw) == "" {
		return nil, errors.New("no held update to apply")
	}
	var held HeldUpdate
	if err := json.Unmarshal([]byte(heldRaw), &held); err != nil {
		return nil, fmt.Errorf("invalid held update: %w", err)
	}
	oldV4, oldV6, oldV4Cov, _, err := loadProviderCoverage(db, pid)
	if err != nil {
		return nil, err
	}
	validated, err := ValidateAndMeasureProviderList(held.EntriesV4, held.EntriesV6)
	if err != nil {
		return nil, err
	}
	if err := applyValidatedProviderList(db, pid, held.Commit, validated); err != nil {
		return nil, err
	}
	metrics.SetEgressProviderEntries(name, len(validated.V4), len(validated.V6))
	writeAuditJSON(db, user, "egress_provider_held_applied", name, map[string]any{
		"commit":              held.Commit,
		"growth_pct":          held.GrowthPct,
		"v4_before":           oldV4,
		"v4_after":            len(validated.V4),
		"v6_before":           oldV6,
		"v6_after":            len(validated.V6),
		"ipv4_covered_before": oldV4Cov,
		"ipv4_covered_after":  validated.IPv4Covered,
	})
	if configDir != "" {
		if err := database.ExportBlacklistsToFiles(db, configDir); err == nil {
			metrics.ExportSuccess()
		} else {
			metrics.ExportFailure()
		}
	}
	RequestExport()
	return GetEgressProviderState(db, kind, name)
}

// GetEgressProviderState returns the current state of one provider.
func GetEgressProviderState(db *sql.DB, kind, name string) (*EgressProviderState, error) {
	all, err := ListEgressProviders(db)
	if err != nil {
		return nil, err
	}
	for _, p := range all {
		if p.Kind == kind && p.Name == name {
			return &p, nil
		}
	}
	return nil, fmt.Errorf("provider %q not found", name)
}

// ListEgressProviders returns all 13 catalog providers in catalog order followed
// by any custom URL providers.
func ListEgressProviders(db *sql.DB) ([]EgressProviderState, error) {
	type dbRow struct {
		id          int64
		kind, name  string
		url         string
		enabled     bool
		lastRefresh string
		lastCommit  string
		lastError   string
		heldJSON    string
		created     string
	}
	rows, err := db.Query(`
		SELECT id, kind, name, url, enabled, last_refresh, last_commit, last_error, held_json, created
		FROM egress_providers
		ORDER BY id`)
	if err != nil {
		return nil, err
	}
	var stored []dbRow
	for rows.Next() {
		var r dbRow
		var en int
		if err := rows.Scan(&r.id, &r.kind, &r.name, &r.url, &en, &r.lastRefresh, &r.lastCommit, &r.lastError, &r.heldJSON, &r.created); err != nil {
			rows.Close()
			return nil, err
		}
		r.enabled = en == 1
		stored = append(stored, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	byCatalog := map[string]dbRow{}
	var urlRows []dbRow
	for _, r := range stored {
		if r.kind == "catalog" {
			byCatalog[r.name] = r
		} else {
			urlRows = append(urlRows, r)
		}
	}

	buildState := func(r dbRow, cat *CatalogProvider) (EgressProviderState, error) {
		st := EgressProviderState{
			ID:          r.id,
			Kind:        r.kind,
			Name:        r.name,
			URL:         r.url,
			Enabled:     r.enabled,
			LastRefresh: r.lastRefresh,
			LastCommit:  r.lastCommit,
			LastError:   r.lastError,
			Created:     r.created,
		}
		if cat != nil {
			st.Kind = "catalog"
			st.Name = cat.Name
			st.Source = cat.Source
			st.SharedNetwork = cat.SharedNetwork
		}
		if r.id > 0 {
			v4c, v6c, v4cov, v6cov, err := loadProviderCoverage(db, r.id)
			if err != nil {
				return st, err
			}
			st.V4Count = v4c
			st.V6Count = v6c
			st.IPv4Covered = v4cov
			st.IPv664Covered = v6cov
		}
		if strings.TrimSpace(r.heldJSON) != "" {
			var h HeldUpdate
			if err := json.Unmarshal([]byte(r.heldJSON), &h); err == nil {
				st.Held = &HeldSummary{
					Commit:        h.Commit,
					V4Count:       h.V4Count,
					V6Count:       h.V6Count,
					IPv4Covered:   h.IPv4Covered,
					IPv664Covered: h.IPv664Covered,
					GrowthPct:     h.GrowthPct,
					Reason:        h.Reason,
					HeldAt:        h.HeldAt,
				}
			}
		}
		return st, nil
	}

	out := make([]EgressProviderState, 0, len(catalogProviders)+len(urlRows))
	for i := range catalogProviders {
		cat := &catalogProviders[i]
		r := byCatalog[cat.Name]
		st, err := buildState(r, cat)
		if err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	for _, r := range urlRows {
		st, err := buildState(r, nil)
		if err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, nil
}

// StartEgressProviderRefresh refreshes enabled egress providers every
// egress_provider_refresh_hours (default 24, minimum 6), even when
// egress_default_deny is disabled so the lists stay ready.
func StartEgressProviderRefresh(ctx context.Context, db *sql.DB, configDir string) {
	egressWorkerMu.Lock()
	egressWorkerCtx = ctx
	egressWorkerMu.Unlock()
	Track(func() {
		log.Info().Msg("egress provider refresh worker started")
		for {
			metrics.WorkerHeartbeat("egress_provider_refresh")
			hours := readEgressRefreshHours(db)
			select {
			case <-ctx.Done():
				log.Info().Msg("egress provider refresh worker stopped")
				return
			case <-time.After(time.Duration(hours) * time.Hour):
			}
			if ctx.Err() != nil {
				return
			}
			RefreshEnabledEgressProviders(db, configDir, "system")
			metrics.WorkerHeartbeat("egress_provider_refresh")
		}
	})
}

func readEgressRefreshHours(db *sql.DB) int {
	var raw string
	if err := db.QueryRow("SELECT setting_value FROM settings WHERE setting_name = 'egress_provider_refresh_hours'").Scan(&raw); err != nil {
		return DefaultEgressRefreshHours
	}
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || n < MinEgressRefreshHours {
		return DefaultEgressRefreshHours
	}
	return n
}

// RefreshEnabledEgressProvidersAsync runs RefreshEnabledEgressProviders in a
// tracked background worker goroutine so callers like config restore return
// immediately without waiting on remote downloads.
func RefreshEnabledEgressProvidersAsync(db *sql.DB, configDir, user string) {
	Track(func() {
		RefreshEnabledEgressProviders(db, configDir, user)
	})
}

// RefreshEnabledEgressProviders refreshes every currently enabled provider.
func RefreshEnabledEgressProviders(db *sql.DB, configDir, user string) {
	rows, err := db.Query(`SELECT kind, name FROM egress_providers WHERE enabled = 1 ORDER BY id`)
	if err != nil {
		log.Error().Err(err).Msg("egress provider refresh: query enabled providers")
		return
	}
	type pair struct{ kind, name string }
	var enabled []pair
	for rows.Next() {
		var p pair
		if err := rows.Scan(&p.kind, &p.name); err == nil {
			enabled = append(enabled, p)
		}
	}
	rows.Close()

	egressWorkerMu.Lock()
	wctx := egressWorkerCtx
	egressWorkerMu.Unlock()
	for _, p := range enabled {
		if wctx != nil && wctx.Err() != nil {
			return
		}
		if _, _, err := RefreshEgressProvider(db, configDir, p.kind, p.name, user); err != nil {
			log.Warn().Str("provider", p.name).Err(err).Msg("egress provider refresh failed")
		}
	}
}
