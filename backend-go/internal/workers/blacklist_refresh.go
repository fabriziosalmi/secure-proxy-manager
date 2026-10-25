package workers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/metrics"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/netguard"
)

// Default lists to refresh.
var defaultIPLists = []string{
	"https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
	"https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt",
}

var defaultDomainLists = []string{
	"https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
	// URLhaus via the malware-filter mirror: abuse.ch answers 410 Gone on every
	// unauthenticated download since 2026-10 and now requires an Auth-Key.
	"https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt",
}

// StartBlacklistRefresh runs an auto-refresh loop based on DB settings. After
// each export it signals dnsmasq to reload (Squid's blacklists are picked up
// separately by the proxy-side watchdog; only the DNS sinkhole needs the nudge).
func StartBlacklistRefresh(ctx context.Context, db *sql.DB, configDir string) {
	Track(func() {
		for {
			// Re-read settings on each cycle so changes take effect.
			enabled, interval := readRefreshSettings(db)
			if !enabled || interval <= 0 {
				select {
				case <-ctx.Done():
					log.Info().Msg("blacklist refresh worker stopping")
					return
				case <-time.After(30 * time.Minute):
				}
				continue
			}
			select {
			case <-ctx.Done():
				log.Info().Msg("blacklist refresh worker stopping")
				return
			case <-time.After(time.Duration(interval) * time.Hour):
			}
			log.Info().Msg("auto-refresh blacklists starting")
			metrics.WorkerHeartbeat("blacklist_refresh")
			runRefresh(db)
			if err := database.ExportBlacklistsToFiles(db, configDir); err != nil {
				log.Warn().Err(err).Msg("blacklist export after auto-refresh failed")
				continue
			}
			reloadFile := filepath.Join(configDir, ".reload-dns")
			// #nosec G306 — reload trigger, must be readable by the proxy/dns container
			if err := os.WriteFile(reloadFile, []byte(strconv.FormatInt(time.Now().Unix(), 10)), 0644); err != nil {
				log.Warn().Err(err).Msg("dns reload file trigger after auto-refresh failed")
			} else {
				log.Info().Msg("signaled dnsmasq to reload blocklist after auto-refresh")
			}
		}
	})
	log.Info().Msg("blacklist auto-refresh worker started")
}

func readRefreshSettings(db *sql.DB) (bool, int) {
	var enabledVal, hoursVal string
	db.QueryRow("SELECT setting_value FROM settings WHERE setting_name='auto_refresh_enabled'").Scan(&enabledVal) //nolint:errcheck
	db.QueryRow("SELECT setting_value FROM settings WHERE setting_name='auto_refresh_hours'").Scan(&hoursVal)     //nolint:errcheck
	hours, _ := strconv.Atoi(hoursVal)
	return enabledVal == "true", hours
}

// refreshCount is what one run of the worker did to one list: the feeds it
// read, the ones it could not, the entries that were new, and (domains only)
// the new ones left out because the list is at its limit.
type refreshCount struct {
	Added    int `json:"added"`
	Fetched  int `json:"fetched"`
	Failed   int `json:"failed"`
	NotAdded int `json:"not_added,omitempty"`
}

// runRefresh is one run of the worker: every feed refreshed, then one audit
// row, as the user "system", with what the run did to each list. The worker
// used to add tens of thousands of entries a day without a trace in the log.
func runRefresh(db *sql.DB) {
	counts := refreshAll(db)
	details, err := json.Marshal(counts)
	if err != nil {
		details = nil
	}
	database.Audit(db, "system", "refresh_blacklists", "", string(details))
}

func refreshAll(db *sql.DB) map[string]refreshCount {
	var customIPURLs, customDomainURLs string
	db.QueryRow("SELECT setting_value FROM settings WHERE setting_name='ip_blacklist_urls'").Scan(&customIPURLs)         //nolint:errcheck
	db.QueryRow("SELECT setting_value FROM settings WHERE setting_name='domain_blacklist_urls'").Scan(&customDomainURLs) //nolint:errcheck

	ipURLs := append([]string{}, defaultIPLists...)
	for _, u := range strings.Split(customIPURLs, "\n") {
		if u = strings.TrimSpace(u); u != "" {
			ipURLs = append(ipURLs, u)
		}
	}
	domainURLs := append([]string{}, defaultDomainLists...)
	for _, u := range strings.Split(customDomainURLs, "\n") {
		if u = strings.TrimSpace(u); u != "" {
			domainURLs = append(domainURLs, u)
		}
	}

	return map[string]refreshCount{
		"ip_blacklist":     refreshList(db, "ip_blacklist", "ip", ipURLs),
		"domain_blacklist": refreshList(db, "domain_blacklist", "domain", domainURLs),
	}
}

var errRefreshRefused = errors.New("non-routable or invalid URL")

// fetchRefreshFeed reads one feed. It is a variable so a test can serve the
// feeds without a public address; nothing else replaces it.
//
// It uses the same SSRF-safe client and validation as the import handler
// (shared in internal/netguard), so the auto-refresh path can't be pointed at
// internal services.
var fetchRefreshFeed = func(u string) (string, error) {
	if ssrf, err := netguard.IsSSRFTarget(u); err != nil || ssrf {
		return "", errRefreshRefused
	}
	resp, err := netguard.SSRFSafeClient().Get(u)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 200*1024*1024))
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func refreshList(db *sql.DB, table, col string, urls []string) refreshCount {
	existing := map[string]struct{}{}
	rows, _ := db.Query(fmt.Sprintf("SELECT %s FROM %s", col, table))
	if rows != nil {
		for rows.Next() {
			var v string
			rows.Scan(&v) //nolint:errcheck
			existing[v] = struct{}{}
		}
		rows.Close()
	}

	// The entries are validated as the import handler validates them, so the
	// refresh cannot reintroduce private/bogon ranges into the source ACL.
	var c refreshCount
	for _, u := range urls {
		data, err := fetchRefreshFeed(u)
		if err != nil {
			c.Failed++
			if errors.Is(err, errRefreshRefused) {
				log.Warn().Str("url", u).Msg("blacklist refresh: refusing non-routable/invalid URL")
			} else {
				log.Warn().Err(err).Str("url", u).Msg("blacklist refresh fetch failed")
			}
			continue
		}
		c.Fetched++
		added, capped := insertBlacklistEntries(db, table, col, u, data, existing)
		c.Added += added
		c.NotAdded += capped
	}
	if c.Added > 0 {
		log.Info().Str("table", table).Int("added", c.Added).Msg("blacklist refresh complete")
	}
	return c
}

// insertBlacklistEntries parses a fetched list and inserts new entries in one
// transaction, returning the count added (rows the database actually took,
// committed) and, for domains, the new entries left out at the list's limit.
// For IP lists it applies the same
// validation as the import handler: valid CIDR/IP only, and never a
// private/bogon range (the ip_blacklist is a source ACL — a LAN range would
// lock out the proxy's own clients).
//
// The entries are recorded under the URL's source, the same one an import of
// that URL uses, so a refreshed list is still one source that can be removed
// as a whole.
func insertBlacklistEntries(db *sql.DB, table, col, sourceURL, data string, existing map[string]struct{}) (int, int) {
	tx, err := db.Begin()
	if err != nil {
		log.Error().Err(err).Msg("blacklist refresh: tx begin failed")
		return 0, 0
	}
	sourceID, err := database.KeyedSource(tx, table, database.SourceURL, sourceURL, "")
	if err != nil {
		tx.Rollback() //nolint:errcheck
		log.Error().Err(err).Msg("blacklist refresh: cannot record the source")
		return 0, 0
	}
	stmt, err := tx.Prepare(fmt.Sprintf("INSERT OR IGNORE INTO %s (%s, description, source_id) VALUES(?,'',?)", table, col))
	if err != nil {
		tx.Rollback() //nolint:errcheck
		log.Error().Err(err).Msg("blacklist refresh: prepare failed")
		return 0, 0
	}
	added := 0
	limit := database.DomainBlacklistLimit()
	capped := 0
	for _, line := range strings.Split(data, "\n") {
		parts := strings.Fields(line)
		if len(parts) == 0 || strings.HasPrefix(parts[0], "#") {
			continue
		}
		entry := parts[len(parts)-1]
		if col == "ip" && (!netguard.IsValidCIDR(entry) || netguard.IsLANBogonCIDR(entry)) {
			continue
		}
		if col == "domain" && !netguard.IsValidDomainEntry(entry) {
			continue
		}
		if _, ex := existing[entry]; !ex {
			// The domain list is bounded by what dnsmasq can hold in memory
			// (database.DomainBlacklistLimit); past it, stop adding and say so.
			if col == "domain" && len(existing) >= limit {
				capped++
				continue
			}
			existing[entry] = struct{}{}
			if res, err := stmt.Exec(entry, sourceID); err == nil {
				if n, _ := res.RowsAffected(); n > 0 {
					added++
				}
			}
		}
	}
	stmt.Close()
	if err := tx.Commit(); err != nil {
		log.Error().Err(err).Msg("blacklist refresh: commit failed")
		return 0, 0
	}
	if capped > 0 {
		log.Warn().Int("not_added", capped).Int("limit", limit).
			Msg("blacklist refresh: the domain blacklist is at SPM_DNS_BLOCKLIST_MAX_DOMAINS; entries past it were not added")
	}
	return added, capped
}
