package workers

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"net/http"
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
	"https://urlhaus.abuse.ch/downloads/text/",
}

// dnsSignaler is the subset of docker.DockerClient the refresh worker needs to
// tell dnsmasq to re-read its exported blocklist. Kept as a local interface so
// the worker stays testable and nil-safe (a nil signaler simply skips the
// reload, which is what the unit tests pass).
type dnsSignaler interface {
	KillContainer(name, signal string) error
}

// dnsContainer is the compose-default name of the DNS service, matching the
// docker client's control allowlist and the ReloadDNS handler.
const dnsContainer = "secure-proxy-manager-dns-1"

// StartBlacklistRefresh runs an auto-refresh loop based on DB settings. After
// each export it signals dnsmasq to reload (Squid's blacklists are picked up
// separately by the proxy-side watchdog; only the DNS sinkhole needs the nudge).
func StartBlacklistRefresh(ctx context.Context, db *sql.DB, configDir string, dns dnsSignaler) {
	go func() {
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
			refreshAll(db)
			if err := database.ExportBlacklistsToFiles(db, configDir); err != nil {
				log.Warn().Err(err).Msg("blacklist export after auto-refresh failed")
				continue
			}
			signalDNSReload(dns)
		}
	}()
	log.Info().Msg("blacklist auto-refresh worker started")
}

// signalDNSReload tells dnsmasq to re-read its addn-hosts blocklist via SIGHUP.
// No-op when dns is nil (tests). Failures are non-fatal: the export already
// landed on disk and dnsmasq will pick it up on its next reload regardless.
func signalDNSReload(dns dnsSignaler) {
	if dns == nil {
		return
	}
	if err := dns.KillContainer(dnsContainer, "HUP"); err != nil {
		log.Warn().Err(err).Msg("dnsmasq SIGHUP after auto-refresh failed (non-fatal)")
		return
	}
	log.Info().Msg("signaled dnsmasq to reload blocklist after auto-refresh")
}

func readRefreshSettings(db *sql.DB) (bool, int) {
	var enabledVal, hoursVal string
	db.QueryRow("SELECT setting_value FROM settings WHERE setting_name='auto_refresh_enabled'").Scan(&enabledVal) //nolint:errcheck
	db.QueryRow("SELECT setting_value FROM settings WHERE setting_name='auto_refresh_hours'").Scan(&hoursVal)     //nolint:errcheck
	hours, _ := strconv.Atoi(hoursVal)
	return enabledVal == "true", hours
}

func refreshAll(db *sql.DB) {
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

	refreshList(db, "ip_blacklist", "ip", ipURLs)
	refreshList(db, "domain_blacklist", "domain", domainURLs)
}

func refreshList(db *sql.DB, table, col string, urls []string) {
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

	// Use the same SSRF-safe client and validation as the import handler (shared
	// in internal/netguard) so the auto-refresh path can't be pointed at internal
	// services and can't reintroduce private/bogon ranges into the source ACL.
	client := netguard.SSRFSafeClient()
	var added int

	for _, u := range urls {
		if ssrf, err := netguard.IsSSRFTarget(u); err != nil || ssrf {
			log.Warn().Str("url", u).Msg("blacklist refresh: refusing non-routable/invalid URL")
			continue
		}
		resp, err := client.Get(u)
		if err != nil || resp.StatusCode != http.StatusOK {
			if resp != nil {
				resp.Body.Close()
			}
			log.Warn().Str("url", u).Msg("blacklist refresh fetch failed")
			continue
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 200*1024*1024))
		resp.Body.Close()
		added += insertBlacklistEntries(db, table, col, string(data), existing)
	}
	if added > 0 {
		log.Info().Str("table", table).Int("added", added).Msg("blacklist refresh complete")
	}
}

// insertBlacklistEntries parses a fetched list and inserts new entries in one
// transaction, returning the count added. For IP lists it applies the same
// validation as the import handler: valid CIDR/IP only, and never a
// private/bogon range (the ip_blacklist is a source ACL — a LAN range would
// lock out the proxy's own clients).
func insertBlacklistEntries(db *sql.DB, table, col, data string, existing map[string]struct{}) int {
	tx, err := db.Begin()
	if err != nil {
		log.Error().Err(err).Msg("blacklist refresh: tx begin failed")
		return 0
	}
	stmt, err := tx.Prepare(fmt.Sprintf("INSERT OR IGNORE INTO %s (%s, description) VALUES(?,?)", table, col))
	if err != nil {
		tx.Rollback() //nolint:errcheck
		log.Error().Err(err).Msg("blacklist refresh: prepare failed")
		return 0
	}
	added := 0
	for _, line := range strings.Split(data, "\n") {
		parts := strings.Fields(line)
		if len(parts) == 0 || strings.HasPrefix(parts[0], "#") {
			continue
		}
		entry := parts[len(parts)-1]
		if col == "ip" && (!netguard.IsValidCIDR(entry) || netguard.IsLANBogonCIDR(entry)) {
			continue
		}
		if _, ex := existing[entry]; !ex {
			stmt.Exec(entry, "Auto-refresh: "+time.Now().Format("2006-01-02")) //nolint:errcheck
			existing[entry] = struct{}{}
			added++
		}
	}
	stmt.Close()
	tx.Commit() //nolint:errcheck
	return added
}
