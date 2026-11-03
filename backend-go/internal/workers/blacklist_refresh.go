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
	// The feeds' URLs stay out of the alert: a custom one can carry a key.
	failed, total := 0, 0
	var urls []string
	for _, c := range counts {
		failed += c.Failed
		total += c.Failed + c.Fetched
		urls = append(urls, strings.Fields(c.failedURLs)...)
	}
	// Once per change: the same feeds still down on the next run send
	// nothing more; a run with none down resets it.
	sort.Strings(urls)
	key := strings.Join(urls, "\n")
	lastRefreshFailures.Lock()
	changed := key != lastRefreshFailures.key
	lastRefreshFailures.key = key
	lastRefreshFailures.Unlock()
	if failed > 0 && changed {
		raiseAlert("blocklist_refresh_failed", "warning", fmt.Sprintf(
			"The blocklist refresh could not download %d of %d feeds; the lists keep the entries they had. The backend log names the feeds.",
			failed, total))
	}
}

// lastRefreshFailures is the set of feeds the last run could not download.
var lastRefreshFailures struct {
	sync.Mutex
	key string
}

func refreshAll(db *sql.DB) map[string]refreshCount {
	var customIPURLs, customDomainURLs string
	db.QueryRow("SELECT setting_value FROM settings WHERE setting_name='ip_blacklist_urls'").Scan(&customIPURLs)         //nolint:errcheck
	db.QueryRow("SELECT setting_value FROM settings WHERE setting_name='domain_blacklist_urls'").Scan(&customDomainURLs) //nolint:errcheck

	ipURLs := feedURLs(db, "ip_blacklist", defaultIPLists, customIPURLs)
	domainURLs := feedURLs(db, "domain_blacklist", defaultDomainLists, customDomainURLs)

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

// feedURLs is every feed a list is refreshed from, each once: the built-in
// feeds, the URLs of the setting (one per line), and every URL the list was
// imported from (a Popular list, an address typed in the import form). The
// last were never downloaded again before.
func feedURLs(db *sql.DB, table string, builtIn []string, setting string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(u string) {
		if u = strings.TrimSpace(u); u != "" && !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
	for _, u := range builtIn {
		add(u)
	}
	for _, u := range strings.Split(setting, "\n") {
		add(u)
	}
	rows, err := db.Query("SELECT source FROM list_sources WHERE list = ? AND kind = 'url' ORDER BY id", table)
	if err != nil {
		log.Warn().Err(err).Str("table", table).Msg("blacklist refresh: the imported URLs could not be read; only the built-in feeds are refreshed")
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var u string
		if rows.Scan(&u) == nil {
			add(u)
		}
	}
	return out
}
