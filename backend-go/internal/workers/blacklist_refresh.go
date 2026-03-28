package workers

import (
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
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

// StartBlacklistRefresh runs an auto-refresh loop based on DB settings.
func StartBlacklistRefresh(db *sql.DB, configDir string) {
	go func() {
		for {
			// Re-read settings on each cycle so changes take effect.
			enabled, interval := readRefreshSettings(db)
			if !enabled || interval <= 0 {
				time.Sleep(30 * time.Minute)
				continue
			}
			time.Sleep(time.Duration(interval) * time.Hour)
			log.Info().Msg("auto-refresh blacklists starting")
			refreshAll(db)
			database.ExportBlacklistsToFiles(db, configDir) //nolint:errcheck
		}
	}()
	log.Info().Msg("blacklist auto-refresh worker started")
}

func readRefreshSettings(db *sql.DB) (bool, int) {
	var enabledVal, hoursVal string
	db.QueryRow("SELECT setting_value FROM settings WHERE setting_name='auto_refresh_enabled'").Scan(&enabledVal) //nolint:errcheck
	db.QueryRow("SELECT setting_value FROM settings WHERE setting_name='auto_refresh_hours'").Scan(&hoursVal)    //nolint:errcheck
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

	client := &http.Client{Timeout: 120 * time.Second}
	var added int

	for _, u := range urls {
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

		tx, err := db.Begin()
		if err != nil {
			log.Error().Err(err).Msg("blacklist refresh: tx begin failed")
			continue
		}
		stmt, err := tx.Prepare(fmt.Sprintf("INSERT OR IGNORE INTO %s (%s, description) VALUES(?,?)", table, col))
		if err != nil {
			tx.Rollback() //nolint:errcheck
			log.Error().Err(err).Msg("blacklist refresh: prepare failed")
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			parts := strings.Fields(line)
			if len(parts) == 0 || strings.HasPrefix(parts[0], "#") {
				continue
			}
			entry := parts[len(parts)-1]
			if _, ex := existing[entry]; !ex {
				stmt.Exec(entry, "Auto-refresh: "+time.Now().Format("2006-01-02")) //nolint:errcheck
				existing[entry] = struct{}{}
				added++
			}
		}
		stmt.Close()
		tx.Commit() //nolint:errcheck
	}
	if added > 0 {
		log.Info().Str("table", table).Int("added", added).Msg("blacklist refresh complete")
	}
}
