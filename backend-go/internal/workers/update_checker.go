package workers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/config"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/metrics"
)

// UpdateInfo holds the latest release info from GitHub.
type UpdateInfo struct {
	Available bool   `json:"available"`
	Latest    string `json:"latest,omitempty"`
	Current   string `json:"current"`
	URL       string `json:"url,omitempty"`
	CheckedAt string `json:"checked_at,omitempty"`
}

var (
	updateMu   sync.RWMutex
	updateInfo = UpdateInfo{Current: config.AppVersion}
)

// GetUpdateInfo returns the cached update check result.
func GetUpdateInfo() UpdateInfo {
	updateMu.RLock()
	defer updateMu.RUnlock()
	return updateInfo
}

// updateFirstCheck is how long the checker lets the system boot first.
var updateFirstCheck = 30 * time.Second

// StartUpdateChecker checks GitHub releases every 6h. With enabled false
// (UPDATE_CHECK=false) it sends nothing: an egress appliance an operator
// wants silent makes no request of its own to api.github.com.
func StartUpdateChecker(ctx context.Context, repo string, enabled bool) {
	if !enabled {
		log.Info().Msg("update check off (UPDATE_CHECK=false): no request to api.github.com")
		return
	}
	if repo == "" {
		repo = "fabriziosalmi/secure-proxy-manager"
	}

	Track(func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(updateFirstCheck):
		}
		check(repo)

		ticker := time.NewTicker(6 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				log.Info().Msg("update checker stopping")
				return
			case <-ticker.C:
				check(repo)
			}
		}
	})

	log.Info().Str("repo", repo).Msg("update checker started (every 6h)")
}

// semverGreater returns true if a > b using numeric comparison per segment.
func semverGreater(a, b string) bool {
	aParts := strings.Split(a, ".")
	bParts := strings.Split(b, ".")
	for i := 0; i < len(aParts) || i < len(bParts); i++ {
		var av, bv int
		if i < len(aParts) {
			av, _ = strconv.Atoi(aParts[i])
		}
		if i < len(bParts) {
			bv, _ = strconv.Atoi(bParts[i])
		}
		if av > bv {
			return true
		}
		if av < bv {
			return false
		}
	}
	return false
}

func check(url string) {
	metrics.WorkerHeartbeat("update_checker")
	client := &http.Client{Timeout: 10 * time.Second}
	if !strings.Contains(url, "://") {
		url = "https://api.github.com/repos/" + url + "/releases/latest"
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "SecureProxyManager/"+config.AppVersion)

	resp, err := client.Do(req)
	if err != nil {
		log.Debug().Err(err).Msg("update check failed")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return
	}

	var release struct {
		TagName string `json:"tag_name"`
		HTMLURL string `json:"html_url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return
	}

	latest := strings.TrimPrefix(release.TagName, "v")
	current := strings.TrimSuffix(config.AppVersion, "-go")

	updateMu.Lock()
	prev := updateInfo
	updateInfo = UpdateInfo{
		Available: latest != current && semverGreater(latest, current),
		Latest:    release.TagName,
		Current:   config.AppVersion,
		URL:       release.HTMLURL,
		CheckedAt: time.Now().UTC().Format(time.RFC3339),
	}
	info := updateInfo
	updateMu.Unlock()

	if info.Available {
		log.Info().Str("latest", release.TagName).Str("current", config.AppVersion).Msg("update available")
		// Once per new version, not on every check.
		if !prev.Available || prev.Latest != info.Latest {
			raiseAlert("update_available", "info", fmt.Sprintf("Secure Proxy Manager %s is available; this one runs %s. %s", info.Latest, info.Current, info.URL))
		}
	} else {
		log.Debug().Str("latest", release.TagName).Msg("up to date")
	}
}
