package workers

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/config"
)

// UpdateInfo holds the latest release info from GitHub.
type UpdateInfo struct {
	Available  bool   `json:"available"`
	Latest     string `json:"latest,omitempty"`
	Current    string `json:"current"`
	URL        string `json:"url,omitempty"`
	CheckedAt  string `json:"checked_at,omitempty"`
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

// StartUpdateChecker checks GitHub releases every 6h.
func StartUpdateChecker(ctx context.Context, repo string) {
	if repo == "" {
		repo = "fabriziosalmi/secure-proxy-manager"
	}

	go func() {
		// First check after 30s (let the system boot)
		select {
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Second):
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
	}()

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
	updateInfo = UpdateInfo{
		Available: latest != current && semverGreater(latest, current),
		Latest:    release.TagName,
		Current:   config.AppVersion,
		URL:       release.HTMLURL,
		CheckedAt: time.Now().UTC().Format(time.RFC3339),
	}
	updateMu.Unlock()

	if updateInfo.Available {
		log.Info().Str("latest", release.TagName).Str("current", config.AppVersion).Msg("update available")
	} else {
		log.Debug().Str("latest", release.TagName).Msg("up to date")
	}
}
