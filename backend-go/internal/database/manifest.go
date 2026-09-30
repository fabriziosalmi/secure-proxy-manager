package database

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/atomicfile"
)

// ListsManifestName is the file, next to the exported lists, that says what the
// lists must contain. The proxy's watchdog verifies each list against it before
// it becomes a live Squid ACL.
const ListsManifestName = "lists.manifest.json"

// ListsManifestVersion is bumped when the manifest's shape changes. A reader
// that does not know the version refuses rather than guessing.
const ListsManifestVersion = 1

// manifestLists are the exported files Squid enforces. Keep in step with PAIRS
// in proxy/blacklist_watchdog.py.
var manifestLists = []string{
	"ip_blacklist.txt",
	"ip_whitelist.txt",
	"domain_blacklist.txt",
	"dst_allow_ip.txt",
	"dst_allow_domain.txt",
}

type manifestEntry struct {
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

type listsManifest struct {
	Version     int                      `json:"version"`
	GeneratedAt int64                    `json:"generated_at"`
	Files       map[string]manifestEntry `json:"files"`
}

// writeListsManifest records the checksum of each exported list as it now
// stands on disk. It is written LAST, after every list has been published, and
// atomically, so a reader that sees a list newer than the manifest knows the
// set is mid-update and waits, and one that sees them agree knows they are the
// bytes the backend meant to publish.
//
// Without it the seam between the backend and Squid was a set of bare files
// copied verbatim: a truncated or malformed list became the live blocklist and
// nothing on the receiving side could tell (SECURE-ARCH-01).
func writeListsManifest(configDir string) error {
	m := listsManifest{
		Version:     ListsManifestVersion,
		GeneratedAt: time.Now().Unix(),
		Files:       make(map[string]manifestEntry, len(manifestLists)),
	}
	for _, name := range manifestLists {
		sum, n, err := hashListFile(filepath.Join(configDir, name))
		if err != nil {
			return fmt.Errorf("manifest: hash %s: %w", name, err)
		}
		m.Files[name] = manifestEntry{SHA256: sum, Bytes: n}
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	// 0644: it holds checksums, not secrets, and the proxy container reads it.
	return atomicfile.Write(filepath.Join(configDir, ListsManifestName), append(data, '\n'), 0o644)
}

func hashListFile(path string) (string, int64, error) {
	// #nosec G304 — path is the configured ConfigDir plus a constant name.
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}
