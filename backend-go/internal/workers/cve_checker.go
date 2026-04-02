package workers

import (
	"os/exec"
	"regexp"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
)

// SquidCVE represents a known vulnerability.
type SquidCVE struct {
	ID       string `json:"id"`
	Severity string `json:"severity"` // critical, high, medium
	Summary  string `json:"summary"`
}

// CVEInfo holds the Squid version and known CVEs.
type CVEInfo struct {
	Version string     `json:"version"`
	CVEs    []SquidCVE `json:"cves"`
}

var (
	cveMu   sync.RWMutex
	cveInfo = CVEInfo{}
)

// GetCVEInfo returns cached CVE check result.
func GetCVEInfo() CVEInfo {
	cveMu.RLock()
	defer cveMu.RUnlock()
	return cveInfo
}

// Known CVEs per Squid version range (manually curated — updated periodically).
// Source: https://www.cvedetails.com/product/29/Squid-Squid.html
var knownCVEs = map[string][]SquidCVE{
	"5.": {
		{ID: "CVE-2024-45802", Severity: "high", Summary: "DoS via ESI processing (Squid <6.10)"},
		{ID: "CVE-2024-25111", Severity: "high", Summary: "HTTP chunked decoding DoS"},
		{ID: "CVE-2024-25617", Severity: "medium", Summary: "HTTP header parsing DoS"},
		{ID: "CVE-2023-50269", Severity: "high", Summary: "Request smuggling via HTTP/1.1"},
		{ID: "CVE-2023-46847", Severity: "high", Summary: "Buffer overflow in HTTP digest auth"},
		{ID: "CVE-2023-46846", Severity: "high", Summary: "Request smuggling in chunked encoding"},
	},
	"4.": {
		{ID: "CVE-2023-46847", Severity: "critical", Summary: "Buffer overflow in HTTP digest auth"},
		{ID: "CVE-2023-46846", Severity: "critical", Summary: "Request smuggling in chunked encoding"},
		{ID: "CVE-2022-41318", Severity: "high", Summary: "Buffer over-read in SSPI/SMB auth"},
		{ID: "CVE-2021-28116", Severity: "medium", Summary: "Info disclosure via WCCPv2"},
	},
	"3.": {
		{ID: "CVE-2020-15049", Severity: "critical", Summary: "Request smuggling via Content-Length"},
		{ID: "CVE-2019-12528", Severity: "high", Summary: "Info disclosure via FTP"},
	},
}

// CheckSquidCVEs detects the Squid version and matches known CVEs.
func CheckSquidCVEs() {
	// Try to get Squid version via docker exec or direct binary
	version := detectSquidVersion()
	if version == "" {
		log.Debug().Msg("could not detect Squid version for CVE check")
		return
	}
	runCheck(version)
}

func runCheck(version string) {
	var matched []SquidCVE
	for prefix, cves := range knownCVEs {
		if strings.HasPrefix(version, prefix) {
			matched = append(matched, cves...)
		}
	}

	cveMu.Lock()
	cveInfo = CVEInfo{
		Version: version,
		CVEs:    matched,
	}
	cveMu.Unlock()

	if len(matched) > 0 {
		log.Warn().Str("squid_version", version).Int("cves", len(matched)).Msg("known CVEs for this Squid version")
	} else {
		log.Info().Str("squid_version", version).Msg("no known CVEs for this Squid version")
	}
}

func detectSquidVersion() string {
	// Method 1: docker exec
	out, err := exec.Command("docker", "exec", "secure-proxy-manager-proxy", "squid", "-v").CombinedOutput()
	if err == nil {
		return parseSquidVersion(string(out))
	}

	// Method 2: direct binary (if running on same host)
	out, err = exec.Command("squid", "-v").CombinedOutput()
	if err == nil {
		return parseSquidVersion(string(out))
	}

	return ""
}

var versionRe = regexp.MustCompile(`Squid Cache: Version ([0-9.]+)`)

func parseSquidVersion(output string) string {
	m := versionRe.FindStringSubmatch(output)
	if len(m) > 1 {
		return m[1]
	}
	// Fallback to old parsing if regex fails
	if strings.Contains(output, "Version ") {
		parts := strings.Split(output, "Version ")
		if len(parts) > 1 {
			v := strings.Split(parts[1], " ")[0]
			v = strings.Split(v, "\n")[0]
			return strings.TrimSpace(v)
		}
	}
	return ""
}
