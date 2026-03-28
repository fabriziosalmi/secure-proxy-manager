package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"
)

type DNSDetectHandlers struct{ db *sql.DB }

func NewDNSDetectHandlers(db *sql.DB) *DNSDetectHandlers { return &DNSDetectHandlers{db: db} }

func (h *DNSDetectHandlers) Register(r chi.Router, authMW func(http.Handler) http.Handler) {
	r.With(authMW).Post("/api/dns/detect", h.Detect)
}

type DetectedDNS struct {
	IP      string `json:"ip"`
	Type    string `json:"type"`    // "pihole", "adguard", "unknown"
	Name    string `json:"name"`    // "Pi-hole @ 192.168.1.2"
	Version string `json:"version"` // if available
	API     string `json:"api"`     // tested API URL
}

func (h *DNSDetectHandlers) Detect(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Subnet string `json:"subnet"` // e.g. "192.168.1" or auto-detect
	}
	json.NewDecoder(r.Body).Decode(&req) //nolint:errcheck

	// Auto-detect subnet from gateway if not provided
	subnet := req.Subnet
	if subnet == "" {
		subnet = detectLocalSubnet()
	}
	if subnet == "" {
		writeError(w, http.StatusBadRequest, "could not detect local subnet — provide 'subnet' field (e.g. '192.168.1')")
		return
	}

	log.Info().Str("subnet", subnet).Msg("scanning for DNS providers")

	// Scan common IPs in parallel
	ipsToScan := []string{
		subnet + ".1",   // gateway (common for router DNS)
		subnet + ".2",
		subnet + ".3",
		subnet + ".4",
		subnet + ".5",
		subnet + ".10",
		subnet + ".20",
		subnet + ".50",
		subnet + ".53",  // sometimes DNS is on .53
		subnet + ".100",
		subnet + ".200",
		subnet + ".254",
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var found []DetectedDNS

	for _, ip := range ipsToScan {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			if result := checkDNSProvider(ip); result != nil {
				mu.Lock()
				found = append(found, *result)
				mu.Unlock()
			}
		}(ip)
	}
	wg.Wait()

	writeOK(w, map[string]any{
		"subnet":  subnet,
		"scanned": len(ipsToScan),
		"found":   found,
	})
}

func checkDNSProvider(ip string) *DetectedDNS {
	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{Timeout: 1 * time.Second}).DialContext,
		},
	}

	// Check Pi-hole API
	for _, port := range []string{"80", "8080", "443"} {
		url := fmt.Sprintf("http://%s:%s/admin/api.php?summary", ip, port)
		if result := tryPihole(client, ip, url); result != nil {
			return result
		}
	}

	// Check AdGuard Home API
	for _, port := range []string{"80", "3000", "8080"} {
		url := fmt.Sprintf("http://%s:%s/control/status", ip, port)
		if result := tryAdGuard(client, ip, url); result != nil {
			return result
		}
	}

	return nil
}

func tryPihole(client *http.Client, ip, url string) *DetectedDNS {
	resp, err := client.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil
	}
	var data map[string]any
	if json.NewDecoder(resp.Body).Decode(&data) != nil {
		return nil
	}
	if _, ok := data["domains_being_blocked"]; !ok {
		return nil
	}
	version := ""
	if v, ok := data["gravity_last_updated"]; ok {
		version = fmt.Sprintf("%v", v)
	}
	return &DetectedDNS{IP: ip, Type: "pihole", Name: fmt.Sprintf("Pi-hole @ %s", ip), Version: version, API: url}
}

func tryAdGuard(client *http.Client, ip, url string) *DetectedDNS {
	resp, err := client.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil
	}
	var data map[string]any
	if json.NewDecoder(resp.Body).Decode(&data) != nil {
		return nil
	}
	if _, ok := data["dns_addresses"]; !ok {
		return nil
	}
	version := ""
	if v, ok := data["version"]; ok {
		version = fmt.Sprintf("%v", v)
	}
	return &DetectedDNS{IP: ip, Type: "adguard", Name: fmt.Sprintf("AdGuard Home @ %s", ip), Version: version, API: url}
}

func detectLocalSubnet() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
			ip := ipnet.IP.String()
			parts := strings.Split(ip, ".")
			if len(parts) == 4 {
				return strings.Join(parts[:3], ".")
			}
		}
	}
	return ""
}
