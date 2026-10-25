package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/models"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/validate"
)

// listLabels are the names the Blacklists page gives the four lists, so a
// refusal says which list it is about in the words on screen.
var listLabels = map[string]string{
	"ip_blacklist":     "Blocked IPs",
	"domain_blacklist": "Blocked domains",
	"ip_whitelist":     "Allowed IPs",
	"domain_whitelist": "Allowed domains",
}

// The refusals the list endpoints give, worded as the page's add form words
// its own checks (ui/src/components/blacklists/AddEntries.tsx). The value is
// quoted with %q, so a control character in it is shown escaped.
func notADomainMessage(v string) string {
	return fmt.Sprintf("%q is not a domain name: labels of letters, digits and hyphens separated by dots", v)
}

func notAnIPMessage(v string) string {
	return fmt.Sprintf("%q is not an IP address or network", v)
}

func alreadyListedMessage(v, table string) string {
	return fmt.Sprintf("%q is already on %s", v, listLabels[table])
}

// notExactMessage refuses a wildcard or a leading dot on Allowed domains. The
// allowed list takes the same name off Blocked domains and covers no name
// under it (database.EnforcedDomain), so ".example.com" would read as "and
// its subdomains" and allow only example.com. The refusal used to say "a
// parent domain covers its subdomains", which is not what the export does.
func notExactMessage(v, name string) string {
	return fmt.Sprintf("%q is not an exact name: write %s. An allowed name takes that same name off Blocked domains, "+
		"however it is written there, and covers no name under it", v, name)
}

// allowedIPValue is the value Allowed IPs stores for raw, or why it refuses it.
func allowedIPValue(raw string) (string, string) {
	ip := strings.TrimSpace(raw)
	if !isValidCIDR(ip) {
		return "", notAnIPMessage(ip)
	}
	return ip, ""
}

// allowedDomainValue is the value Allowed domains stores for raw, or why it
// refuses it.
//
// A metacharacter used to be classified as type="url-regex", persisted, and
// listed in the UI, while the ONLY reader of this table filters on
// type='fqdn'. So `*.example.com` was accepted, shown as whitelisted, and
// silently did nothing (SECURE-DOM-07). It is refused, with the name to write.
func allowedDomainValue(raw string) (string, string) {
	domain := strings.TrimSpace(strings.ToLower(raw))
	if strings.HasPrefix(domain, "*.") || strings.HasPrefix(domain, ".") {
		if name := database.EnforcedDomain(domain); isValidHostname(name) {
			return "", notExactMessage(domain, name)
		}
		return "", notADomainMessage(domain)
	}
	if strings.ContainsAny(domain, "*?[(|\\") {
		return "", fmt.Sprintf("%q is not an exact name: wildcards and regular expressions are not supported on Allowed domains", domain)
	}
	if !isValidHostname(domain) {
		return "", notADomainMessage(domain)
	}
	return domain, ""
}

func entriesWord(n int) string {
	if n == 1 {
		return "entry"
	}
	return "entries"
}

// allowedRefusalsShown bounds the refusals an import response lists; the
// count covers all of them.
const allowedRefusalsShown = 20

// allowedRefusal is one pasted line an allowed list did not take, and why.
type allowedRefusal struct {
	Entry  string `json:"entry"`
	Reason string `json:"reason"`
}

// ImportAllowed adds a pasted list to Allowed IPs or Allowed domains as one
// source of kind paste, the way a paste on a blocked list is recorded
// (POST /api/blacklists/import). Each line is checked as the single add checks
// it; lines starting with # and blank lines are ignored. The page used to send
// a paste on an allowed list one POST per line to the single add endpoint,
// so every pasted entry was recorded as Manual and could not be removed as
// the paste it was, and a refused line was only counted, not explained.
func (h *BlacklistHandlers) ImportAllowed(table, col string, check func(string) (string, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req models.ImportAllowedRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		if err := validate.Struct(&req); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		var values []string
		var refused []allowedRefusal
		refusedCount, repeated := 0, 0
		seen := map[string]struct{}{}
		for _, line := range strings.Split(req.Content, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			v, reason := check(line)
			if reason != "" {
				refusedCount++
				if len(refused) < allowedRefusalsShown {
					refused = append(refused, allowedRefusal{Entry: line, Reason: reason})
				}
				continue
			}
			if _, dup := seen[v]; dup {
				repeated++
				continue
			}
			seen[v] = struct{}{}
			values = append(values, v)
		}
		added, err := h.insertAllowed(table, col, values)
		if err != nil {
			writeInternalError(w, "import_"+table, err)
			return
		}
		skipped := repeated + len(values) - added
		if added > 0 {
			requestExport()
		}
		auditChange(h.db, r, "import_"+auditListName(table), "", map[string]any{
			"added": added, "skipped": skipped + refusedCount, "from": "paste",
		})
		if refused == nil {
			refused = []allowedRefusal{}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"status":  "success",
			"message": fmt.Sprintf("Added %d %s to %s (%d already listed, %d refused)", added, entriesWord(added), listLabels[table], skipped, refusedCount),
			"data":    map[string]any{"added": added, "skipped": skipped, "refused": refusedCount, "refusals": refused},
		})
	}
}

// insertAllowed writes values under one new paste source in one transaction
// and returns how many were new; an entry already on the list is left as it
// is, with the source that added it first. A paste that adds nothing leaves
// no source behind.
func (h *BlacklistHandlers) insertAllowed(table, col string, values []string) (int, error) {
	if len(values) == 0 {
		return 0, nil
	}
	tx, err := h.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck // no-op once committed
	sourceID, err := database.NewSource(tx, table, database.SourcePaste, "")
	if err != nil {
		return 0, err
	}
	// table and col come from the route table in Register, never the request.
	stmt, err := tx.Prepare(fmt.Sprintf("INSERT OR IGNORE INTO %s (%s, description, source_id) VALUES(?, '', ?)", table, col)) // #nosec G201
	if err != nil {
		return 0, err
	}
	defer stmt.Close()
	added := 0
	for _, v := range values {
		res, err := stmt.Exec(v, sourceID)
		if err != nil {
			return 0, err
		}
		if n, err := res.RowsAffected(); err == nil {
			added += int(n)
		}
	}
	if added == 0 {
		// Nothing references the source: it goes with the rollback.
		return 0, nil
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return added, nil
}
