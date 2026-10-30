package database

import (
	"database/sql"
	"encoding/json"
	"errors"
)

// WAFEvent is what the WAF reported about one block: the rules and
// categories behind it, the host and path a policy exception is scoped to,
// which half of the WAF blocked (spm or crs) and, for a Core Rule Set block,
// the variable each scoring rule matched. The access log row of the request
// carries the same event ID.
type WAFEvent struct {
	EventID    string      `json:"event_id"`
	Timestamp  string      `json:"timestamp"`
	ClientIP   string      `json:"client_ip"`
	Host       string      `json:"host"`
	Path       string      `json:"path"`
	URL        string      `json:"url"`
	Source     string      `json:"source"`
	BlockedBy  string      `json:"blocked_by"`
	Score      int         `json:"score"`
	CRSScore   int         `json:"crs_score"`
	Rules      []string    `json:"rules"`
	Categories []string    `json:"categories"`
	CRSTargets []WAFTarget `json:"crs_targets"`
}

// WAFTarget is one variable a Core Rule Set rule matched, as the policy file
// writes it (ARGS:pwd, REQUEST_FILENAME).
type WAFTarget struct {
	Rule   string `json:"rule"`
	Target string `json:"target"`
}

// The WAF is the only sender, behind the service token; the caps keep one
// malformed alert from storing an unbounded row.
const (
	wafEventMaxText = 2048
	wafEventMaxList = 64
)

// StoreWAFEvent records a block. An event ID seen before is left as it is:
// the WAF retries an alert it could not deliver.
func StoreWAFEvent(db *sql.DB, e WAFEvent) error {
	if e.EventID == "" {
		return errors.New("a WAF event without an event ID")
	}
	rules, _ := json.Marshal(capList(e.Rules))
	cats, _ := json.Marshal(capList(e.Categories))
	tg := e.CRSTargets
	if len(tg) > wafEventMaxList {
		tg = tg[:wafEventMaxList]
	}
	for i := range tg {
		tg[i] = WAFTarget{Rule: capText(tg[i].Rule), Target: capText(tg[i].Target)}
	}
	if tg == nil {
		tg = []WAFTarget{}
	}
	targets, _ := json.Marshal(tg)
	_, err := db.Exec(`INSERT OR IGNORE INTO waf_events
		(event_id, client_ip, host, path, url, source, blocked_by, score, crs_score, rules, categories, crs_targets)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		capText(e.EventID), capText(e.ClientIP), capText(e.Host), capText(e.Path), capText(e.URL),
		capText(e.Source), capText(e.BlockedBy), e.Score, e.CRSScore, string(rules), string(cats), string(targets))
	return err
}

// GetWAFEvent reads one block by its event ID; sql.ErrNoRows when there is
// none (never reported, or pruned with the access log).
func GetWAFEvent(db *sql.DB, eventID string) (WAFEvent, error) {
	var e WAFEvent
	var rules, cats, targets string
	err := db.QueryRow(`SELECT event_id, timestamp, client_ip, host, path, url, source, blocked_by,
		score, crs_score, rules, categories, crs_targets FROM waf_events WHERE event_id = ?`, eventID).
		Scan(&e.EventID, &e.Timestamp, &e.ClientIP, &e.Host, &e.Path, &e.URL, &e.Source, &e.BlockedBy,
			&e.Score, &e.CRSScore, &rules, &cats, &targets)
	if err != nil {
		return e, err
	}
	e.Rules, e.Categories, e.CRSTargets = []string{}, []string{}, []WAFTarget{}
	_ = json.Unmarshal([]byte(rules), &e.Rules)
	_ = json.Unmarshal([]byte(cats), &e.Categories)
	_ = json.Unmarshal([]byte(targets), &e.CRSTargets)
	return e, nil
}

func capText(s string) string {
	if len(s) > wafEventMaxText {
		return s[:wafEventMaxText]
	}
	return s
}

func capList(l []string) []string {
	if len(l) > wafEventMaxList {
		l = l[:wafEventMaxList]
	}
	out := make([]string, len(l))
	for i, v := range l {
		out[i] = capText(v)
	}
	return out
}
