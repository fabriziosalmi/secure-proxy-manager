package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
)

// The parts of a configuration backup (backup_version 3) beyond settings and
// list values: where each list entry came from, the client groups, and the
// WAF policy.
//
// Version 2 exported every list entry as a bare value, and restore put them
// all under one new "Restore" source of scope global. A list that blocked
// only a group's clients came back as a list that blocked every client, the
// groups themselves were not exported, and neither was the WAF policy. A
// restore of version 2 still works as it did; its response says what the
// file did not carry.

// backupSource is a row of list_sources. ID is the id in the database the
// backup was taken from; entries and groups refer to it, and restore maps it
// to the id the source gets where it is restored.
type backupSource struct {
	ID     int64  `json:"id"`
	List   string `json:"list"`
	Kind   string `json:"kind"`
	Source string `json:"source"`
	Label  string `json:"label"`
	Scope  string `json:"scope"`
}

// backupEntry is one list entry. Source is the source that added it, Also
// the other sources that list it (database/entry_sources.go), both ids of
// the backup's sources; a version 2 file has neither.
type backupEntry struct {
	Value       string  `json:"value"`
	Description string  `json:"description"`
	Source      *int64  `json:"source,omitempty"`
	Also        []int64 `json:"also,omitempty"`
}

// backupGroup is a client group, its lists given as the backup's source ids.
type backupGroup struct {
	Name          string                  `json:"name"`
	Description   string                  `json:"description"`
	Members       []string                `json:"members"`
	Lists         []int64                 `json:"lists"`
	Schedule      *database.GroupSchedule `json:"schedule"`
	AllowlistOnly bool                    `json:"allowlist_only"`
}

// skippedItem is a source, group or policy restore did not apply, and why.
type skippedItem struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// sourceListTables are the lists whose entries record a source, each with its
// value column and its table of other sources, written out so no table name is
// built from input.
var sourceListTables = []struct{ list, col, others string }{
	{"ip_blacklist", "ip", "ip_blacklist_sources"},
	{"ip_whitelist", "ip", "ip_whitelist_sources"},
	{"domain_blacklist", "domain", "domain_blacklist_sources"},
	{"domain_whitelist", "domain", "domain_whitelist_sources"},
}

// exportSources reads every source of the four lists that record one.
func exportSources(db *sql.DB) ([]backupSource, error) {
	rows, err := db.Query(`SELECT id, list, kind, source, label, scope FROM list_sources ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []backupSource{}
	for rows.Next() {
		var s backupSource
		if err := rows.Scan(&s.ID, &s.List, &s.Kind, &s.Source, &s.Label, &s.Scope); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// exportSourcedEntries reads one list with each entry's source and its other
// sources.
func exportSourcedEntries(db *sql.DB, list, col, others string) ([]backupEntry, error) {
	also := map[int64][]int64{}
	// #nosec G202 -- table names come from sourceListTables, constants
	arows, err := db.Query("SELECT entry_id, source_id FROM " + others + " ORDER BY entry_id, source_id")
	if err != nil {
		return nil, err
	}
	for arows.Next() {
		var e, s int64
		if err := arows.Scan(&e, &s); err != nil {
			arows.Close()
			return nil, err
		}
		also[e] = append(also[e], s)
	}
	arows.Close()
	if err := arows.Err(); err != nil {
		return nil, err
	}
	// #nosec G202 -- table and column names come from sourceListTables, constants
	rows, err := db.Query("SELECT id, " + col + ", COALESCE(description,''), source_id FROM " + list + " ORDER BY " + col)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []backupEntry{}
	for rows.Next() {
		var id int64
		var e backupEntry
		var src sql.NullInt64
		if err := rows.Scan(&id, &e.Value, &e.Description, &src); err != nil {
			return nil, err
		}
		if src.Valid {
			v := src.Int64
			e.Source = &v
		}
		e.Also = also[id]
		out = append(out, e)
	}
	return out, rows.Err()
}

// exportGroups reads the client groups.
func exportGroups(db *sql.DB) ([]backupGroup, error) {
	groups, err := database.ListClientGroups(db)
	if err != nil {
		return nil, err
	}
	out := make([]backupGroup, 0, len(groups))
	for _, g := range groups {
		out = append(out, backupGroup{
			Name: g.Name, Description: g.Description, Members: g.Members, Lists: g.Lists,
			Schedule: g.Schedule, AllowlistOnly: g.AllowlistOnly,
		})
	}
	return out, nil
}

// sourceRestore maps the backup's source ids to the ids they have here, and
// remembers the sources this restore created, so the ones nothing ends up
// using are dropped before commit.
type sourceRestore struct {
	ids     map[int64]int64
	created []int64
	skipped []skippedItem
}

// restoreSources records the backup's sources inside tx. A keyed source (a
// URL, a country, a preset, the manual entries) that exists already is used
// as it is; an event source (a paste, an earlier restore) is created anew.
// The scope comes from the backup, except that a source a group here already
// uses is not made global under it.
func restoreSources(tx *sql.Tx, sources []backupSource, lists map[string][]backupEntry) (*sourceRestore, error) {
	sr := &sourceRestore{ids: map[int64]int64{}, skipped: []skippedItem{}}
	values := sourceValues(lists)
	for _, s := range sources {
		name := fmt.Sprintf("%s source %d (%s)", s.List, s.ID, s.Kind)
		if !database.IsSourceList(s.List) {
			sr.skipped = append(sr.skipped, skippedItem{name, "not a list that records sources"})
			continue
		}
		var id int64
		var err error
		existed := false
		switch s.Kind {
		case database.SourceURL, database.SourceGeo, database.SourcePreset, database.SourceManual:
			if s.Kind == database.SourceURL && !restorableSourceURL(s.Source) {
				sr.skipped = append(sr.skipped, skippedItem{name, "the URL is not http or https; its entries are restored under the Restore source"})
				continue
			}
			var n int
			_ = tx.QueryRow("SELECT COUNT(*) FROM list_sources WHERE list = ? AND kind = ? AND source = ?", s.List, s.Kind, s.Source).Scan(&n)
			existed = n > 0
			id, err = database.KeyedSource(tx, s.List, s.Kind, s.Source, s.Label)
		case database.SourcePaste, database.SourceRestore:
			// Restoring the same backup again, or onto the database it was
			// taken from, must not add a copy of every pasted list.
			if id, existed, err = sameEventSource(tx, s, values[s.ID]); err == nil && !existed {
				id, err = database.NewSource(tx, s.List, s.Kind, s.Label)
			}
		default:
			sr.skipped = append(sr.skipped, skippedItem{name, "unknown kind; its entries are restored under the Restore source"})
			continue
		}
		if err != nil {
			return nil, err
		}
		if !existed {
			sr.created = append(sr.created, id)
		}
		if err := restoreSourceScope(tx, s, id, existed, sr); err != nil {
			return nil, err
		}
		sr.ids[s.ID] = id
	}
	return sr, nil
}

// sourceValues is, for each of the backup's sources, the values of the
// entries it added (their Source).
func sourceValues(lists map[string][]backupEntry) map[int64][]string {
	out := map[int64][]string{}
	for _, t := range sourceListTables {
		for _, e := range lists[t.list] {
			if e.Source != nil {
				out[*e.Source] = append(out[*e.Source], strings.TrimSpace(e.Value))
			}
		}
	}
	return out
}

// sameEventSource finds the source here that is the backup's pasted list (or
// earlier restore) s: one source of the same list and kind that added every
// one of s's entries and nothing else. A source with no entries in the backup
// has nothing to be recognised by, and is created anew.
func sameEventSource(tx *sql.Tx, s backupSource, values []string) (int64, bool, error) {
	if len(values) == 0 {
		return 0, false, nil
	}
	var col string
	for _, t := range sourceListTables {
		if t.list == s.List {
			col = t.col
		}
	}
	if col == "" {
		return 0, false, nil
	}
	// #nosec G202 -- table and column names come from sourceListTables, constants
	q := "SELECT source_id FROM " + s.List + " WHERE " + col + " = ?"
	var found int64
	for _, v := range values {
		var id sql.NullInt64
		err := tx.QueryRow(q, v).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && !id.Valid) {
			return 0, false, nil
		}
		if err != nil {
			return 0, false, err
		}
		if found == 0 {
			found = id.Int64
		} else if id.Int64 != found {
			return 0, false, nil
		}
	}
	var kind string
	var n int
	if err := tx.QueryRow("SELECT kind FROM list_sources WHERE id = ? AND list = ?", found, s.List).Scan(&kind); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, false, nil
		}
		return 0, false, err
	}
	// #nosec G202 -- table name from sourceListTables, a constant
	if err := tx.QueryRow("SELECT COUNT(*) FROM "+s.List+" WHERE source_id = ?", found).Scan(&n); err != nil {
		return 0, false, err
	}
	if kind != s.Kind || n != len(values) {
		return 0, false, nil
	}
	return found, true, nil
}

// restoreSourceScope gives a restored blacklist source the backup's scope.
func restoreSourceScope(tx *sql.Tx, s backupSource, id int64, existed bool, sr *sourceRestore) error {
	if s.List != "ip_blacklist" && s.List != "domain_blacklist" {
		return nil
	}
	switch s.Scope {
	case database.ScopeGroups:
		_, err := tx.Exec("UPDATE list_sources SET scope = 'groups' WHERE id = ?", id)
		return err
	case database.ScopeGlobal, "":
		if !existed {
			return nil
		}
		var used int
		if err := tx.QueryRow("SELECT COUNT(*) FROM client_group_lists WHERE source_id = ?", id).Scan(&used); err != nil {
			return err
		}
		if used > 0 {
			sr.skipped = append(sr.skipped, skippedItem{
				fmt.Sprintf("%s source %d (%s)", s.List, s.ID, s.Kind),
				"a group here uses it, so it stays groups only although the backup has it global",
			})
			return nil
		}
		_, err := tx.Exec("UPDATE list_sources SET scope = 'global' WHERE id = ?", id)
		return err
	}
	return nil
}

// restorableSourceURL is a URL the list refresh may fetch: http or https with
// a host. The refresh checks it again against private networks before every
// fetch (workers/blacklist_refresh.go).
func restorableSourceURL(raw string) bool {
	if len(raw) > 2048 {
		return false
	}
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// dropUnusedRestoredSources deletes the sources this restore created that no
// entry and no group uses: a source of the backup whose entries were all
// refused, or already listed under a source of their own.
func dropUnusedRestoredSources(tx *sql.Tx, created []int64) error {
	for _, id := range created {
		var used int
		err := tx.QueryRow(`SELECT
			(SELECT COUNT(*) FROM ip_blacklist WHERE source_id = ?1) + (SELECT COUNT(*) FROM ip_blacklist_sources WHERE source_id = ?1) +
			(SELECT COUNT(*) FROM domain_blacklist WHERE source_id = ?1) + (SELECT COUNT(*) FROM domain_blacklist_sources WHERE source_id = ?1) +
			(SELECT COUNT(*) FROM ip_whitelist WHERE source_id = ?1) + (SELECT COUNT(*) FROM ip_whitelist_sources WHERE source_id = ?1) +
			(SELECT COUNT(*) FROM domain_whitelist WHERE source_id = ?1) + (SELECT COUNT(*) FROM domain_whitelist_sources WHERE source_id = ?1) +
			(SELECT COUNT(*) FROM client_group_lists WHERE source_id = ?1)`, id).Scan(&used)
		if err != nil {
			return err
		}
		if used == 0 {
			if _, err := tx.Exec("DELETE FROM list_sources WHERE id = ?", id); err != nil {
				return err
			}
		}
	}
	return nil
}

// restoreGroups writes the backup's groups inside tx: a group whose name is
// taken here is replaced, the others are added. A group is checked as the
// groups API checks it; one that fails, or names a list the restore could not
// map, is skipped with the reason.
func restoreGroups(tx *sql.Tx, groups []backupGroup, ids map[int64]int64) (restored int, skipped []skippedItem, err error) {
	skipped = []skippedItem{}
	for _, bg := range groups {
		g := database.ClientGroup{
			Name: bg.Name, Description: bg.Description, Members: bg.Members,
			Schedule: bg.Schedule, AllowlistOnly: bg.AllowlistOnly, Lists: []int64{},
		}
		missing := []string{}
		for _, old := range bg.Lists {
			id, ok := ids[old]
			if !ok {
				missing = append(missing, fmt.Sprint(old))
				continue
			}
			g.Lists = append(g.Lists, id)
		}
		if len(missing) > 0 {
			skipped = append(skipped, skippedItem{bg.Name, "its lists " + strings.Join(missing, ", ") + " are not in the backup's sources"})
			continue
		}
		if err := database.NormalizeClientGroup(&g); err != nil {
			skipped = append(skipped, skippedItem{bg.Name, strings.TrimPrefix(err.Error(), database.ErrGroupInvalid.Error()+": ")})
			continue
		}
		if err := tx.QueryRow("SELECT id FROM client_groups WHERE name = ?", g.Name).Scan(&g.ID); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return restored, skipped, err
		}
		if err := database.SaveClientGroupTx(tx, &g); err != nil {
			if errors.Is(err, database.ErrGroupInvalid) {
				skipped = append(skipped, skippedItem{bg.Name, err.Error()})
				continue
			}
			return restored, skipped, err
		}
		restored++
	}
	return restored, skipped, nil
}

// restoreWAFPolicy writes the backup's policy through the path PUT
// /api/waf/policy takes: the WAF validates it first, and nothing is written
// when it refuses or cannot be asked. It runs after the database commit; its
// outcome is reported, and a refusal does not undo the rest of the restore.
func (h *MaintenanceHandlers) restoreWAFPolicy(ctx context.Context, p *wafPolicyFile) map[string]any {
	ph := &WAFPolicyHandlers{db: h.db, cfg: h.cfg}
	wafPolicyMu.Lock()
	defer wafPolicyMu.Unlock()
	cur, _, exists, err := ph.readPolicy()
	if err == nil && exists && samePolicy(cur, *p) {
		return map[string]any{"restored": false, "unchanged": true}
	}
	digest, reload, err := ph.writePolicy(ctx, *p)
	if err != nil {
		return map[string]any{"restored": false, "detail": err.Error()}
	}
	return map[string]any{"restored": true, "sha256": digest, "waf": reload}
}

// samePolicy compares two policies as the file would hold them.
func samePolicy(a, b wafPolicyFile) bool {
	ja, err1 := json.Marshal(a)
	jb, err2 := json.Marshal(b)
	return err1 == nil && err2 == nil && string(ja) == string(jb)
}

// notInBackup names what a backup did not carry, for the response: a file
// from before version 3 has no sources, groups or WAF policy.
func notInBackup(hasSources, hasGroups, hasPolicy bool) []string {
	out := []string{}
	if !hasSources {
		out = append(out, "list_sources")
	}
	if !hasGroups {
		out = append(out, "client_groups")
	}
	if !hasPolicy {
		out = append(out, "waf_policy")
	}
	sort.Strings(out)
	return out
}
