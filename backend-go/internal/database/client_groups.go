package database

import (
	"bufio"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
)

// Client groups (schema version 11).
//
// A group is a set of clients, by source address or network, with extra
// restrictions on top of the policy every client gets: blocklist sources that
// apply to the group only, a time window, and allowlist-only egress. A group
// only tightens: the global lists, the DNS sinkhole and every global rule
// still apply to its members, and a client in two groups gets both sets of
// restrictions.
//
// A source of the IP or domain blacklist has a scope: 'global' (every client,
// the default) or 'groups' (only the groups that list it). A 'groups' source
// is not in the global files or the DNS sinkhole, which cannot tell clients
// apart: Squid enforces it, one ACL per source that the groups reference
// (loaded once however many groups use it; measured in the G0 spike). An
// entry that a global source also lists stays global.
//
// The export writes the groups' files under <config>/groups (groupsDir),
// listed in the lists manifest so the proxy copies them verified; the proxy's
// generator builds the rules from groups.conf (proxy/generate_squid_conf.sh).

const (
	ScopeGlobal = "global"
	ScopeGroups = "groups"

	// groupsDir holds the files of the groups, under the config directory.
	groupsDir = "groups"
	// GroupsIndexName is the index the proxy's generator reads, one line per
	// group (writeGroupsIndex).
	GroupsIndexName = "groups.conf"

	maxGroupMembers = 1000
	maxGroupLists   = 50
)

// ClientGroup is a group as the API reads and writes it.
type ClientGroup struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	// Members are addresses or networks, as given (normalised to a prefix).
	Members []string `json:"members"`
	// Lists are the ids of blacklist sources whose scope is 'groups'.
	Lists []int64 `json:"lists"`
	// Schedule, when set, is the only window the group may browse in.
	Schedule      *GroupSchedule `json:"schedule"`
	AllowlistOnly bool           `json:"allowlist_only"`
}

// GroupSchedule is a window within one day, on the days given in Squid's
// letters: S Sunday, M Monday, T Tuesday, W Wednesday, H Thursday, F Friday,
// A Saturday.
type GroupSchedule struct {
	Days  string `json:"days"`
	Start string `json:"start"`
	End   string `json:"end"`
}

// squidDays is every day letter, in the order Squid's documentation lists them.
const squidDays = "SMTWHFA"

var (
	groupNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._-]{0,39}$`)
	timeOfDayRe = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)
)

// ErrGroupInvalid wraps a refusal of a group's fields; its text is for the user.
var ErrGroupInvalid = errors.New("invalid group")

func groupInvalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrGroupInvalid, fmt.Sprintf(format, a...))
}

// NormalizeClientGroup checks and normalises g in place: the name, the
// members (each an address or a network, written as its masked prefix,
// without repeats), the lists (without repeats) and the schedule. The lists
// are checked against the database when the group is saved.
func NormalizeClientGroup(g *ClientGroup) error {
	g.Name = strings.TrimSpace(g.Name)
	if !groupNameRe.MatchString(g.Name) {
		return groupInvalid("the name is 1 to 40 letters, digits, spaces, dots, hyphens or underscores, starting with a letter or a digit")
	}
	g.Description = strings.TrimSpace(g.Description)
	if len(g.Description) > 200 || strings.ContainsAny(g.Description, "\r\n") {
		return groupInvalid("the description is one line of at most 200 characters")
	}
	if len(g.Members) > maxGroupMembers {
		return groupInvalid("a group has at most %d members", maxGroupMembers)
	}
	seen := map[string]bool{}
	members := []string{}
	for _, m := range g.Members {
		p, err := clientPrefix(strings.TrimSpace(m))
		if err != nil {
			return groupInvalid("%q is not an IP address or network", m)
		}
		if !seen[p] {
			seen[p] = true
			members = append(members, p)
		}
	}
	sort.Strings(members)
	g.Members = members
	if len(g.Lists) > maxGroupLists {
		return groupInvalid("a group uses at most %d lists", maxGroupLists)
	}
	ids := map[int64]bool{}
	lists := []int64{}
	for _, id := range g.Lists {
		if id <= 0 {
			return groupInvalid("%d is not a source id", id)
		}
		if !ids[id] {
			ids[id] = true
			lists = append(lists, id)
		}
	}
	sort.Slice(lists, func(i, j int) bool { return lists[i] < lists[j] })
	g.Lists = lists
	if g.Schedule != nil {
		s := g.Schedule
		days := ""
		for _, c := range squidDays {
			if strings.ContainsRune(s.Days, c) {
				days += string(c)
			}
		}
		if days == "" || len(days) != len(dedupeRunes(s.Days)) {
			return groupInvalid("days are letters among S M T W H F A (Sunday to Saturday), at least one")
		}
		s.Days = days
		if !timeOfDayRe.MatchString(s.Start) || !timeOfDayRe.MatchString(s.End) {
			return groupInvalid("start and end are times of day, HH:MM")
		}
		if s.End <= s.Start {
			return groupInvalid("the window ends after it starts, on the same day")
		}
	}
	return nil
}

func dedupeRunes(s string) string {
	seen := map[rune]bool{}
	out := ""
	for _, c := range s {
		if !seen[c] {
			seen[c] = true
			out += string(c)
		}
	}
	return out
}

// clientPrefix is an address or a network as a masked prefix ("10.0.0.5/32",
// "10.1.0.0/16"); an address is a single host.
func clientPrefix(v string) (string, error) {
	if strings.Contains(v, "/") {
		p, err := netip.ParsePrefix(v)
		if err != nil {
			return "", err
		}
		return p.Masked().String(), nil
	}
	a, err := netip.ParseAddr(v)
	if err != nil {
		return "", err
	}
	return netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()).String(), nil
}

// migrateClientGroups records version 11: the scope of a list source and the
// three tables of the groups.
func migrateClientGroups(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op once committed
	has, err := hasColumn(tx, "list_sources", "scope")
	if err != nil {
		return err
	}
	if !has {
		if _, err := tx.Exec(`ALTER TABLE list_sources ADD COLUMN scope TEXT NOT NULL DEFAULT 'global' CHECK (scope IN ('global','groups'))`); err != nil {
			return fmt.Errorf("list_sources.scope: %w", err)
		}
	}
	for _, s := range []string{
		`CREATE TABLE IF NOT EXISTS client_groups (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL UNIQUE,
			description TEXT NOT NULL DEFAULT '',
			allowlist_only INTEGER NOT NULL DEFAULT 0 CHECK (allowlist_only IN (0, 1)),
			days TEXT NOT NULL DEFAULT '',
			time_start TEXT NOT NULL DEFAULT '',
			time_end TEXT NOT NULL DEFAULT '',
			created TEXT DEFAULT (datetime('now'))
		)`,
		// kind is 'cidr' today; users and directory groups come with the
		// directory login. No CHECK, so adding a kind needs no table rebuild.
		`CREATE TABLE IF NOT EXISTS client_group_members (
			group_id INTEGER NOT NULL REFERENCES client_groups(id) ON DELETE CASCADE,
			kind TEXT NOT NULL,
			value TEXT NOT NULL,
			PRIMARY KEY (group_id, kind, value)
		) WITHOUT ROWID`,
		`CREATE TABLE IF NOT EXISTS client_group_lists (
			group_id INTEGER NOT NULL REFERENCES client_groups(id) ON DELETE CASCADE,
			source_id INTEGER NOT NULL REFERENCES list_sources(id) ON DELETE CASCADE,
			PRIMARY KEY (group_id, source_id)
		) WITHOUT ROWID`,
		`CREATE INDEX IF NOT EXISTS idx_client_group_lists_source ON client_group_lists(source_id)`,
		"PRAGMA user_version = 11",
	} {
		if _, err := tx.Exec(s); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	log.Info().Int("version", 11).Msg("schema migrated: client groups, and a scope on every list source")
	return nil
}

// ListClientGroups returns every group, by name.
func ListClientGroups(db *sql.DB) ([]ClientGroup, error) {
	rows, err := db.Query("SELECT id, name, description, allowlist_only, days, time_start, time_end FROM client_groups ORDER BY name")
	if err != nil {
		return nil, err
	}
	var out []ClientGroup
	for rows.Next() {
		var g ClientGroup
		var days, start, end string
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.AllowlistOnly, &days, &start, &end); err != nil {
			rows.Close()
			return nil, err
		}
		if days != "" {
			g.Schedule = &GroupSchedule{Days: days, Start: start, End: end}
		}
		g.Members, g.Lists = []string{}, []int64{}
		out = append(out, g)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		if err := fillClientGroup(db, &out[i]); err != nil {
			return nil, err
		}
	}
	if out == nil {
		out = []ClientGroup{}
	}
	return out, nil
}

// GetClientGroup returns one group, or sql.ErrNoRows.
func GetClientGroup(db *sql.DB, id int64) (ClientGroup, error) {
	var g ClientGroup
	var days, start, end string
	err := db.QueryRow("SELECT id, name, description, allowlist_only, days, time_start, time_end FROM client_groups WHERE id = ?", id).
		Scan(&g.ID, &g.Name, &g.Description, &g.AllowlistOnly, &days, &start, &end)
	if err != nil {
		return g, err
	}
	if days != "" {
		g.Schedule = &GroupSchedule{Days: days, Start: start, End: end}
	}
	return g, fillClientGroup(db, &g)
}

func fillClientGroup(db *sql.DB, g *ClientGroup) error {
	g.Members, g.Lists = []string{}, []int64{}
	rows, err := db.Query("SELECT value FROM client_group_members WHERE group_id = ? AND kind = 'cidr' ORDER BY value", g.ID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return err
		}
		g.Members = append(g.Members, v)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	rows, err = db.Query("SELECT source_id FROM client_group_lists WHERE group_id = ? ORDER BY source_id", g.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return err
		}
		g.Lists = append(g.Lists, id)
	}
	return rows.Err()
}

// ErrGroupNameTaken is SaveClientGroup refusing a name another group has.
var ErrGroupNameTaken = errors.New("a group with this name exists")

// SaveClientGroup creates g (ID 0) or replaces the group g.ID, members and
// lists included, in one transaction. g must be normalised. Every list must
// be a source of the IP or domain blacklist whose scope is 'groups'.
func SaveClientGroup(db *sql.DB, g *ClientGroup) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op once committed
	for _, id := range g.Lists {
		var list, scope string
		err := tx.QueryRow("SELECT list, scope FROM list_sources WHERE id = ?", id).Scan(&list, &scope)
		if errors.Is(err, sql.ErrNoRows) {
			return groupInvalid("source %d does not exist", id)
		}
		if err != nil {
			return err
		}
		if list != "ip_blacklist" && list != "domain_blacklist" {
			return groupInvalid("source %d is not a source of Blocked IPs or Blocked domains", id)
		}
		if scope != ScopeGroups {
			return groupInvalid("source %d applies to every client: set it to groups only first", id)
		}
	}
	days, start, end := "", "", ""
	if g.Schedule != nil {
		days, start, end = g.Schedule.Days, g.Schedule.Start, g.Schedule.End
	}
	if g.ID == 0 {
		res, err := tx.Exec("INSERT INTO client_groups(name, description, allowlist_only, days, time_start, time_end) VALUES(?,?,?,?,?,?)",
			g.Name, g.Description, g.AllowlistOnly, days, start, end)
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				return ErrGroupNameTaken
			}
			return err
		}
		if g.ID, err = res.LastInsertId(); err != nil {
			return err
		}
	} else {
		res, err := tx.Exec("UPDATE client_groups SET name = ?, description = ?, allowlist_only = ?, days = ?, time_start = ?, time_end = ? WHERE id = ?",
			g.Name, g.Description, g.AllowlistOnly, days, start, end, g.ID)
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				return ErrGroupNameTaken
			}
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return sql.ErrNoRows
		}
		for _, q := range []string{"DELETE FROM client_group_members WHERE group_id = ?", "DELETE FROM client_group_lists WHERE group_id = ?"} {
			if _, err := tx.Exec(q, g.ID); err != nil {
				return err
			}
		}
	}
	for _, m := range g.Members {
		if _, err := tx.Exec("INSERT INTO client_group_members(group_id, kind, value) VALUES(?, 'cidr', ?)", g.ID, m); err != nil {
			return err
		}
	}
	for _, id := range g.Lists {
		if _, err := tx.Exec("INSERT INTO client_group_lists(group_id, source_id) VALUES(?, ?)", g.ID, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// DeleteClientGroup removes a group, its members and its lists; false when
// there was no such group.
func DeleteClientGroup(db *sql.DB, id int64) (bool, error) {
	res, err := db.Exec("DELETE FROM client_groups WHERE id = ?", id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ErrSourceInUse is SetSourceScope refusing to make global a source groups use.
var ErrSourceInUse = errors.New("source in use by a group")

// SetSourceScope sets the scope of a source of the IP or domain blacklist.
// A source a group uses cannot go back to global: the group would silently
// lose a list it chose. Returns sql.ErrNoRows for no such source on list.
func SetSourceScope(db *sql.DB, list string, id int64, scope string) error {
	if list != "ip_blacklist" && list != "domain_blacklist" {
		return ErrUnknownList
	}
	if scope != ScopeGlobal && scope != ScopeGroups {
		return fmt.Errorf("scope %q is not global or groups", scope)
	}
	if scope == ScopeGlobal {
		var n int
		if err := db.QueryRow("SELECT COUNT(*) FROM client_group_lists WHERE source_id = ?", id).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return ErrSourceInUse
		}
	}
	res, err := db.Exec("UPDATE list_sources SET scope = ? WHERE id = ? AND list = ?", scope, id, list)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// anyGroupsScope reports whether some source applies to groups only, so the
// global export can take its plain query when none does.
func anyGroupsScope(db *sql.DB) (bool, error) {
	var n int
	err := db.QueryRow("SELECT EXISTS (SELECT 1 FROM list_sources WHERE scope = 'groups')").Scan(&n)
	return n == 1, err
}

// The entries every client gets: those with no recorded source, or with at
// least one global source among the one that added them and the others.
const (
	globalIPBlacklistQuery = `SELECT t.ip FROM ip_blacklist t
		WHERE t.source_id IS NULL
		OR EXISTS (SELECT 1 FROM list_sources s WHERE s.id = t.source_id AND s.scope = 'global')
		OR EXISTS (SELECT 1 FROM ip_blacklist_sources x JOIN list_sources s ON s.id = x.source_id WHERE x.entry_id = t.id AND s.scope = 'global')
		ORDER BY t.ip`
	globalDomainBlacklistQuery = `SELECT t.domain FROM domain_blacklist t
		WHERE t.source_id IS NULL
		OR EXISTS (SELECT 1 FROM list_sources s WHERE s.id = t.source_id AND s.scope = 'global')
		OR EXISTS (SELECT 1 FROM domain_blacklist_sources x JOIN list_sources s ON s.id = x.source_id WHERE x.entry_id = t.id AND s.scope = 'global')
		ORDER BY t.domain`
	// The entries one source lists, as the one that added them or another.
	ipBySourceQuery = `SELECT t.ip FROM ip_blacklist t WHERE t.source_id = ?
		UNION SELECT t.ip FROM ip_blacklist_sources x JOIN ip_blacklist t ON t.id = x.entry_id WHERE x.source_id = ?
		ORDER BY 1`
	domainBySourceQuery = `SELECT t.domain FROM domain_blacklist t WHERE t.source_id = ?
		UNION SELECT t.domain FROM domain_blacklist_sources x JOIN domain_blacklist t ON t.id = x.entry_id WHERE x.source_id = ?
		ORDER BY 1`
)

// globalBlacklistQueries returns the queries of the global IP and domain
// exports: the plain ones while no source applies to groups only.
func globalBlacklistQueries(db *sql.DB) (ipQuery, domainQuery string, err error) {
	scoped, err := anyGroupsScope(db)
	if err != nil {
		return "", "", err
	}
	if !scoped {
		return "SELECT ip FROM ip_blacklist ORDER BY ip", "SELECT domain FROM domain_blacklist ORDER BY domain", nil
	}
	return globalIPBlacklistQuery, globalDomainBlacklistQuery, nil
}

// exportGroups writes <config>/groups: for every group, g<ID>_src.txt (its
// members); for every source a group uses, s<ID>_ip.txt or s<ID>_domain.txt
// (its entries, the domains less the allowed ones, as the global list); and
// groups.conf, the index. Files of groups and sources no longer used are
// removed. It returns the paths it wrote, relative to configDir, for the
// manifest.
func exportGroups(db *sql.DB, configDir string, exclusions map[string]struct{}) ([]string, error) {
	dir := filepath.Join(configDir, groupsDir)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	groups, err := ListClientGroups(db)
	if err != nil {
		return nil, err
	}
	sourceList := map[int64]string{}
	rows, err := db.Query(`SELECT DISTINCT s.id, s.list FROM client_group_lists l JOIN list_sources s ON s.id = l.source_id
		WHERE s.scope = 'groups' AND s.list IN ('ip_blacklist', 'domain_blacklist')`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id int64
		var list string
		if err := rows.Scan(&id, &list); err != nil {
			rows.Close()
			return nil, err
		}
		sourceList[id] = list
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	keep := map[string]bool{GroupsIndexName: true}
	var written []string
	for id, list := range sourceList {
		name := fmt.Sprintf("s%d_%s.txt", id, map[string]string{"ip_blacklist": "ip", "domain_blacklist": "domain"}[list])
		path := filepath.Join(dir, name)
		if list == "ip_blacklist" {
			err = streamList(db, path, ipBySourceQuery, func(w *bufio.Writer, v string) error {
				_, err := fmt.Fprintln(w, v)
				return err
			}, id, id)
		} else {
			err = streamList(db, path, domainBySourceQuery, func(w *bufio.Writer, v string) error {
				if _, excluded := exclusions[EnforcedDomain(v)]; excluded {
					return nil
				}
				_, err := fmt.Fprintln(w, v)
				return err
			}, id, id)
		}
		if err != nil {
			return nil, fmt.Errorf("group list %s: %w", name, err)
		}
		keep[name] = true
		written = append(written, groupsDir+"/"+name)
	}
	var index strings.Builder
	for _, g := range groups {
		name := fmt.Sprintf("g%d_src.txt", g.ID)
		if err := atomicWrite(filepath.Join(dir, name), func(f *os.File) error {
			for _, m := range g.Members {
				if _, err := fmt.Fprintln(f, m); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return nil, err
		}
		keep[name] = true
		written = append(written, groupsDir+"/"+name)
		index.WriteString(groupIndexLine(g, sourceList))
	}
	if err := atomicWrite(filepath.Join(dir, GroupsIndexName), func(f *os.File) error {
		_, err := f.WriteString(index.String())
		return err
	}); err != nil {
		return nil, err
	}
	written = append(written, groupsDir+"/"+GroupsIndexName)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if !keep[e.Name()] && !e.IsDir() {
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(written)
	return written, nil
}

// groupIndexLine is one line of groups.conf, the whole of what the generator
// reads about a group; it validates every line with one pattern:
//
//	group <id> days=<letters|-> start=<HH:MM|-> end=<HH:MM|-> allowlist_only=<0|1> domain=<ids|-> ip=<ids|->
func groupIndexLine(g ClientGroup, sourceList map[int64]string) string {
	days, start, end := "-", "-", "-"
	if g.Schedule != nil {
		days, start, end = g.Schedule.Days, g.Schedule.Start, g.Schedule.End
	}
	var domains, ips []string
	for _, id := range g.Lists {
		switch sourceList[id] {
		case "domain_blacklist":
			domains = append(domains, strconv.FormatInt(id, 10))
		case "ip_blacklist":
			ips = append(ips, strconv.FormatInt(id, 10))
		}
	}
	join := func(v []string) string {
		if len(v) == 0 {
			return "-"
		}
		return strings.Join(v, ",")
	}
	allow := 0
	if g.AllowlistOnly {
		allow = 1
	}
	return fmt.Sprintf("group %d days=%s start=%s end=%s allowlist_only=%d domain=%s ip=%s\n",
		g.ID, days, start, end, allow, join(domains), join(ips))
}
