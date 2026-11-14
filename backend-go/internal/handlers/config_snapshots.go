package handlers

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/config"
	appcrypto "github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/crypto"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/middleware"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/privacy"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/workers"
)

// Configuration history. A snapshot is the configuration an operator sets
// (the settings, the client groups, the WAF policy and the egress
// allowlist), taken before every change made through these routes and on
// demand. Any snapshot can be compared with the configuration in force and
// restored exactly; a restore takes a snapshot first, so it can be undone.
//
// The blacklists and whitelists are not in a snapshot: they are data with
// their own sources, refreshed from URLs, hundreds of thousands of entries
// that the backend's memory limit would not hold twice for a comparison.
// They are in the full backup (GET /api/maintenance/backup-config).

// snapshotKeep is how many snapshots are kept; the oldest go first.
const snapshotKeep = 200

// snapshotVersion is the shape of a snapshot's data.
const snapshotVersion = 1

// configSnapshot is what a snapshot holds. Every slice is sorted, so the same
// configuration always encodes to the same bytes and the same sha256.
type configSnapshot struct {
	Version         int                     `json:"version"`
	Settings        map[string]string       `json:"settings"`
	ClientGroups    []snapshotGroup         `json:"client_groups"`
	WAFPolicy       *wafPolicyFile          `json:"waf_policy"`
	EgressAllowlist []snapshotAllowlistItem `json:"egress_allowlist"`
}

// snapshotGroup names its lists by the source's identity, not its id: an id
// does not survive a source being removed and added again.
type snapshotGroup struct {
	Name          string                  `json:"name"`
	Description   string                  `json:"description"`
	Members       []string                `json:"members"`
	Lists         []snapshotSourceRef     `json:"lists"`
	Schedule      *database.GroupSchedule `json:"schedule"`
	AllowlistOnly bool                    `json:"allowlist_only"`
}

type snapshotSourceRef struct {
	List   string `json:"list"`
	Kind   string `json:"kind"`
	Source string `json:"source"`
	Label  string `json:"label"`
}

type snapshotAllowlistItem struct {
	Entry       string `json:"entry"`
	Description string `json:"description"`
}

// captureSnapshot reads the configuration in force.
func captureSnapshot(db *sql.DB, cfg *config.Config) (configSnapshot, error) {
	s := configSnapshot{Version: snapshotVersion, Settings: map[string]string{}, ClientGroups: []snapshotGroup{}, EgressAllowlist: []snapshotAllowlistItem{}}
	rows, err := db.Query("SELECT setting_name, setting_value FROM settings")
	if err != nil {
		return s, err
	}
	for rows.Next() {
		var k, v string
		if rows.Scan(&k, &v) == nil && isWritableSettingKey(k) {
			s.Settings[k] = v
		}
	}
	rows.Close()

	groups, err := database.ListClientGroups(db)
	if err != nil {
		return s, err
	}
	for _, g := range groups {
		sg := snapshotGroup{Name: g.Name, Description: g.Description, Members: g.Members, Schedule: g.Schedule, AllowlistOnly: g.AllowlistOnly, Lists: []snapshotSourceRef{}}
		for _, id := range g.Lists {
			var ref snapshotSourceRef
			if err := db.QueryRow("SELECT list, kind, source, label FROM list_sources WHERE id = ?", id).Scan(&ref.List, &ref.Kind, &ref.Source, &ref.Label); err == nil {
				sg.Lists = append(sg.Lists, ref)
			}
		}
		sort.Slice(sg.Lists, func(i, j int) bool { return refKey(sg.Lists[i]) < refKey(sg.Lists[j]) })
		s.ClientGroups = append(s.ClientGroups, sg)
	}
	sort.Slice(s.ClientGroups, func(i, j int) bool { return s.ClientGroups[i].Name < s.ClientGroups[j].Name })

	if cfg != nil {
		ph := &WAFPolicyHandlers{db: db, cfg: cfg}
		if pol, _, exists, perr := ph.readPolicy(); perr == nil && exists {
			s.WAFPolicy = &pol
		}
	}

	arows, err := db.Query("SELECT entry, COALESCE(description,'') FROM dst_allowlist ORDER BY entry")
	if err != nil {
		return s, err
	}
	for arows.Next() {
		var it snapshotAllowlistItem
		if arows.Scan(&it.Entry, &it.Description) == nil {
			s.EgressAllowlist = append(s.EgressAllowlist, it)
		}
	}
	arows.Close()
	return s, arows.Err()
}

func refKey(r snapshotSourceRef) string {
	return r.List + "\x00" + r.Kind + "\x00" + r.Source + "\x00" + r.Label
}

func snapshotDigest(s configSnapshot) (data []byte, digest string, err error) {
	data, err = json.Marshal(s) // map keys are sorted by encoding/json
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(data)
	return data, hex.EncodeToString(sum[:]), nil
}

// takeSnapshot stores the configuration in force, unless it is the one the
// newest snapshot already holds, and keeps the newest snapshotKeep. It
// returns the id of the snapshot that holds it, new or not.
func takeSnapshot(db *sql.DB, cfg *config.Config, username, reason string) (int64, bool, error) {
	s, err := captureSnapshot(db, cfg)
	if err != nil {
		return 0, false, err
	}
	data, digest, err := snapshotDigest(s)
	if err != nil {
		return 0, false, err
	}
	var lastID int64
	var lastDigest string
	err = db.QueryRow("SELECT id, sha256 FROM config_snapshots ORDER BY id DESC LIMIT 1").Scan(&lastID, &lastDigest)
	if err == nil && lastDigest == digest {
		return lastID, false, nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, false, err
	}
	res, err := db.Exec("INSERT INTO config_snapshots(created_at, username, reason, sha256, data) VALUES(?,?,?,?,?)",
		time.Now().Unix(), username, reason, digest, string(data))
	if err != nil {
		return 0, false, err
	}
	id, _ := res.LastInsertId()
	if _, err := db.Exec("DELETE FROM config_snapshots WHERE id NOT IN (SELECT id FROM config_snapshots ORDER BY id DESC LIMIT ?)", snapshotKeep); err != nil {
		log.Warn().Err(err).Msg("old configuration snapshots could not be pruned")
	}
	return id, true, nil
}

// snapshotState is what the snapshot middleware needs: set once by
// NewSnapshotHandlers. Without it (a test that builds one handler) the
// middleware does nothing.
var snapshotState atomic.Pointer[SnapshotHandlers]

// snapshotBefore takes a snapshot before the request reaches its handler,
// for a route that changes the configuration. A snapshot that cannot be
// taken is logged and the change goes ahead: history must not block a fix.
func snapshotBefore(reason string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if sh := snapshotState.Load(); sh != nil {
				user, _ := r.Context().Value(middleware.CtxUsername).(string)
				if _, _, err := takeSnapshot(sh.db, sh.cfg, user, "before "+reason); err != nil {
					log.Warn().Err(err).Str("reason", reason).Msg("configuration snapshot not taken")
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// SnapshotHandlers serves the configuration history.
type SnapshotHandlers struct {
	db  *sql.DB
	cfg *config.Config
}

// NewSnapshotHandlers returns the handlers and makes them the ones the
// snapshot middleware uses.
func NewSnapshotHandlers(db *sql.DB, cfg *config.Config) *SnapshotHandlers {
	h := &SnapshotHandlers{db: db, cfg: cfg}
	snapshotState.Store(h)
	return h
}

func (h *SnapshotHandlers) Register(r chi.Router, authMW func(http.Handler) http.Handler) {
	r.With(authMW).Get("/api/config/snapshots", h.List)
	r.With(authMW).Post("/api/config/snapshots", h.Take)
	r.With(authMW).Get("/api/config/snapshots/{id}/diff", h.Diff)
	r.With(authMW).Post("/api/config/snapshots/{id}/restore", h.Restore)
}

// List answers GET /api/config/snapshots: newest first, without their data;
// current marks the one that holds the configuration in force.
func (h *SnapshotHandlers) List(w http.ResponseWriter, _ *http.Request) {
	cur, _ := captureSnapshot(h.db, h.cfg)
	_, curDigest, _ := snapshotDigest(cur)
	rows, err := h.db.Query("SELECT id, created_at, username, reason, sha256 FROM config_snapshots ORDER BY id DESC")
	if err != nil {
		writeInternalError(w, "list_snapshots", err)
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, at int64
		var user, reason, digest string
		if rows.Scan(&id, &at, &user, &reason, &digest) != nil {
			continue
		}
		out = append(out, map[string]any{"id": id, "created_at": at, "username": user, "reason": reason, "sha256": digest, "current": digest == curDigest})
	}
	writeOK(w, out)
}

// Take answers POST /api/config/snapshots ({"note": "..."} optional).
func (h *SnapshotHandlers) Take(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Note string `json:"note"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body)
	note := strings.TrimSpace(body.Note)
	if len(note) > 200 || strings.ContainsAny(note, "\r\n") {
		writeError(w, http.StatusBadRequest, "a note is one line of at most 200 characters")
		return
	}
	reason := "taken by hand"
	if note != "" {
		reason += ": " + note
	}
	user, _ := r.Context().Value(middleware.CtxUsername).(string)
	id, created, err := takeSnapshot(h.db, h.cfg, user, reason)
	if err != nil {
		writeInternalError(w, "take_snapshot", err)
		return
	}
	writeOK(w, map[string]any{"id": id, "created": created})
}

func (h *SnapshotHandlers) load(r *http.Request) (int64, configSnapshot, error) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		return 0, configSnapshot{}, sql.ErrNoRows
	}
	var data string
	if err := h.db.QueryRow("SELECT data FROM config_snapshots WHERE id = ?", id).Scan(&data); err != nil {
		return id, configSnapshot{}, err
	}
	var s configSnapshot
	if err := json.Unmarshal([]byte(data), &s); err != nil || s.Version != snapshotVersion {
		return id, s, fmt.Errorf("snapshot %d does not decode: %v", id, err)
	}
	return id, s, nil
}

// snapshotSettingChange is one setting a restore would change: from is the value in
// force, to the snapshot's. A secret is named, never shown.
type snapshotSettingChange struct {
	Key    string  `json:"key"`
	From   *string `json:"from"`
	To     *string `json:"to"`
	Secret bool    `json:"secret,omitempty"`
}

// snapshotDiff is what restoring a snapshot would change.
type snapshotDiff struct {
	Settings      []snapshotSettingChange `json:"settings"`
	GroupsAdded   []string                `json:"groups_added"`
	GroupsRemoved []string                `json:"groups_removed"`
	GroupsChanged []string                `json:"groups_changed"`
	WAFPolicy     *struct {
		ModeFrom         string `json:"mode_from"`
		ModeTo           string `json:"mode_to"`
		ExceptionsFrom   int    `json:"exceptions_from"`
		ExceptionsTo     int    `json:"exceptions_to"`
		ObserveRulesFrom int    `json:"observe_rules_from"`
		ObserveRulesTo   int    `json:"observe_rules_to"`
	} `json:"waf_policy"`
	AllowlistAdded   []string `json:"egress_allowlist_added"`
	AllowlistRemoved []string `json:"egress_allowlist_removed"`
	Same             bool     `json:"same"`
}

func diffSnapshots(cur, to configSnapshot) snapshotDiff {
	d := snapshotDiff{Settings: []snapshotSettingChange{}, GroupsAdded: []string{}, GroupsRemoved: []string{}, GroupsChanged: []string{},
		AllowlistAdded: []string{}, AllowlistRemoved: []string{}}
	keys := map[string]bool{}
	for k := range to.Settings {
		keys[k] = true
	}
	// A setting the snapshot does not have (added by a later version) is left
	// as it is by a restore, so it is not a change.
	for k := range keys {
		cv, inCur := cur.Settings[k]
		tv := to.Settings[k]
		if inCur && cv == tv {
			continue
		}
		c := snapshotSettingChange{Key: k, Secret: isSecretKey(k)}
		if !c.Secret {
			if inCur {
				v := cv
				c.From = &v
			}
			v := tv
			c.To = &v
		}
		d.Settings = append(d.Settings, c)
	}
	sort.Slice(d.Settings, func(i, j int) bool { return d.Settings[i].Key < d.Settings[j].Key })

	curG := map[string]string{}
	for _, g := range cur.ClientGroups {
		b, _ := json.Marshal(g)
		curG[g.Name] = string(b)
	}
	toG := map[string]bool{}
	for _, g := range to.ClientGroups {
		toG[g.Name] = true
		b, _ := json.Marshal(g)
		if have, ok := curG[g.Name]; !ok {
			d.GroupsAdded = append(d.GroupsAdded, g.Name)
		} else if have != string(b) {
			d.GroupsChanged = append(d.GroupsChanged, g.Name)
		}
	}
	for name := range curG {
		if !toG[name] {
			d.GroupsRemoved = append(d.GroupsRemoved, name)
		}
	}
	sort.Strings(d.GroupsRemoved)

	if !samePolicyPtr(cur.WAFPolicy, to.WAFPolicy) && to.WAFPolicy != nil {
		p := &struct {
			ModeFrom         string `json:"mode_from"`
			ModeTo           string `json:"mode_to"`
			ExceptionsFrom   int    `json:"exceptions_from"`
			ExceptionsTo     int    `json:"exceptions_to"`
			ObserveRulesFrom int    `json:"observe_rules_from"`
			ObserveRulesTo   int    `json:"observe_rules_to"`
		}{ModeTo: modeOf(*to.WAFPolicy), ExceptionsTo: len(to.WAFPolicy.Exceptions), ObserveRulesTo: len(to.WAFPolicy.ObserveRules)}
		if cur.WAFPolicy != nil {
			p.ModeFrom, p.ExceptionsFrom, p.ObserveRulesFrom = modeOf(*cur.WAFPolicy), len(cur.WAFPolicy.Exceptions), len(cur.WAFPolicy.ObserveRules)
		}
		d.WAFPolicy = p
	}

	curA := map[string]bool{}
	for _, it := range cur.EgressAllowlist {
		curA[it.Entry] = true
	}
	toA := map[string]bool{}
	for _, it := range to.EgressAllowlist {
		toA[it.Entry] = true
		if !curA[it.Entry] {
			d.AllowlistAdded = append(d.AllowlistAdded, it.Entry)
		}
	}
	for _, it := range cur.EgressAllowlist {
		if !toA[it.Entry] {
			d.AllowlistRemoved = append(d.AllowlistRemoved, it.Entry)
		}
	}
	d.Same = len(d.Settings) == 0 && len(d.GroupsAdded) == 0 && len(d.GroupsRemoved) == 0 && len(d.GroupsChanged) == 0 &&
		d.WAFPolicy == nil && len(d.AllowlistAdded) == 0 && len(d.AllowlistRemoved) == 0
	return d
}

func samePolicyPtr(a, b *wafPolicyFile) bool {
	if a == nil || b == nil {
		return a == b
	}
	return samePolicy(*a, *b)
}

func isSecretKey(k string) bool { return appcrypto.IsSensitive(k) }

// Diff answers GET /api/config/snapshots/{id}/diff: what restoring the
// snapshot would change in the configuration in force.
func (h *SnapshotHandlers) Diff(w http.ResponseWriter, r *http.Request) {
	_, snap, err := h.load(r)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "no such snapshot")
		return
	}
	if err != nil {
		writeInternalError(w, "diff_snapshot", err)
		return
	}
	cur, err := captureSnapshot(h.db, h.cfg)
	if err != nil {
		writeInternalError(w, "diff_snapshot", err)
		return
	}
	writeOK(w, diffSnapshots(cur, snap))
}

// Restore answers POST /api/config/snapshots/{id}/restore: the configuration
// becomes the snapshot's exactly. The settings it holds are written (one a
// later version added is left), the groups are replaced (a group it does not
// have is removed), the egress allowlist is replaced, and the WAF policy goes
// through the WAF's check after the commit. A snapshot of the configuration
// in force is taken first, so the restore can be undone.
func (h *SnapshotHandlers) Restore(w http.ResponseWriter, r *http.Request) {
	id, snap, err := h.load(r)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "no such snapshot")
		return
	}
	if err != nil {
		writeInternalError(w, "restore_snapshot", err)
		return
	}
	user, _ := r.Context().Value(middleware.CtxUsername).(string)
	beforeID, _, err := takeSnapshot(h.db, h.cfg, user, fmt.Sprintf("before restoring snapshot %d", id))
	if err != nil {
		writeInternalError(w, "restore_snapshot", err)
		return
	}
	cur, err := captureSnapshot(h.db, h.cfg)
	if err != nil {
		writeInternalError(w, "restore_snapshot", err)
		return
	}
	diff := diffSnapshots(cur, snap)

	mh := &MaintenanceHandlers{db: h.db, cfg: h.cfg}
	tx, err := h.db.Begin()
	if err != nil {
		writeInternalError(w, "restore_snapshot", err)
		return
	}
	defer tx.Rollback() //nolint:errcheck // no-op once committed

	changed := map[string]string{}
	for _, c := range diff.Settings {
		changed[c.Key] = snap.Settings[c.Key]
	}
	_, skippedSettings, err := mh.restoreSettings(tx, changed)
	if err != nil {
		writeInternalError(w, "restore_snapshot", err)
		return
	}
	skippedGroups, err := replaceGroups(tx, snap.ClientGroups)
	if err != nil {
		writeInternalError(w, "restore_snapshot", err)
		return
	}
	if err := replaceAllowlist(tx, snap.EgressAllowlist); err != nil {
		writeInternalError(w, "restore_snapshot", err)
		return
	}
	if err := tx.Commit(); err != nil {
		writeInternalError(w, "restore_snapshot", err)
		return
	}
	privacy.InvalidateDB(h.db)
	settingsChanged()
	workers.RequestExport()

	// The proxy files every restored setting drives, as a save writes them,
	// and the proxy is asked to reload.
	// A secret is passed by name only: the files it drives (the proxy
	// password file, the upstream and LDAP files) are written from the
	// stored, decrypted value, as after a restore from a file.
	artefacts := map[string]string{}
	for k, v := range changed {
		if appcrypto.IsSensitive(k) {
			artefacts[k] = ""
			continue
		}
		artefacts[k] = v
	}
	sh := &SettingsHandlers{db: h.db, cfg: h.cfg}
	failedFiles := sh.writeSquidArtefacts(artefacts)
	if err := requestProxyReload(h.cfg.ConfigDir); err != nil {
		log.Warn().Err(err).Msg("proxy reload trigger not written after a snapshot restore")
	}
	var policy map[string]any
	if diff.WAFPolicy != nil && snap.WAFPolicy != nil {
		policy = mh.restoreWAFPolicy(r.Context(), snap.WAFPolicy)
	}
	auditChange(h.db, r, "restore_snapshot", strconv.FormatInt(id, 10), map[string]any{
		"settings": len(diff.Settings), "groups_added": len(diff.GroupsAdded), "groups_removed": len(diff.GroupsRemoved),
		"groups_changed": len(diff.GroupsChanged), "egress_allowlist_added": len(diff.AllowlistAdded),
		"egress_allowlist_removed": len(diff.AllowlistRemoved), "undo_snapshot": beforeID,
	})
	if failedFiles == nil {
		failedFiles = []string{}
	}
	writeOK(w, map[string]any{
		"restored":         id,
		"undo_snapshot":    beforeID,
		"changes":          diff,
		"skipped_settings": skippedSettings,
		"skipped_groups":   skippedGroups,
		"failed_files":     failedFiles,
		"waf_policy":       policy,
	})
}

// replaceGroups makes the client groups the snapshot's: a group it does not
// have is deleted, the others are written. A list whose source is gone is
// left out of its group and named.
func replaceGroups(tx *sql.Tx, groups []snapshotGroup) ([]skippedItem, error) {
	skipped := []skippedItem{}
	keep := map[string]bool{}
	for _, g := range groups {
		keep[g.Name] = true
	}
	rows, err := tx.Query("SELECT id, name FROM client_groups")
	if err != nil {
		return skipped, err
	}
	var drop []int64
	for rows.Next() {
		var id int64
		var name string
		if rows.Scan(&id, &name) == nil && !keep[name] {
			drop = append(drop, id)
		}
	}
	rows.Close()
	for _, id := range drop {
		if _, err := tx.Exec("DELETE FROM client_groups WHERE id = ?", id); err != nil {
			return skipped, err
		}
	}
	for _, sg := range groups {
		g := database.ClientGroup{Name: sg.Name, Description: sg.Description, Members: sg.Members, Schedule: sg.Schedule, AllowlistOnly: sg.AllowlistOnly, Lists: []int64{}}
		for _, ref := range sg.Lists {
			var sid int64
			err := tx.QueryRow("SELECT id FROM list_sources WHERE list = ? AND kind = ? AND source = ? AND label = ?", ref.List, ref.Kind, ref.Source, ref.Label).Scan(&sid)
			if err != nil {
				skipped = append(skipped, skippedItem{sg.Name, fmt.Sprintf("its list %q (%s) is no longer a source, so the group is restored without it", ref.Label+ref.Source, ref.Kind)})
				continue
			}
			if _, err := tx.Exec("UPDATE list_sources SET scope = 'groups' WHERE id = ? AND list IN ('ip_blacklist','domain_blacklist')", sid); err != nil {
				return skipped, err
			}
			g.Lists = append(g.Lists, sid)
		}
		if err := database.NormalizeClientGroup(&g); err != nil {
			skipped = append(skipped, skippedItem{sg.Name, err.Error()})
			continue
		}
		if err := tx.QueryRow("SELECT id FROM client_groups WHERE name = ?", g.Name).Scan(&g.ID); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return skipped, err
		}
		if err := database.SaveClientGroupTx(tx, &g); err != nil {
			if errors.Is(err, database.ErrGroupInvalid) {
				skipped = append(skipped, skippedItem{sg.Name, err.Error()})
				continue
			}
			return skipped, err
		}
	}
	return skipped, nil
}

// replaceAllowlist makes the egress allowlist the snapshot's.
func replaceAllowlist(tx *sql.Tx, items []snapshotAllowlistItem) error {
	keep := map[string]bool{}
	for _, it := range items {
		keep[it.Entry] = true
	}
	rows, err := tx.Query("SELECT id, entry FROM dst_allowlist")
	if err != nil {
		return err
	}
	var drop []int64
	for rows.Next() {
		var id int64
		var entry string
		if rows.Scan(&id, &entry) == nil && !keep[entry] {
			drop = append(drop, id)
		}
	}
	rows.Close()
	for _, id := range drop {
		if _, err := tx.Exec("DELETE FROM dst_allowlist WHERE id = ?", id); err != nil {
			return err
		}
	}
	for _, it := range items {
		if !validRestoredListValue("dst_allowlist", it.Entry) {
			continue
		}
		if _, err := tx.Exec("INSERT OR IGNORE INTO dst_allowlist(entry, type, description) VALUES(?,?,?)", it.Entry, egressEntryType(it.Entry), it.Description); err != nil {
			return err
		}
	}
	return nil
}
