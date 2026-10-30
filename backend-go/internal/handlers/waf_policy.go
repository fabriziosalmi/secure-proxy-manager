package handlers

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/go-chi/chi/v5"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/atomicfile"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/config"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/privacy"
)

// WAFPolicyHandlers manage the WAF's policy file and show what the WAF said
// about a block.
//
// The file (WAF_POLICY_FILE, /config/waf_policy.json) stays the one source of
// truth: the WAF reads it, and an operator may edit it by hand. The backend
// edits it only after the WAF has accepted the new content
// (POST /policy/validate), because a file the WAF refuses at start stops the
// WAF. It writes it atomically and readable by the WAF's user (0644; the
// backend runs as root and its other artefacts are 0600), then asks the WAF
// to reload it. With the WAF unreachable nothing is written.
type WAFPolicyHandlers struct {
	db  *sql.DB
	cfg *config.Config
	// mu serialises read-modify-write: two exceptions added at once must
	// both end up in the file.
	mu sync.Mutex
}

func NewWAFPolicyHandlers(db *sql.DB, cfg *config.Config) *WAFPolicyHandlers {
	return &WAFPolicyHandlers{db: db, cfg: cfg}
}

func (h *WAFPolicyHandlers) Register(r chi.Router, authMW func(http.Handler) http.Handler) {
	r.With(authMW).Get("/api/waf/events/{id}", h.Event)
	r.With(authMW).Get("/api/waf/policy", h.Get)
	r.With(authMW).Put("/api/waf/policy", h.Put)
	r.With(authMW).Post("/api/waf/policy/exceptions", h.AddException)
	r.With(authMW).Post("/api/waf/policy/observe-rules", h.ObserveRule)
}

// wafPolicyFile mirrors the WAF's policy.File (waf-go/internal/policy). The
// backend decodes it strictly too: a field it does not know would otherwise
// be dropped on the next write.
type wafPolicyFile struct {
	Version           int                  `json:"version"`
	Mode              string               `json:"mode,omitempty"`
	ObserveRules      []string             `json:"observe_rules,omitempty"`
	ObserveCategories []string             `json:"observe_categories,omitempty"`
	Exceptions        []wafPolicyException `json:"exceptions,omitempty"`
}

type wafPolicyException struct {
	Rule    string `json:"rule"`
	Host    string `json:"host,omitempty"`
	Path    string `json:"path,omitempty"`
	Target  string `json:"target,omitempty"`
	Comment string `json:"comment,omitempty"`
}

// sameScope is whether two exceptions take the same rule off the same
// requests; the comment does not count.
func (e wafPolicyException) sameScope(o wafPolicyException) bool {
	return e.Rule == o.Rule && strings.EqualFold(e.Host, o.Host) && e.Path == o.Path && strings.EqualFold(e.Target, o.Target)
}

// wafPolicyMax is the WAF's own limit on the file (policy.MaxFileSize).
const wafPolicyMax = 1 << 20

// readPolicy reads the file. A missing file is the empty policy, with an
// empty digest; a file that does not decode returns its digest and the error,
// so a PUT can still replace it.
func (h *WAFPolicyHandlers) readPolicy() (f wafPolicyFile, digest string, exists bool, err error) {
	raw, err := os.ReadFile(h.cfg.WAFPolicyFile)
	if errors.Is(err, fs.ErrNotExist) {
		return wafPolicyFile{Version: 1}, "", false, nil
	}
	if err != nil {
		return f, "", false, err
	}
	sum := sha256.Sum256(raw)
	digest = hex.EncodeToString(sum[:])
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return f, digest, true, fmt.Errorf("the policy file does not parse: %w", err)
	}
	return f, digest, true, nil
}

// wafPolicyStatus is the WAF's GET /policy, nil with the reason when it
// cannot be read.
func (h *WAFPolicyHandlers) wafPolicyStatus(ctx context.Context) (map[string]any, string) {
	resp, err := wafGetBreaker(ctx, h.cfg, "/policy")
	if err != nil {
		return nil, wafRefusal(h.cfg.AlertToken, err, 0)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, wafRefusal(h.cfg.AlertToken, nil, resp.StatusCode)
	}
	var body struct {
		Data map[string]any `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil || body.Data == nil {
		return nil, "the WAF's answer could not be read"
	}
	return body.Data, ""
}

// Get answers GET /api/waf/policy: the file, its digest (what a PUT must
// send back), and the policy the WAF has in force. in_force is true when the
// WAF runs this file; the WAF re-reads it within 5 seconds of a change.
func (h *WAFPolicyHandlers) Get(w http.ResponseWriter, r *http.Request) {
	f, digest, exists, err := h.readPolicy()
	data := map[string]any{"path": h.cfg.WAFPolicyFile, "exists": exists, "sha256": digest, "policy": f}
	if err != nil {
		data["policy"] = nil
		data["file_error"] = err.Error()
	}
	waf, reason := h.wafPolicyStatus(r.Context())
	data["waf"] = waf
	if waf == nil {
		data["waf_error"] = reason
	} else {
		wafDigest, _ := waf["sha256"].(string)
		data["in_force"] = wafDigest == digest || (!exists && wafDigest == "empty")
		if p, _ := waf["path"].(string); p != "" && p != h.cfg.WAFPolicyFile {
			data["path_mismatch"] = fmt.Sprintf("the WAF reads %s and the backend writes %s: set WAF_POLICY_FILE to the same path on both services", p, h.cfg.WAFPolicyFile)
		}
	}
	writeOK(w, data)
}

// errWAFRefused is a policy the WAF validated and refused.
type errWAFRefused struct{ detail string }

func (e errWAFRefused) Error() string { return "the WAF refused the policy: " + e.detail }

// errWAFUnchecked is a policy the WAF could not check.
type errWAFUnchecked struct{ reason string }

func (e errWAFUnchecked) Error() string {
	return "the WAF could not check the policy (" + e.reason + "), so nothing was written"
}

// writePolicy has the WAF validate f, writes it, and asks the WAF to reload
// it. The reload is reported, not required: the WAF's watcher picks the file
// up within 5 seconds anyway.
func (h *WAFPolicyHandlers) writePolicy(ctx context.Context, f wafPolicyFile) (digest string, reload map[string]any, err error) {
	raw, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return "", nil, err
	}
	raw = append(raw, '\n')
	if len(raw) > wafPolicyMax {
		return "", nil, errWAFRefused{fmt.Sprintf("the policy is over %d bytes", wafPolicyMax)}
	}
	resp, err := wafPostBreaker(ctx, h.cfg, "/policy/validate", bytes.NewReader(raw))
	if err != nil {
		return "", nil, errWAFUnchecked{wafRefusal(h.cfg.AlertToken, err, 0)}
	}
	var verdict struct {
		Detail string `json:"detail"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&verdict)
	resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusUnprocessableEntity:
		return "", nil, errWAFRefused{verdict.Detail}
	case resp.StatusCode != http.StatusOK:
		return "", nil, errWAFUnchecked{wafRefusal(h.cfg.AlertToken, nil, resp.StatusCode)}
	}
	if err := atomicfile.Write(h.cfg.WAFPolicyFile, raw, 0o644); err != nil {
		return "", nil, err
	}
	sum := sha256.Sum256(raw)
	digest = hex.EncodeToString(sum[:])

	reload = map[string]any{"reloaded": false}
	resp, err = wafPostBreaker(ctx, h.cfg, "/policy/reload", nil)
	if err != nil {
		reload["detail"] = wafRefusal(h.cfg.AlertToken, err, 0) + "; the WAF picks the file up within 5 seconds of coming back"
		return digest, reload, nil
	}
	var answer struct {
		Detail string `json:"detail"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&answer)
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		reload["reloaded"] = true
	} else if answer.Detail != "" {
		reload["detail"] = answer.Detail
	} else {
		reload["detail"] = wafRefusal(h.cfg.AlertToken, nil, resp.StatusCode)
	}
	return digest, reload, nil
}

// writeFailure answers a failed write: 422 for a policy the WAF refused, 503
// when it could not check it, 500 otherwise.
func writeFailure(w http.ResponseWriter, err error) {
	var refused errWAFRefused
	var unchecked errWAFUnchecked
	switch {
	case errors.As(err, &refused):
		writeError(w, http.StatusUnprocessableEntity, refused.Error())
	case errors.As(err, &unchecked):
		writeError(w, http.StatusServiceUnavailable, unchecked.Error())
	default:
		writeInternalError(w, "the policy file could not be written", err)
	}
}

// decodeStrict reads a JSON request body into v, refusing unknown fields.
func decodeStrict(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 2*wafPolicyMax))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// Put answers PUT /api/waf/policy with {"policy": {...}, "sha256": "..."}:
// the whole file, and the digest of the file it was edited from ("" when
// there was none). A file changed since is refused with 409, so an edit in
// one browser does not undo one made in another, or by hand.
func (h *WAFPolicyHandlers) Put(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Policy *wafPolicyFile `json:"policy"`
		SHA256 *string        `json:"sha256"`
	}
	if err := decodeStrict(r, &body); err != nil || body.Policy == nil || body.SHA256 == nil {
		writeError(w, http.StatusBadRequest, `send {"policy": {...}, "sha256": "<the sha256 GET /api/waf/policy returned>"}`)
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	before, digest, _, readErr := h.readPolicy()
	if digest != *body.SHA256 {
		writeError(w, http.StatusConflict, "the policy file changed since it was read: read it again and redo the change")
		return
	}
	newDigest, reload, err := h.writePolicy(r.Context(), *body.Policy)
	if err != nil {
		writeFailure(w, err)
		return
	}
	details := map[string]any{
		"exceptions": len(body.Policy.Exceptions), "observe_rules": len(body.Policy.ObserveRules),
		"observe_categories": len(body.Policy.ObserveCategories), "mode": modeOf(*body.Policy),
	}
	if readErr == nil {
		details["exceptions_before"], details["mode_before"] = len(before.Exceptions), modeOf(before)
	}
	auditChange(h.db, r, "update_waf_policy", h.cfg.WAFPolicyFile, details)
	writeOK(w, map[string]any{"sha256": newDigest, "waf": reload})
}

func modeOf(f wafPolicyFile) string {
	if f.Mode == "" {
		return "block"
	}
	return f.Mode
}

// AddException answers POST /api/waf/policy/exceptions with one exception
// ({"rule", "host"?, "path"?, "target"?, "comment"?}), as the access log
// offers it for a block. One with the same scope already there is not added
// twice.
func (h *WAFPolicyHandlers) AddException(w http.ResponseWriter, r *http.Request) {
	var e wafPolicyException
	if err := decodeStrict(r, &e); err != nil {
		writeError(w, http.StatusBadRequest, "send one exception: rule, and at least one of host, path and target")
		return
	}
	e.Rule, e.Host, e.Path, e.Target = strings.TrimSpace(e.Rule), strings.TrimSpace(e.Host), strings.TrimSpace(e.Path), strings.TrimSpace(e.Target)
	e.Comment = strings.TrimSpace(e.Comment)
	h.mu.Lock()
	defer h.mu.Unlock()
	f, _, _, err := h.readPolicy()
	if err != nil {
		writeError(w, http.StatusConflict, err.Error()+": fix the file, or replace it from the WAF policy settings")
		return
	}
	for _, x := range f.Exceptions {
		if x.sameScope(e) {
			writeOK(w, map[string]any{"added": false})
			return
		}
	}
	f.Exceptions = append(f.Exceptions, e)
	digest, reload, err := h.writePolicy(r.Context(), f)
	if err != nil {
		writeFailure(w, err)
		return
	}
	auditChange(h.db, r, "add_waf_exception", e.Rule, map[string]any{"host": e.Host, "path": e.Path, "target": e.Target})
	writeOK(w, map[string]any{"added": true, "sha256": digest, "waf": reload})
}

// ObserveRule answers POST /api/waf/policy/observe-rules with {"rule": "..."}:
// the rule keeps running and is recorded, and no longer blocks anywhere.
func (h *WAFPolicyHandlers) ObserveRule(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Rule string `json:"rule"`
	}
	if err := decodeStrict(r, &body); err != nil || strings.TrimSpace(body.Rule) == "" {
		writeError(w, http.StatusBadRequest, `send {"rule": "<rule ID>"}`)
		return
	}
	rule := strings.TrimSpace(body.Rule)
	h.mu.Lock()
	defer h.mu.Unlock()
	f, _, _, err := h.readPolicy()
	if err != nil {
		writeError(w, http.StatusConflict, err.Error()+": fix the file, or replace it from the WAF policy settings")
		return
	}
	for _, x := range f.ObserveRules {
		if x == rule {
			writeOK(w, map[string]any{"added": false})
			return
		}
	}
	f.ObserveRules = append(f.ObserveRules, rule)
	digest, reload, err := h.writePolicy(r.Context(), f)
	if err != nil {
		writeFailure(w, err)
		return
	}
	auditChange(h.db, r, "observe_waf_rule", rule, nil)
	writeOK(w, map[string]any{"added": true, "sha256": digest, "waf": reload})
}

// eventIDPattern is the WAF's event ID (nextEventID in waf-go): the time and
// a counter, both in base 36, joined by a dash.
var eventIDPattern = regexp.MustCompile(`^[a-z0-9]{1,32}-[a-z0-9]{1,20}$`)

// Event answers GET /api/waf/events/{id}: what the WAF reported about the
// block with that event ID. 404 when it never reached the backend or was
// pruned with the access log.
func (h *WAFPolicyHandlers) Event(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if !eventIDPattern.MatchString(id) {
		writeError(w, http.StatusBadRequest, "not a WAF event ID")
		return
	}
	e, err := database.GetWAFEvent(h.db, id)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "no WAF event with this ID: it did not reach the backend, or it was pruned with the access log")
		return
	}
	if err != nil {
		writeInternalError(w, "the WAF event could not be read", err)
		return
	}
	// Stored before GDPR mode was switched on: masked on the way out too.
	if privacy.Enabled(h.db) {
		e.ClientIP = privacy.MaskIP(e.ClientIP)
	}
	writeOK(w, e)
}
