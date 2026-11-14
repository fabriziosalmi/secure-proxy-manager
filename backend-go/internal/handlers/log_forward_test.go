package handlers

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/logforward"
)

func setSetting(t *testing.T, h *SettingsHandlers, kv map[string]string) {
	t.Helper()
	if w, resp := bulkUpdate(t, h, "", kv); w.Code != http.StatusOK {
		t.Fatalf("saving %v: %d %v", kv, w.Code, resp)
	}
}

// Off until a host is set, whatever the switch says; the defaults are RFC
// 5424 over UDP 514, blocked requests and audit events; GDPR mode masks.
func TestLogForwardConfigFollowsTheSettings(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	sh := NewSettingsHandlers(db, cfg)
	c := LogForwardConfig(db)
	if c.Enabled || c.Port != 514 || c.Protocol != logforward.ProtoUDP || c.Format != logforward.FormatRFC5424 ||
		c.Events != logforward.EventsBlocked || !c.Audit || c.MaskIPs {
		t.Errorf("defaults = %+v", c)
	}
	setSetting(t, sh, map[string]string{settingLogForwardEnabled: "true"})
	if LogForwardConfig(db).Enabled {
		t.Error("on without a host")
	}
	setSetting(t, sh, map[string]string{settingLogForwardHost: "siem.example.internal", settingLogForwardProtocol: "tls", "gdpr_mode": "true"})
	c = LogForwardConfig(db)
	if !c.Enabled || c.Host != "siem.example.internal" || c.Protocol != logforward.ProtoTLS || !c.MaskIPs {
		t.Errorf("configured = %+v", c)
	}
	// A value written past the API is read as off, not used.
	if _, err := db.Exec(`UPDATE settings SET setting_value = 'smtp' WHERE setting_name = ?`, settingLogForwardProtocol); err != nil {
		t.Fatal(err)
	}
	if LogForwardConfig(db).Enabled {
		t.Error("on with protocol smtp")
	}
}

func TestLogForwardSettingsAreValidated(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	sh := NewSettingsHandlers(db, cfg)
	for k, v := range map[string]string{
		settingLogForwardHost:     "http://siem.example",
		settingLogForwardPort:     "70000",
		settingLogForwardProtocol: "smtp",
		settingLogForwardFormat:   "cef",
		settingLogForwardEvents:   "some",
		settingLogForwardEnabled:  "yes",
		settingLogForwardHostname: "spm host",
	} {
		if w, _ := bulkUpdate(t, sh, "", map[string]string{k: v}); w.Code == http.StatusOK {
			t.Errorf("%s=%q was accepted", k, v)
		}
	}
	for k, v := range map[string]string{
		settingLogForwardHost: "10.0.0.5", settingLogForwardPort: "6514", settingLogForwardProtocol: "tcp",
		settingLogForwardFormat: "json", settingLogForwardEvents: "all", settingLogForwardHostname: "proxy-1.lan",
	} {
		if w, resp := bulkUpdate(t, sh, "", map[string]string{k: v}); w.Code != http.StatusOK {
			t.Errorf("%s=%q refused: %v", k, v, resp)
		}
	}
}

// The test sends one event to the saved target now, says whether it went,
// and is in the audit log either way.
func TestLogForwardTestSendsOneEvent(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	sh := NewSettingsHandlers(db, cfg)
	h := NewLogForwardHandlers(db)
	post := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.Test(w, httptest.NewRequest("POST", "/api/log-forward/test", nil))
		return w
	}
	if w := post(); w.Code != http.StatusBadRequest {
		t.Errorf("no host: %d", w.Code)
	}

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	_, p, _ := net.SplitHostPort(pc.LocalAddr().String())
	setSetting(t, sh, map[string]string{settingLogForwardHost: "127.0.0.1", settingLogForwardPort: p})
	if w := post(); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "UDP, which has no answer") {
		t.Fatalf("udp: %d %s", w.Code, w.Body.String())
	}
	_ = pc.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 2048)
	n, _, err := pc.ReadFrom(buf)
	if err != nil || !strings.Contains(string(buf[:n]), " - test - message=\"test event from Secure Proxy Manager\"") {
		t.Fatalf("received %q, %v", buf[:n], err)
	}

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	setSetting(t, sh, map[string]string{settingLogForwardProtocol: "tcp", settingLogForwardPort: strconv.Itoa(closed)})
	if w := post(); w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "did not reach 127.0.0.1:"+strconv.Itoa(closed)+" over tcp") {
		t.Errorf("closed port: %d %s", w.Code, w.Body.String())
	}
	var n2 int
	_ = db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action = 'test_log_forward'`).Scan(&n2)
	if n2 != 2 {
		t.Errorf("%d audit rows for the two tests", n2)
	}
}

// Every audit event reaches the hook the forwarder sets.
func TestAuditEventsReachTheForwarderHook(t *testing.T) {
	db, _, _, cleanup := setupTestDB(t)
	defer cleanup()
	var got []string
	database.SetAuditHook(func(user, action, target, details string) { got = append(got, user+"/"+action+"/"+target) })
	defer database.SetAuditHook(nil)
	database.Audit(db, "admin", "update_settings", "gdpr_mode", "{}")
	if len(got) != 1 || got[0] != "admin/update_settings/gdpr_mode" {
		t.Errorf("hook got %v", got)
	}
}
