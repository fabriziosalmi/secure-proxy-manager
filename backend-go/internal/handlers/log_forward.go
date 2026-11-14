package handlers

import (
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/logforward"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/privacy"
)

// The settings of log forwarding (internal/logforward), on the Logs and
// privacy page. The forwarder reads them every logforward.ReloadEvery.
const (
	settingLogForwardEnabled  = "log_forward_enabled"
	settingLogForwardHost     = "log_forward_host"
	settingLogForwardPort     = "log_forward_port"
	settingLogForwardProtocol = "log_forward_protocol"
	settingLogForwardFormat   = "log_forward_format"
	settingLogForwardEvents   = "log_forward_events"
	settingLogForwardAudit    = "log_forward_audit"
	settingLogForwardHostname = "log_forward_hostname"
)

// hostnameRE is a DNS name: labels of letters, digits and hyphens.
var hostnameRE = regexp.MustCompile(`^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$`)

// validLogForwardHost is empty, an IP address, or a DNS name.
func validLogForwardHost(v string) error {
	if v == "" {
		return nil
	}
	if len(v) > 253 {
		return errors.New("at most 253 characters")
	}
	if net.ParseIP(v) != nil || hostnameRE.MatchString(v) {
		return nil
	}
	return errors.New("an IP address or a host name, without a scheme or a port")
}

// validChoice accepts exactly one of choices.
func validChoice(choices ...string) func(string) error {
	return func(v string) error {
		for _, c := range choices {
			if v == c {
				return nil
			}
		}
		return fmt.Errorf("one of %s", strings.Join(choices, ", "))
	}
}

func init() {
	settingValidators[settingLogForwardHost] = validLogForwardHost
	settingValidators[settingLogForwardPort] = validPort
	settingValidators[settingLogForwardProtocol] = validChoice(logforward.ProtoUDP, logforward.ProtoTCP, logforward.ProtoTLS)
	settingValidators[settingLogForwardFormat] = validChoice(logforward.FormatRFC5424, logforward.FormatJSON)
	settingValidators[settingLogForwardEvents] = validChoice(logforward.EventsAll, logforward.EventsBlocked, logforward.EventsNone)
	settingValidators[settingLogForwardHostname] = func(v string) error {
		if v == "" {
			return nil
		}
		if len(v) > 255 || !hostnameRE.MatchString(v) {
			return errors.New("a host name: letters, digits, hyphens and dots")
		}
		return nil
	}
}

// LogForwardConfig reads the forwarding settings. Forwarding is on only when
// the switch is on and a host is set; a value the settings API would refuse
// (the database edited by hand) is read as off.
func LogForwardConfig(db *sql.DB) logforward.Config {
	v := map[string]string{}
	rows, err := db.Query(`SELECT setting_name, setting_value FROM settings WHERE setting_name LIKE 'log\_forward\_%' ESCAPE '\'`)
	if err != nil {
		return logforward.Config{}
	}
	for rows.Next() {
		var k, val string
		if rows.Scan(&k, &val) == nil {
			v[k] = val
		}
	}
	rows.Close()
	port, _ := strconv.Atoi(v[settingLogForwardPort])
	c := logforward.Config{
		Enabled:  v[settingLogForwardEnabled] == "true",
		Host:     v[settingLogForwardHost],
		Port:     port,
		Protocol: v[settingLogForwardProtocol],
		Format:   v[settingLogForwardFormat],
		Events:   v[settingLogForwardEvents],
		Audit:    v[settingLogForwardAudit] == "true",
		Hostname: v[settingLogForwardHostname],
		MaskIPs:  privacy.Enabled(db),
	}
	for k, fn := range map[string]func(string) error{
		settingLogForwardHost: validLogForwardHost, settingLogForwardPort: validPort,
		settingLogForwardProtocol: settingValidators[settingLogForwardProtocol],
		settingLogForwardFormat:   settingValidators[settingLogForwardFormat],
		settingLogForwardEvents:   settingValidators[settingLogForwardEvents],
	} {
		if fn(v[k]) != nil {
			c.Enabled = false
		}
	}
	if c.Host == "" {
		c.Enabled = false
	}
	return c
}

// LogForwardHandlers serves the test of the forwarding target.
type LogForwardHandlers struct{ db *sql.DB }

func NewLogForwardHandlers(db *sql.DB) *LogForwardHandlers { return &LogForwardHandlers{db: db} }

func (h *LogForwardHandlers) Register(r chi.Router, authMW func(http.Handler) http.Handler) {
	r.With(authMW).Post("/api/log-forward/test", h.Test)
}

// sendLogForwardTest is logforward.SendTest; a test replaces it.
var sendLogForwardTest = logforward.SendTest

// Test answers POST /api/log-forward/test: one test event to the saved
// target, now, whether forwarding is switched on or not.
func (h *LogForwardHandlers) Test(w http.ResponseWriter, r *http.Request) {
	c := LogForwardConfig(h.db)
	if c.Host == "" || c.Port == 0 || c.Protocol == "" || c.Format == "" {
		writeError(w, http.StatusBadRequest, "save a host, a port, a protocol and a format first")
		return
	}
	err := sendLogForwardTest(r.Context(), c)
	details := map[string]any{"target": c.Addr(), "protocol": c.Protocol, "format": c.Format, "sent": err == nil}
	if err != nil {
		details["error"] = err.Error()
	}
	auditChange(h.db, r, "test_log_forward", c.Addr(), details)
	if err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("the test event did not reach %s over %s: %v", c.Addr(), c.Protocol, err))
		return
	}
	note := "The target accepted the connection and the event."
	if c.Protocol == logforward.ProtoUDP {
		note = "The event left over UDP, which has no answer: check that it arrived on the target."
	}
	writeOK(w, map[string]any{"sent": true, "target": c.Addr(), "protocol": c.Protocol, "format": c.Format, "note": note})
}
