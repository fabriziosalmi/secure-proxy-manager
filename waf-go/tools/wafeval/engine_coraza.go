package main

import (
	"net/http"
	"strconv"

	"secure-proxy-waf/internal/crs"
	"secure-proxy-waf/internal/engine"
	"secure-proxy-waf/internal/inspect"
)

// corazaEngine is the WAF's CRS half (internal/crs) on its own: Coraza with
// the OWASP Core Rule Set, configured as it sits behind this proxy's ICAP.
// It is measured against the spm engine on the same corpora; the
// directives and their reasons are in internal/crs.
type corazaEngine struct {
	crs *crs.Engine
}

// crsOptions are the ablation flags -crs-keep-policy and -crs-restore.
var crsOptions crs.Options

func newCorazaEngine(paranoia int) (*corazaEngine, error) {
	o := crsOptions
	o.Paranoia = paranoia
	e, err := crs.New(o)
	if err != nil {
		return nil, err
	}
	return &corazaEngine{crs: e}, nil
}

func (e *corazaEngine) Name() string { return "coraza-crs-pl" + strconv.Itoa(e.crs.Paranoia()) }

func (e *corazaEngine) Describe() map[string]any {
	return map[string]any{
		"coraza":          "v3.8.1",
		"coreruleset":     "v4.25.0 (coraza-coreruleset module)",
		"paranoia_level":  e.crs.Paranoia(),
		"inbound_anomaly": 5,
		"adjustments":     []string{"CONNECT, PUT, PATCH, DELETE allowed", "origin-form URI with Host", "1 MiB body, inspected partially beyond", "policy rules removed: 920420 920450 920451 920480 943110 943120 930130 932370", "text/plain body: RAW processor, 921110 off", "942100 not on ARGS us_privacy, usp, sst.us_privacy", "ad-tech macros ${NAME}, ${a.b}, [name] neutralized in the URI", "920440 on the egress extension list"},
	}
}

// InspectResponse: CRS's response rules look for the errors and leaks of
// the application a reverse proxy protects (SQL, PHP, Java, IIS); on the
// responses of third-party sites crossing an egress proxy they have no
// target, so this engine does not inspect responses and says so.
func (e *corazaEngine) InspectResponse(resp *http.Response) Verdict {
	return Verdict{NotInspected: true}
}

func (e *corazaEngine) Inspect(r *http.Request, clientIP string, _ *inspect.Hello) Verdict {
	// The production handler lets LAN destinations through uninspected; the
	// comparison keeps that, so both engines see the same requests.
	if engine.IsLANHost(r.Host) {
		return Verdict{LANSkipped: true}
	}
	body, err := readBody(r)
	if err != nil {
		return Verdict{}
	}
	res := e.crs.Inspect(r, body, clientIP, explainOn)
	v := Verdict{Blocked: res.Blocked, Rules: res.Rules, Explain: res.Explain}
	if len(res.Rules) > 0 {
		v.Signals = []string{"CRS"}
	}
	if res.Blocked {
		v.Score = 1
	}
	return v
}
