package metrics

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// SECURE-OBS-02. The shipped alert rules are only worth what their metric names
// and label values are worth: an alert on spm_notifications_total{outcome="failed"}
// never fires, because the code emits "failure". That is the same decorative-gate
// failure the rules exist to prevent, so the agreement is checked rather than
// assumed.
//
// This asserts that every spm_* metric name and every label VALUE the rules
// match on appears in the metrics package. It does not evaluate PromQL —
// promtool does that in CI.
func TestAlertRulesReferenceMetricsThatExist(t *testing.T) {
	rules, err := os.ReadFile(filepath.Join("..", "..", "..", "infra", "prometheus", "rules", "spm.rules.yml"))
	if err != nil {
		t.Skipf("rules file not reachable from here: %v", err)
	}
	src, err := os.ReadFile("metrics.go")
	if err != nil {
		t.Fatalf("read metrics.go: %v", err)
	}
	code := string(src)

	names := regexp.MustCompile(`spm_[a-z_]+`).FindAllString(string(rules), -1)
	seen := map[string]bool{}
	for _, n := range names {
		if seen[n] {
			continue
		}
		seen[n] = true
		if !strings.Contains(code, `"`+n+`"`) {
			t.Errorf("alert rules reference %s, which is not declared in metrics.go", n)
		}
	}
	if len(seen) == 0 {
		t.Fatal("no spm_ metric names found in the rules — the file was not read")
	}
	t.Logf("%d distinct metric names checked", len(seen))

	// Label values matched with = must be values the code actually emits,
	// otherwise the alert is silently inert.
	for _, m := range regexp.MustCompile(`(\w+)\s*=\s*"([^"]+)"`).FindAllStringSubmatch(string(rules), -1) {
		label, value := m[1], m[2]
		if label != "outcome" && label != "worker" && label != "channel" {
			continue
		}
		if !strings.Contains(code, `"`+value+`"`) {
			t.Errorf("alert rules match %s=%q, a value metrics.go never emits", label, value)
		}
	}
}
