package engine

import (
	"strings"
	"testing"
)

// The template injection rules catch an expression inside template
// delimiters, in every shape the attack corpus has, and leave placeholders
// (a bare name or a dotted path) alone, as ad-tech URLs and pasted
// configuration carry them.
func TestTemplateInjection(t *testing.T) {
	e := New(Config{BlockThreshold: 10})
	for _, attack := range []string{
		"q={{x*45}}", "q={{60*'94'}}", "q={%set x=76%}{{x*2}}", "q={%SeT x=1%}", "q=${32*24}", "q=${{39*92}",
		"q=#{53*35}", "q=*{16*34}", "q=@(86*22)", "q=<%= 53*47 %>",
		"q={{''.__class__.__mro__[2].__subclasses__()[249]}}",
		"q={{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
		"q=${T(java.lang.Runtime).getRuntime().exec('ls')}", "q=#{T(java.lang.System).getenv('PATH')}",
		"q={{config.items()}}",
	} {
		ms, score := e.MatchRulesScored(NormalizeInput(attack))
		if score < 10 || !hasCategory(ms, "TEMPLATE_INJECTION") {
			t.Errorf("%q: score %d, %v", attack, score, ids(ms))
		}
	}
	for _, benign := range []string{
		"us_privacy={{US_PRIVACY}}&u=${PUBMATIC_UID}", "xuid=${CRITEO_USER_ID}", "euid={{oui}}",
		`api_key = "{{ secrets.AWS_SECRET }}"`, "api_key: {{ .Values.api_key }}", "SECRET_KEY=${SECRET_KEY}",
		"<%= schema.route_helper %>", `{"cookieEnabled":1,"userAgent":"Mozilla"}`, "*{margin:0;padding:0}",
		"#{$i} in a sass loop", "mail me at name@(work)", "{% endif %}",
		`application/json,text/plain,*/*{"brand":"wix","BSI":"a06ba548-b988-438a-bad8-b19d3d9658c9|1"}`,
	} {
		if ms, _ := e.MatchRulesScored(NormalizeInput(benign)); hasCategory(ms, "TEMPLATE_INJECTION") {
			t.Errorf("benign %q: %v", benign, ids(ms))
		}
	}
}

func hasCategory(ms []MatchResult, cat string) bool {
	for _, m := range ms {
		if m.Category == cat {
			return true
		}
	}
	return false
}

func ids(ms []MatchResult) string {
	var out []string
	for _, m := range ms {
		out = append(out, m.RuleID)
	}
	return strings.Join(out, ",")
}
