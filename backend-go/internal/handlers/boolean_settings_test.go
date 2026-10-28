package handlers

import (
	"testing"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
)

// Every setting that holds a boolean accepts exactly "true" and "false". The
// readers compare with "true" (the UI's toggles, privacy, the marker files),
// and the WAF reconciler used to accept "1" as well, so a value such as "1"
// stored through the API was on for one reader and off for another.
func TestEveryBooleanSettingAcceptsOnlyTrueOrFalse(t *testing.T) {
	keys := []string{"wizard_completed"}
	for _, kv := range database.DefaultSettings {
		if kv[1] == "true" || kv[1] == "false" {
			keys = append(keys, kv[0])
		}
	}
	if len(keys) < 20 {
		t.Fatalf("found %d boolean settings, the seed has more than 20: is DefaultSettings complete?", len(keys))
	}
	for _, k := range keys {
		for _, ok := range []string{"true", "false"} {
			if err := validateSettingValue(k, ok); err != nil {
				t.Errorf("%s=%q refused: %v", k, ok, err)
			}
		}
		for _, bad := range []string{"1", "0", "yes", "True", "on", ""} {
			if validateSettingValue(k, bad) == nil {
				t.Errorf("%s=%q accepted; a boolean setting takes only true or false", k, bad)
			}
		}
	}
}
