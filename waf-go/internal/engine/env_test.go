package engine

import (
	"bytes"
	"log"
	"os"
	"strings"
	"testing"
)

func TestEnvHelpersLogWhatTheyReject(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	t.Setenv("T_INT", "5o")
	t.Setenv("T_FLOAT", "abc")
	t.Setenv("T_BOOL", "maybe")
	if got := envInt("T_INT", 9); got != 9 {
		t.Errorf("envInt = %d", got)
	}
	if got := envFloat("T_FLOAT", 7.5); got != 7.5 {
		t.Errorf("envFloat = %v", got)
	}
	if got := envBool("T_BOOL", true); !got {
		t.Error("envBool changed the default")
	}
	for _, name := range []string{"T_INT", "T_FLOAT", "T_BOOL"} {
		if !strings.Contains(buf.String(), name) {
			t.Errorf("no log line names %s: %q", name, buf.String())
		}
	}
}

// "TRUE" and "on" used to read as false, silently turning a protection off.
func TestEnvBoolIsCaseInsensitiveAndUnderstandsOnOff(t *testing.T) {
	for v, want := range map[string]bool{"1": true, "TRUE": true, "Yes": true, "on": true, "0": false, "False": false, "OFF": false, "no": false} {
		t.Setenv("T_B", v)
		if got := envBool("T_B", !want); got != want {
			t.Errorf("envBool(%q) = %v, want %v", v, got, want)
		}
	}
}
