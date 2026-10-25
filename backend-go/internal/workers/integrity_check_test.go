package workers

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/metrics"
)

func integrityOK(t *testing.T) float64 {
	t.Helper()
	w := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	out := w.Body.String()
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "spm_db_integrity_ok ") {
			if strings.HasSuffix(line, " 1") {
				return 1
			}
			return 0
		}
	}
	t.Fatalf("spm_db_integrity_ok not exported:\n%s", out)
	return -1
}

// TestRunIntegrityCheckReportsADamagedDatabase: a file the check cannot pass
// is recorded for readiness and in the metric; a sound one clears both.
func TestRunIntegrityCheckReportsADamagedDatabase(t *testing.T) {
	t.Cleanup(func() { database.RecordIntegrity(nil) })
	bad := filepath.Join(t.TempDir(), "damaged.db")
	if err := os.WriteFile(bad, []byte(strings.Repeat("not a database ", 512)), 0o600); err != nil {
		t.Fatal(err)
	}
	RunIntegrityCheck(context.Background(), bad)
	if database.IntegrityFailure() == "" {
		t.Fatal("a damaged database left readiness untouched")
	}
	if integrityOK(t) != 0 {
		t.Error("spm_db_integrity_ok is not 0 after a failed check")
	}

	db, cleanup := setupTestDB(t)
	defer cleanup()
	var path string
	if err := db.QueryRow("SELECT file FROM pragma_database_list WHERE name = 'main'").Scan(&path); err != nil {
		t.Fatal(err)
	}
	RunIntegrityCheck(context.Background(), path)
	if got := database.IntegrityFailure(); got != "" {
		t.Fatalf("a sound database is reported as damaged: %s", got)
	}
	if integrityOK(t) != 1 {
		t.Error("spm_db_integrity_ok is not 1 after a passing check")
	}
}

// TestRunIntegrityCheckCutShortRecordsNothing: shutdown during the check is
// not an outcome, so it neither marks the database damaged nor clears a
// failure already recorded.
func TestRunIntegrityCheckCutShortRecordsNothing(t *testing.T) {
	t.Cleanup(func() { database.RecordIntegrity(nil) })
	bad := filepath.Join(t.TempDir(), "damaged.db")
	if err := os.WriteFile(bad, []byte(strings.Repeat("not a database ", 512)), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	RunIntegrityCheck(ctx, bad)
	if got := database.IntegrityFailure(); got != "" {
		t.Errorf("a cancelled check was recorded: %s", got)
	}
}
