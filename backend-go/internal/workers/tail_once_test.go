package workers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The Squid and dnsmasq tailers share tailOnce, so one set of tests covers the
// offset rules for both: resume exactly after a capped batch, retry (not skip)
// when the insert fails, reset on rotation, and do nothing when nothing is new.

func lineSpec(max int, seen *int) tailSpec {
	return tailSpec{
		name: "test tailer",
		parse: func(line string) map[string]any {
			return map[string]any{"timestamp": "2026-01-01 00:00:00", "destination": line, "blocked": 0}
		},
		maxLines: max,
		onEntry:  func(map[string]any) { *seen++ },
	}
}

func TestTailOnceResumesExactlyAfterACappedBatch(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	path := filepath.Join(t.TempDir(), "access.log")
	if err := os.WriteFile(path, []byte(strings.Join([]string{"a", "b", "c", "d", "e"}, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	seen := 0
	spec := lineSpec(2, &seen)

	off, persist := tailOnce(db, nil, path, 0, spec)
	if !persist || off != 4 { // "a\nb\n"
		t.Fatalf("first tick: offset %d persist %v; want 4, true", off, persist)
	}
	off, persist = tailOnce(db, nil, path, off, spec)
	if !persist || off != 8 { // "c\nd\n"
		t.Fatalf("second tick: offset %d persist %v; want 8, true", off, persist)
	}
	off, persist = tailOnce(db, nil, path, off, spec)
	if !persist || off != 10 {
		t.Fatalf("third tick: offset %d persist %v; want 10, true", off, persist)
	}
	if _, persist = tailOnce(db, nil, path, off, spec); persist {
		t.Error("a tick with nothing new claimed progress")
	}

	var n int
	_ = db.QueryRow("SELECT COUNT(*) FROM proxy_logs").Scan(&n)
	if n != 5 || seen != 5 {
		t.Errorf("stored %d rows, saw %d entries; want 5 each, none skipped or repeated", n, seen)
	}
}

func TestTailOnceDoesNotAdvanceWhenTheInsertFails(t *testing.T) {
	db, cleanup := setupTestDB(t)
	path := filepath.Join(t.TempDir(), "access.log")
	_ = os.WriteFile(path, []byte("a\nb\n"), 0o644)
	seen := 0
	cleanup() // closes the database: every insert fails

	off, persist := tailOnce(db, nil, path, 0, lineSpec(10, &seen))
	if persist || off != 0 {
		t.Errorf("offset %d persist %v after a failed insert; want 0, false (retry, do not skip)", off, persist)
	}
}

func TestTailOnceResetsOnRotation(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	path := filepath.Join(t.TempDir(), "access.log")
	_ = os.WriteFile(path, []byte("x\n"), 0o644) // shorter than the saved offset
	seen := 0

	off, persist := tailOnce(db, nil, path, 500, lineSpec(10, &seen))
	if !persist || off != 2 || seen != 1 {
		t.Errorf("after rotation: offset %d persist %v seen %d; want 2, true, 1", off, persist, seen)
	}
}
