package workers

import (
	"os"
	"path/filepath"
	"testing"
)

// When the log rotates while the tailer is behind, the lines it had not read
// yet are in the rotated file (access.log.0, Squid's logfile_rotate). The
// tailer used to restart at 0 on the new file and never read them.
func TestRotationDrainsTheUnreadTailOfTheRotatedFile(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	seen := 0
	spec := lineSpec(10, &seen)

	if err := os.WriteFile(path, []byte("a\nb\nc\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	off, _ := tailOnce(db, nil, path, 0, spec) // reads a, b, c
	// Two more lines arrive, then Squid rotates before the next tick.
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	_, _ = f.WriteString("d\ne\n")
	f.Close()
	if err := os.Rename(path, path+".0"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("f\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	off, persist := tailOnce(db, nil, path, off, spec)
	if !persist || off != 2 {
		t.Errorf("after the rotation: offset %d persist %v; want 2 (end of the new file), true", off, persist)
	}
	rows := map[string]int{}
	r, err := db.Query("SELECT destination FROM proxy_logs")
	if err != nil {
		t.Fatal(err)
	}
	for r.Next() {
		var d string
		_ = r.Scan(&d)
		rows[d]++
	}
	r.Close()
	for _, want := range []string{"a", "b", "c", "d", "e", "f"} {
		if rows[want] != 1 {
			t.Errorf("line %q stored %d times, want once (all: %v)", want, rows[want], rows)
		}
	}
}

// No rotated file, or one that is shorter than the saved offset (it is not
// the file the offset belongs to): the tailer starts the new file from 0 as
// before and reads nothing from the other file.
func TestRotationWithoutAMatchingRotatedFileStartsTheNewFile(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	_ = os.WriteFile(path+".0", []byte("old\n"), 0o644) // 4 bytes, offset is 500
	_ = os.WriteFile(path, []byte("x\n"), 0o644)
	seen := 0
	off, persist := tailOnce(db, nil, path, 500, lineSpec(10, &seen))
	if !persist || off != 2 || seen != 1 {
		t.Errorf("offset %d persist %v seen %d; want 2, true, 1 (the short .0 is not drained)", off, persist, seen)
	}
}

// A backlog larger than one batch is read to the end of the rotated file in
// the same tick, batch by batch.
func TestRotationDrainsABacklogLargerThanABatch(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	_ = os.WriteFile(path+".0", []byte("a\nb\nc\nd\ne\nf\ng\n"), 0o644)
	_ = os.WriteFile(path, []byte("h\n"), 0o644)
	seen := 0
	// The saved offset is after "a\nb\n": five unread lines, batches of two.
	// (The new file must be shorter than the offset: rotation is detected by
	// size, so a new file that has already reached the old offset is missed.)
	off, persist := tailOnce(db, nil, path, 4, lineSpec(2, &seen))
	var n int
	_ = db.QueryRow("SELECT COUNT(*) FROM proxy_logs").Scan(&n)
	if !persist || off != 2 || n != 6 {
		t.Errorf("offset %d persist %v rows %d; want 2, true, 6 (c..g from the rotated file, h from the new one)", off, persist, n)
	}
}

// If the rotated file's lines cannot be stored, the offset stays where it was,
// so the next tick reads them again instead of skipping to the new file.
func TestRotationKeepsTheOffsetWhenTheDrainInsertFails(t *testing.T) {
	db, cleanup := setupTestDB(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	_ = os.WriteFile(path+".0", []byte("a\nb\nc\n"), 0o644)
	_ = os.WriteFile(path, []byte("x\n"), 0o644)
	cleanup() // every insert fails
	seen := 0
	if off, persist := tailOnce(db, nil, path, 4, lineSpec(10, &seen)); persist || off != 4 {
		t.Errorf("offset %d persist %v after a failed drain; want 4, false", off, persist)
	}
}
