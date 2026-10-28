package atomicfile

import (
	"os"
	"path/filepath"
	"testing"
)

// Write publishes the whole content under the final name with the requested
// permissions, replaces an existing file, and leaves no temporary file behind.
// (That the data is fsynced before the rename cannot be observed from a test;
// it is the reason the package exists, see the package comment.)
func TestWriteReplacesAtomicallyAndCleansUp(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "key")
	for _, content := range []string{"first", "second, longer than the first"} {
		if err := Write(p, []byte(content), 0o600); err != nil {
			t.Fatalf("Write %q: %v", content, err)
		}
		got, err := os.ReadFile(p)
		if err != nil || string(got) != content {
			t.Fatalf("read back %q, %v; want %q", got, err, content)
		}
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, want 0600", fi.Mode().Perm())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		names := []string{}
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("directory holds %v, want only the target file", names)
	}
}

// A leftover at the old fixed temporary name (path + ".tmp") cannot block a
// write: the temporary file is unique per writer.
func TestWriteIgnoresAStaleFixedTempName(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "state")
	if err := os.Mkdir(p+".tmp", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := Write(p, []byte("ok"), 0o600); err != nil {
		t.Fatalf("Write with a stale %s.tmp present: %v", p, err)
	}
}
