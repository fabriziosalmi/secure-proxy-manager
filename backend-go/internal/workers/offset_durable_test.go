package workers

import (
	"os"
	"path/filepath"
	"testing"
)

// The read offset is written through atomicfile (unique temp, fsync, rename,
// directory fsync). It used to be os.WriteFile to a fixed path+".tmp" and a
// rename with no fsync, so after a power loss the .pos could be present and
// empty, read back as 0, and the whole log re-ingested as duplicate rows. The
// fsync cannot be observed here; the fixed temp name can: anything left at it
// made every offset write fail.
func TestOffsetIsPersistedDespiteAStaleTempName(t *testing.T) {
	dir := t.TempDir()
	pos := filepath.Join(dir, "access.log.pos")
	if err := os.Mkdir(pos+".tmp", 0o700); err != nil {
		t.Fatal(err)
	}
	writeOffset(pos, 123456)
	if got := readOffset(pos); got != 123456 {
		t.Errorf("offset read back as %d, want 123456: it was not persisted", got)
	}
}
