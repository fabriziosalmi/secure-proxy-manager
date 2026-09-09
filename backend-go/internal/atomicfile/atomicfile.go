// Package atomicfile writes a file so that a reader — or a crash — never sees
// a partial one.
//
// It exists because the two files whose loss cannot be undone were the only
// persisted state written with a plain os.WriteFile. .enc_key decrypts every
// stored notification credential and .jwt_secret signs every session token;
// os.WriteFile opens with O_CREATE|O_TRUNC and returns once the write is
// buffered, so a kill between the truncate and the flush left a short file. The
// read side then rejects it for failing a length check and GENERATES A NEW KEY,
// silently orphaning everything the old one protected. Meanwhile the log
// tailer's byte offset — a value that costs a re-read of a log file — was
// already written through a temp-and-rename (SECURE-DATA-01).
package atomicfile

import (
	"fmt"
	"os"
	"path/filepath"
)

// Write creates path with the given contents and permissions, atomically.
//
// The temp file is unique per writer rather than path+".tmp": with a fixed
// name, a second writer's O_TRUNC resets the first one's still-open file to
// zero length and whichever renames first publishes a short file. The data is
// fsynced before the rename, and the directory is fsynced after it, so the
// rename itself is durable and not merely ordered.
func Write(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, filepath.Base(path)+".tmp*")
	if err != nil {
		return fmt.Errorf("create temp for %s: %w", path, err)
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }() // no-op once the rename succeeds

	if _, err := f.Write(data); err != nil {
		f.Close() //nolint:errcheck // the write error is the one worth reporting
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := f.Chmod(perm); err != nil {
		f.Close() //nolint:errcheck
		return fmt.Errorf("chmod %s: %w", tmp, err)
	}
	if err := f.Sync(); err != nil {
		f.Close() //nolint:errcheck
		return fmt.Errorf("sync %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename %s -> %s: %w", tmp, path, err)
	}
	// Sync the directory so the rename survives, not just the file contents.
	// #nosec G304 — dir is filepath.Dir of a caller-supplied path, opened
	// read-only and never read; the handle exists only to fsync the directory.
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close() //nolint:errcheck
	}
	return nil
}
