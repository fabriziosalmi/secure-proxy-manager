package database

import (
	"os"
	"path/filepath"
	"testing"
)

// TestExportWritesTheListsAsBefore pins the bytes of the files the export
// writes, now that it streams rows instead of collecting them: order, the
// whitelist exclusions, the "*." trim of the hosts file and the skipping of
// values that would split a line.
func TestExportWritesTheListsAsBefore(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(filepath.Join(dir, "spm.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := Init(db, "admin", "hash"); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		"INSERT INTO domain_blacklist(domain) VALUES ('zz.example'), ('*.ads.example'), ('aa.example'), ('kept.example'), ('bad\nline.example')",
		"INSERT INTO domain_whitelist(domain, type) VALUES ('kept.example', 'fqdn')",
		"INSERT INTO ip_blacklist(ip) VALUES ('10.0.0.2'), ('10.0.0.1/32'), ('bad ip')",
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	cfg := filepath.Join(dir, "config")
	if err := ExportBlacklistsToFiles(db, cfg); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"domain_blacklist.txt":      "*.ads.example\naa.example\nzz.example\n",
		"dnsmasq.d/blocklist.hosts": "0.0.0.0 ads.example\n:: ads.example\n0.0.0.0 aa.example\n:: aa.example\n0.0.0.0 zz.example\n:: zz.example\n",
		"ip_blacklist.txt":          "10.0.0.1/32\n10.0.0.2\n",
		"ip_whitelist.txt":          "",
		"dst_allow_domain.txt":      "",
	}
	for name, w := range want {
		got, err := os.ReadFile(filepath.Join(cfg, name))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if string(got) != w {
			t.Errorf("%s:\n got %q\nwant %q", name, got, w)
		}
	}
}

// TestStreamListKeepsThePreviousFileWhenARowFails: a query that fails part
// way through its rows must not publish the rows read so far. Collecting the
// rows ignored rows.Err, so a failure mid-scan wrote a short list.
func TestStreamListKeepsThePreviousFileWhenARowFails(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(filepath.Join(dir, "spm.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	path := filepath.Join(dir, "list.txt")
	if err := os.WriteFile(path, []byte("previous\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// json('x') raises "malformed JSON" when the third row is stepped.
	q := "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 5) " +
		"SELECT CASE WHEN i < 3 THEN 'row' || i ELSE json('x') END FROM n"
	if err := exportLines(db, path, q); err == nil {
		t.Fatal("the export reported success for a query that failed part way")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "previous\n" {
		t.Errorf("the previous file was replaced by %q", got)
	}
}

// TestEveryPooledConnectionGetsTheBoundedCache: the page cache is set per
// connection in the DSN, so every connection of the pool must report it. A
// cache set once with Exec reached one connection out of four (SECURE-PERF-02).
func TestEveryPooledConnectionGetsTheBoundedCache(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "spm.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := t.Context()
	for i := 0; i < 4; i++ {
		conn, err := db.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		var size int
		if err := conn.QueryRowContext(ctx, "PRAGMA cache_size").Scan(&size); err != nil {
			t.Fatal(err)
		}
		if size != -PageCacheKiB {
			t.Errorf("connection %d: cache_size %d, want %d", i, size, -PageCacheKiB)
		}
	}
}
