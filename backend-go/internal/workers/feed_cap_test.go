package workers

import (
	"io"
	"strings"
	"testing"
)

// feedCap is the cap the import applies to a blacklist download (32 MB); the
// auto-refresh must apply the same one.
const feedCap = 32 * 1024 * 1024

// feedBody serves head and then comment lines, size bytes in all, without
// holding them in memory, and counts what was read from it.
type feedBody struct {
	head     string
	size     int64
	consumed int64
}

func (f *feedBody) Read(p []byte) (int, error) {
	if f.consumed >= f.size {
		return 0, io.EOF
	}
	if rest := f.size - f.consumed; int64(len(p)) > rest {
		p = p[:rest]
	}
	const pad = "# padding line of a large feed, nothing to read here\n"
	for i := range p {
		at := f.consumed + int64(i)
		if at < int64(len(f.head)) {
			p[i] = f.head[at]
		} else {
			p[i] = pad[(at-int64(len(f.head)))%int64(len(pad))]
		}
	}
	f.consumed += int64(len(p))
	return len(p), nil
}

// A feed of exactly the cap is read whole.
func TestARefreshFeedOfExactlyTheCapIsReadWhole(t *testing.T) {
	body := &feedBody{head: hosts("a.test"), size: feedCap}
	data, err := readRefreshFeed(body)
	if err != nil {
		t.Fatalf("a feed of %d bytes failed: %v", feedCap, err)
	}
	if len(data) != feedCap {
		t.Errorf("read %d bytes, want %d", len(data), feedCap)
	}
}

// A feed above the cap fails with an error that names the cap, and the read
// stops one byte past it: nothing beyond the cap is buffered, and no truncated
// feed is returned as if it were whole.
func TestARefreshFeedAboveTheCapFailsAndIsNotBuffered(t *testing.T) {
	body := &feedBody{head: hosts("a.test"), size: 2 * feedCap}
	data, err := readRefreshFeed(body)
	if err == nil {
		t.Fatalf("a feed of %d bytes was read (%d bytes) with no error; want it refused above %d", body.size, len(data), feedCap)
	}
	if !strings.Contains(err.Error(), "33554432") {
		t.Errorf("error %q does not name the cap (33554432 bytes)", err)
	}
	if data != "" {
		t.Errorf("an oversized feed returned %d bytes; want none", len(data))
	}
	if body.consumed > feedCap+1 {
		t.Errorf("read %d bytes of the feed; want at most cap+1 = %d", body.consumed, feedCap+1)
	}
	if got := fetchFailure(err); !strings.Contains(got, "32 MB") {
		t.Errorf("source note %q does not name the 32 MB cap", got)
	}
}

// A feed that grew past the cap counts as failed: its entries stay, nothing
// of the list is removed in that run, and its source says why. Read whole, the
// part before the cut would have dropped b.test.
func TestAFeedAboveTheCapFailsAndKeepsItsEntries(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	serveFeeds(t, map[string]string{feedA: hosts("a.test", "b.test")})
	syncDomains(db, feedA)

	orig := fetchRefreshFeed
	t.Cleanup(func() { fetchRefreshFeed = orig })
	fetchRefreshFeed = func(u string) (string, error) {
		return readRefreshFeed(&feedBody{head: hosts("a.test"), size: 2 * feedCap})
	}
	c := syncDomains(db, feedA)
	if c.Failed != 1 || c.Removed != 0 || c.Moved != 0 || !c.RemovalDeferred {
		t.Errorf("run = %+v; want the feed failed, nothing removed, removal deferred", c)
	}
	expectListed(t, db, "a.test<-url:"+feedA, "b.test<-url:"+feedA)
	var status, detail string
	_ = db.QueryRow("SELECT refresh_status, refresh_detail FROM list_sources WHERE source = ?", feedA).Scan(&status, &detail)
	if status != "failed" || !strings.Contains(detail, "32 MB") {
		t.Errorf("source note = %q %q; want failed, naming the 32 MB cap", status, detail)
	}
}
