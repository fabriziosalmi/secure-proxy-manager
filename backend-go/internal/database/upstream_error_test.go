package database

import (
	"strings"
	"testing"
)

// The index statement is one literal and the query condition another: the
// index's WHERE must end with the condition, word for word, or SQLite cannot
// match the query to the partial index.
func TestUpstreamErrorIndexIsItsCondition(t *testing.T) {
	if !strings.Contains(UpstreamErrorIndex, " WHERE blocked != 1 AND ") || !strings.HasSuffix(UpstreamErrorIndex, string(UpstreamErrorCond)) {
		t.Errorf("UpstreamErrorIndex %q does not end with WHERE blocked != 1 AND %q", UpstreamErrorIndex, UpstreamErrorCond)
	}
}
