package listentry

import (
	"bufio"
	"os"
	"sort"
	"testing"
)

// TestCompareFeeds reads two feed files with Parse and reports how many
// names each gives and the names only one gives: the check that two
// formats of one list (adblock and plain) import the same entries. It needs
// LISTENTRY_A and LISTENTRY_B; without them it is skipped.
func TestCompareFeeds(t *testing.T) {
	a, b := os.Getenv("LISTENTRY_A"), os.Getenv("LISTENTRY_B")
	if a == "" || b == "" {
		t.Skip("LISTENTRY_A and LISTENTRY_B not set")
	}
	read := func(path string) (map[string]bool, map[Verdict]int) {
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		names, verdicts := map[string]bool{}, map[Verdict]int{}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			e, v := Parse(sc.Text(), Domain)
			verdicts[v]++
			if v == Accepted {
				names[e] = true
			}
		}
		if err := sc.Err(); err != nil {
			t.Fatal(err)
		}
		return names, verdicts
	}
	na, va := read(a)
	nb, vb := read(b)
	only := func(x, y map[string]bool) []string {
		var out []string
		for n := range x {
			if !y[n] {
				out = append(out, n)
			}
		}
		sort.Strings(out)
		return out
	}
	oa, ob := only(na, nb), only(nb, na)
	t.Logf("A %s: %d names, ignored %d, accepted %d, invalid %d", a, len(na), va[Ignored], va[Accepted], va[Invalid])
	t.Logf("B %s: %d names, ignored %d, accepted %d, invalid %d", b, len(nb), vb[Ignored], vb[Accepted], vb[Invalid])
	t.Logf("only in A: %d %v", len(oa), first(oa, 10))
	t.Logf("only in B: %d %v", len(ob), first(ob, 10))
}

func first(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
