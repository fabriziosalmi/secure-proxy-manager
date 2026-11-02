package inspect

import (
	"bufio"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

// TestJA4MatchesWireshark checks JA4 against an independent implementation:
// each hello in testdata/ja4_tshark.txt was sent by a real client, and its
// expected value is the one Wireshark computed for it.
func TestJA4MatchesWireshark(t *testing.T) {
	f, err := os.Open("testdata/ja4_tshark.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	n := 0
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			t.Fatalf("malformed line: %.60s", line)
		}
		name, want := fields[0], fields[1]
		hello, err := hex.DecodeString(fields[2])
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got, err := JA4(hello)
		if err != nil {
			t.Errorf("%s: %v", name, err)
		} else if got != want {
			t.Errorf("%s: JA4 %s, Wireshark %s", name, got, want)
		}
		n++
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if n < 18 {
		t.Fatalf("read %d hellos, want at least 18", n)
	}
}
