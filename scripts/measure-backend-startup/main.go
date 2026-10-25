// Command measure is the helper of scripts/measure-backend-startup.sh.
//
//	measure sample <cgroup-root> <container-id> <interval-ms>
//	    Waits for the container's cgroup, then prints one CSV row per
//	    interval until the cgroup is gone: the cgroup v2 counters of the
//	    container and /proc/<pid>/status of its first process. It runs in a
//	    container of its own, so its memory is not the backend's.
//
//	measure report <run-dir>...
//	    Reads <run-dir>/t0, log (docker logs -t) and samples.csv, and prints
//	    each start-up step ("startup step" log lines, and the background
//	    integrity check) with its duration and the peak memory sampled
//	    while it ran.
package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "sample":
		if len(os.Args) != 5 {
			usage()
		}
		ms, err := strconv.Atoi(os.Args[4])
		if err != nil || ms <= 0 {
			usage()
		}
		sample(os.Args[2], os.Args[3], time.Duration(ms)*time.Millisecond)
	case "report":
		if len(os.Args) < 3 {
			usage()
		}
		for _, d := range os.Args[2:] {
			if err := report(d); err != nil {
				fmt.Fprintf(os.Stderr, "report %s: %v\n", d, err)
				os.Exit(1)
			}
		}
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: measure sample <cgroup-root> <container-id> <interval-ms> | measure report <run-dir>...")
	os.Exit(2)
}

// ---- sample ----

func readInt(p string) int64 {
	b, err := os.ReadFile(p) // #nosec G304 -- cgroup and proc files named by the caller
	if err != nil {
		return -1
	}
	n, _ := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	return n
}

// keyed reads "key value" or "key: value kB" lines and returns the values of keys.
func keyed(p string, keys ...string) map[string]int64 {
	out := map[string]int64{}
	f, err := os.Open(p) // #nosec G304 -- cgroup and proc files named by the caller
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fs := strings.Fields(strings.ReplaceAll(sc.Text(), ":", " "))
		if len(fs) < 2 {
			continue
		}
		for _, k := range keys {
			if fs[0] == k {
				out[k], _ = strconv.ParseInt(fs[1], 10, 64)
			}
		}
	}
	return out
}

func firstPid(cg string) string {
	b, _ := os.ReadFile(filepath.Join(cg, "cgroup.procs")) // #nosec G304 -- cgroup file
	if f := strings.Fields(string(b)); len(f) > 0 {
		return f[0]
	}
	return ""
}

func sample(root, id string, every time.Duration) {
	cg := filepath.Join(root, "docker", id)
	for {
		if _, err := os.Stat(cg); err == nil {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	pid := ""
	for pid == "" {
		if pid = firstPid(cg); pid == "" {
			time.Sleep(2 * time.Millisecond)
		}
	}
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	fmt.Fprintln(w, "unix_ms,cg_current,cg_peak,cg_anon,cg_file,cg_shmem,rss_kb,rss_anon_kb,rss_file_kb,hwm_kb,oom_kill,pid,swap")
	for {
		st := keyed("/proc/"+pid+"/status", "VmRSS", "RssAnon", "RssFile", "VmHWM")
		if len(st) == 0 {
			if _, err := os.Stat(cg); err != nil {
				return
			}
			if p := firstPid(cg); p != "" {
				pid = p // the process was replaced
			}
		}
		ms := keyed(filepath.Join(cg, "memory.stat"), "anon", "file", "shmem")
		ev := keyed(filepath.Join(cg, "memory.events"), "oom_kill")
		fmt.Fprintf(w, "%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%s,%d\n", time.Now().UnixMilli(),
			readInt(filepath.Join(cg, "memory.current")), readInt(filepath.Join(cg, "memory.peak")),
			ms["anon"], ms["file"], ms["shmem"], st["VmRSS"], st["RssAnon"], st["RssFile"], st["VmHWM"],
			ev["oom_kill"], pid, readInt(filepath.Join(cg, "memory.swap.current")))
		_ = w.Flush()
		time.Sleep(every)
	}
}

// ---- report ----

const mib = 1 << 20

type step struct {
	name       string
	start, end int64 // unix ms
	took       float64
}

type row map[string]int64

func report(dir string) error {
	t0b, err := os.ReadFile(filepath.Join(dir, "t0")) // #nosec G304 -- run directory of this script
	if err != nil {
		return err
	}
	t0, err := strconv.ParseInt(strings.TrimSpace(string(t0b)), 10, 64)
	if err != nil {
		return err
	}
	steps, ready, err := readSteps(filepath.Join(dir, "log"))
	if err != nil {
		return err
	}
	rows, err := readSamples(filepath.Join(dir, "samples.csv"))
	if err != nil {
		return err
	}
	state, _ := os.ReadFile(filepath.Join(dir, "state")) // #nosec G304 -- run directory of this script
	fmt.Printf("== %s  %s\n", filepath.Base(dir), strings.Join(strings.Fields(string(state)), " "))
	fmt.Printf("%-26s %8s %9s %9s %9s %7s %5s\n", "step", "took_s", "anon_MiB", "rssA_MiB", "cgcur_MiB", "swap", "n")
	first := t0
	if len(steps) > 0 {
		first = steps[0].start
	}
	printPeak(rows, "(before the first step)", float64(first-t0)/1000, t0, first)
	for _, s := range steps {
		printPeak(rows, s.name, s.took/1000, s.start, s.end)
	}
	if ready > 0 {
		fmt.Printf("start to HTTP server: %.1f s\n", float64(ready-t0)/1000)
	} else {
		fmt.Println("start to HTTP server: never reached")
	}
	if len(rows) > 0 {
		last := rows[len(rows)-1]
		a, r, c, sw, _ := peak(rows, 0, 1<<62)
		fmt.Printf("whole run: peak anon %.1f MiB, rss_anon %.1f, cgroup current %.1f, swap %.1f, memory.peak %.1f, oom_kill %d\n",
			a, r, c, sw, float64(last["cg_peak"])/mib, last["oom_kill"])
	}
	return nil
}

func printPeak(rows []row, name string, took float64, a, b int64) {
	an, r, c, sw, n := peak(rows, a, b)
	if n == 0 {
		fmt.Printf("%-26s %8.2f %9s\n", name, took, "(no sample: shorter than the interval)")
		return
	}
	fmt.Printf("%-26s %8.2f %9.1f %9.1f %9.1f %7.1f %5d\n", name, took, an, r, c, sw, n)
}

func peak(rows []row, a, b int64) (anon, rssAnon, cur, swap float64, n int) {
	for _, r := range rows {
		if r["unix_ms"] < a || r["unix_ms"] > b {
			continue
		}
		n++
		anon = maxf(anon, float64(r["cg_anon"])/mib)
		rssAnon = maxf(rssAnon, float64(r["rss_anon_kb"])/1024)
		cur = maxf(cur, float64(r["cg_current"])/mib)
		swap = maxf(swap, float64(r["swap"])/mib)
	}
	return
}

func maxf(a, b float64) float64 {
	if b > a {
		return b
	}
	return a
}

// readSteps reads docker logs -t output: "<RFC3339Nano> <json>".
func readSteps(path string) (steps []step, ready int64, err error) {
	f, err := os.Open(path) // #nosec G304 -- run directory of this script
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		stamp, rest, ok := strings.Cut(sc.Text(), " ")
		if !ok {
			continue
		}
		t, err := time.Parse(time.RFC3339Nano, stamp)
		if err != nil {
			continue
		}
		var j struct {
			Message string  `json:"message"`
			Step    string  `json:"step"`
			Took    float64 `json:"took"`
		}
		if json.Unmarshal([]byte(rest), &j) != nil {
			continue
		}
		end := t.UnixMilli()
		switch {
		case j.Message == "startup step":
			steps = append(steps, step{j.Step, end - int64(j.Took), end, j.Took})
		case j.Message == "database integrity check passed" || strings.HasPrefix(j.Message, "DATABASE INTEGRITY CHECK FAILED"):
			steps = append(steps, step{"integrity_check (worker)", end - int64(j.Took), end, j.Took})
		case j.Message == "HTTP server starting":
			ready = end
		}
	}
	return steps, ready, sc.Err()
}

func readSamples(path string) ([]row, error) {
	f, err := os.Open(path) // #nosec G304 -- run directory of this script
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	recs, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(recs) == 0 {
		return nil, nil
	}
	head := recs[0]
	var rows []row
	for _, rec := range recs[1:] {
		if len(rec) != len(head) {
			continue
		}
		m := row{}
		for i, k := range head {
			m[k], _ = strconv.ParseInt(rec[i], 10, 64)
		}
		rows = append(rows, m)
	}
	return rows, nil
}
