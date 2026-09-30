package engine

import (
	"testing"
	"time"
)

// CheckRequestHeuristics is now a composition of one small function per
// heuristic; these pin each one's trigger and its "off" switch.

func TestHeuristicEntropyThresholdsAndSwitch(t *testing.T) {
	on := HeuristicConfig{EntropyThreshold: true, EntropyMax: 7.5}
	if got := heuristicEntropy(on, 7.9, 0, 1000); len(got) != 1 || got[0].ID != "H1-ENTROPY" {
		t.Errorf("high body entropy = %v", got)
	}
	if got := heuristicEntropy(on, 7.9, 0, 200); len(got) != 0 {
		t.Errorf("a body under 256 bytes must not count: %v", got)
	}
	if got := heuristicEntropy(on, 0, 7.9, 0); len(got) != 1 || got[0].ID != "H1-URL-ENTROPY" {
		t.Errorf("high URL entropy = %v", got)
	}
	if got := heuristicEntropy(on, 7.9, 7.9, 1000); len(got) != 2 {
		t.Errorf("both = %v", got)
	}
	if got := heuristicEntropy(HeuristicConfig{EntropyMax: 7.5}, 7.9, 7.9, 1000); got != nil {
		t.Errorf("disabled heuristic fired: %v", got)
	}
}

func TestHeuristicShardingGhostingSequenceSwitches(t *testing.T) {
	if got := heuristicSharding(HeuristicConfig{DestinationSharding: true, ShardingMaxDests: 50}, 51); len(got) != 1 {
		t.Errorf("51 destinations over a max of 50 = %v", got)
	}
	if got := heuristicSharding(HeuristicConfig{DestinationSharding: true, ShardingMaxDests: 50}, 50); got != nil {
		t.Errorf("exactly at the max fired: %v", got)
	}
	if got := heuristicSharding(HeuristicConfig{ShardingMaxDests: 1}, 99); got != nil {
		t.Errorf("disabled sharding fired: %v", got)
	}
	if got := heuristicGhosting(HeuristicConfig{}, "SSH-2.0-OpenSSH_9.0"); got != nil {
		t.Errorf("disabled ghosting fired: %v", got)
	}
	if got := heuristicSequence(HeuristicConfig{}, clientSnapshot{prevMethod: "GET", prevPath: "/"}, "POST", "/x"); got != nil {
		t.Errorf("disabled sequence fired: %v", got)
	}
}

func TestRecordBeaconingTrimsToTheWindowAndCaps(t *testing.T) {
	now := time.Now()
	cs := &clientState{}
	cfg := HeuristicConfig{BeaconingDetection: true, BeaconingWindow: 300}
	cs.reqTimes = []time.Time{now.Add(-10 * time.Minute), now.Add(-1 * time.Minute)}
	cs.reqSizes = []int{1, 2}

	times, sizes := recordBeaconing(cs, cfg, now, 3)
	if len(times) != 2 || sizes[0] != 2 || sizes[1] != 3 {
		t.Errorf("history after trimming = %v %v; want the in-window entry and this request", times, sizes)
	}

	cs.reqTimes, cs.reqSizes = nil, nil
	for i := 0; i < maxBeaconHistory+50; i++ {
		recordBeaconing(cs, cfg, now.Add(time.Duration(i)*time.Millisecond), i)
	}
	if len(cs.reqTimes) != maxBeaconHistory {
		t.Errorf("history grew to %d, want the cap of %d", len(cs.reqTimes), maxBeaconHistory)
	}
}

func TestRecordDestinationForgetsStaleOnes(t *testing.T) {
	now := time.Now()
	cs := &clientState{dests: map[string]time.Time{"old.test": now.Add(-2 * time.Minute), "recent.test": now.Add(-10 * time.Second)}}
	if n := recordDestination(cs, "new.test", now); n != 2 {
		t.Errorf("destinations in the window = %d, want 2 (recent + new)", n)
	}
	if _, ok := cs.dests["old.test"]; ok {
		t.Error("a destination older than 60s was kept")
	}
}
