package telemetry

import (
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/T-Matrix/mmwx-guard/internal/model"
)

func TestParseCPUSample(t *testing.T) {
	sample, ok := parseCPUSample("cpu  100 10 20 800 30 5 6 7 99 88\ncpu0 1 2 3 4\n")
	if !ok {
		t.Fatal("expected valid aggregate CPU sample")
	}
	if sample.idle != 830 {
		t.Fatalf("idle = %d, want 830", sample.idle)
	}
	if sample.total != 978 {
		t.Fatalf("total = %d, want 978", sample.total)
	}
}

func TestCPUUsageBetween(t *testing.T) {
	got := cpuUsageBetween(cpuSample{idle: 800, total: 1000}, cpuSample{idle: 860, total: 1100})
	if math.Abs(got-40) > 0.001 {
		t.Fatalf("cpuUsageBetween() = %.3f, want 40", got)
	}
}

func TestParseCPUSampleRejectsInvalidInput(t *testing.T) {
	for _, input := range []string{"", "cpu0 1 2 3 4", "cpu 1 x 3 4"} {
		if _, ok := parseCPUSample(input); ok {
			t.Fatalf("parseCPUSample(%q) unexpectedly succeeded", input)
		}
	}
}

func TestMachineIDPrefersAgentIdentity(t *testing.T) {
	dir := t.TempDir()
	agentPath := filepath.Join(dir, "agent-id")
	systemPath := filepath.Join(dir, "machine-id")
	if err := os.WriteFile(agentPath, []byte("agent-owned\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(systemPath, []byte("cloned-system\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := machineIDFromFiles([]string{agentPath, systemPath}); got != "agent-owned" {
		t.Fatalf("machineIDFromFiles() = %q", got)
	}
}

func TestParseNetworkCountersExcludesLoopbackAndContainerLinks(t *testing.T) {
	raw := `Inter-|   Receive                                                |  Transmit
 face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed
    lo: 100 1 0 0 0 0 0 0 200 1 0 0 0 0 0 0
  eth0: 1000 1 0 0 0 0 0 0 2000 1 0 0 0 0 0 0
 veth1: 3000 1 0 0 0 0 0 0 4000 1 0 0 0 0 0 0
   wg0: 500 1 0 0 0 0 0 0 700 1 0 0 0 0 0 0`
	receive, transmit := parseNetworkCounters(raw)
	if receive != 1500 || transmit != 2700 {
		t.Fatalf("parseNetworkCounters() = %d/%d, want 1500/2700", receive, transmit)
	}
}

func TestNetworkUsageCalculatesRatesAndHandlesCounterReset(t *testing.T) {
	collector := &Collector{}
	collector.networkMu.Lock()
	collector.lastNetwork = networkSample{receiveBytes: 1000, transmitBytes: 2000, collectedAt: time.Unix(100, 0)}
	collector.hasNetwork = true
	collector.networkMu.Unlock()
	// Test the rate arithmetic without depending on the host's /proc values.
	previous := networkSample{receiveBytes: 1000, transmitBytes: 2000, collectedAt: time.Unix(100, 0)}
	current := networkSample{receiveBytes: 3000, transmitBytes: 5000, collectedAt: time.Unix(102, 0)}
	if got := networkRate(previous.receiveBytes, current.receiveBytes, current.collectedAt.Sub(previous.collectedAt)); got != 1000 {
		t.Fatalf("networkRate(receive) = %d", got)
	}
	if got := networkRate(previous.transmitBytes, current.transmitBytes, current.collectedAt.Sub(previous.collectedAt)); got != 1500 {
		t.Fatalf("networkRate(transmit) = %d", got)
	}
	if got := networkRate(5000, 100, time.Second); got != 0 {
		t.Fatalf("networkRate(reset) = %d", got)
	}
}

func TestParseSocketStatsCountsOnlyInboundListenerConnections(t *testing.T) {
	raw := `LISTEN 0 4096 0.0.0.0:15542 0.0.0.0:*
LISTEN 0 4096 [::]:22 [::]:*
ESTAB 0 0 10.0.0.2:15542 198.51.100.10:41000
ESTAB 0 0 10.0.0.2:51000 156.229.164.222:15542
TIME-WAIT 0 0 10.0.0.2:15542 198.51.100.11:41001
SYN-SENT 0 1 10.0.0.2:51001 45.59.186.47:443`
	stats, sources := parseSocketStats(raw)
	if stats.Total != 2 || stats.Established != 1 || stats.TimeWait != 1 || stats.SynSent != 0 {
		t.Fatalf("parseSocketStats() stats = %#v", stats)
	}
	if len(sources) != 2 || sources[0].IP == "156.229.164.222" || sources[1].IP == "156.229.164.222" {
		t.Fatalf("parseSocketStats() sources = %#v", sources)
	}
}

func TestSourceWeightSaturatesWithoutWrapping(t *testing.T) {
	if got := sourceWeight(model.SourceCount{Connections: 10, Dropped: ^uint64(0) - 5}); got != ^uint64(0) {
		t.Fatalf("sourceWeight() = %d, want saturation", got)
	}
	if got := sourceWeight(model.SourceCount{Connections: -1, Dropped: 9}); got != 9 {
		t.Fatalf("sourceWeight() accepted a negative connection count: %d", got)
	}
}

func TestParseNftSetCountersValidatesTextElements(t *testing.T) {
	raw := []byte(`table inet mmwx_guard {
	set offenders_v4 {
		elements = { 192.0.2.123 counter packets 7 bytes 420,
			2001:db8::8 counter packets 9 bytes 540,
			e counter packets 99 bytes 99 }
	}
}`)
	counters := parseNftSetCounters(raw)
	if len(counters) != 2 || counters["192.0.2.123"] != 7 || counters["2001:db8::8"] != 9 {
		t.Fatalf("parseNftSetCounters() = %#v", counters)
	}
	if counters := parseNftSetCounters([]byte(`elements = { e counter packets 7 bytes 420 }`)); len(counters) != 0 {
		t.Fatalf("invalid address was unexpectedly parsed: %#v", counters)
	}
}

func TestParseNftDropRuleCountersCountsOnlyDropRules(t *testing.T) {
	raw := []byte(`{"nftables":[
		{"set":{"name":"offenders_v4","elem":[{"elem":{"val":"192.0.2.1","counter":{"packets":99,"bytes":5940}}}]}},
		{"rule":{"expr":[{"counter":{"packets":7,"bytes":420}},{"drop":null}]}},
		{"rule":{"expr":[{"counter":{"packets":11,"bytes":660}},{"accept":null}]}},
		{"rule":{"expr":[{"counter":{"packets":13,"bytes":780}},{"drop":null}]}}
	]}`)
	total, err := parseNftDropRuleCounters(raw)
	if err != nil || total != 20 {
		t.Fatalf("parseNftDropRuleCounters() = %d, %v", total, err)
	}
}

func TestCumulativeDropsSurvivesCounterResetAndRestart(t *testing.T) {
	stateDir := t.TempDir()
	collector := NewCollector(nil, stateDir)
	if got := collector.cumulativeDrops(10, true); got != 10 {
		t.Fatalf("first total = %d, want 10", got)
	}
	if got := collector.cumulativeDrops(15, true); got != 15 {
		t.Fatalf("incremented total = %d, want 15", got)
	}
	if got := collector.cumulativeDrops(0, true); got != 15 {
		t.Fatalf("reset total = %d, want 15", got)
	}
	if got := collector.cumulativeDrops(4, true); got != 19 {
		t.Fatalf("post-reset total = %d, want 19", got)
	}
	restarted := NewCollector(nil, stateDir)
	if got := restarted.cumulativeDrops(6, true); got != 21 {
		t.Fatalf("restarted total = %d, want 21", got)
	}
	info, err := os.Stat(filepath.Join(stateDir, dropCounterStateFilename))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("counter state mode = %v, %v", info.Mode().Perm(), err)
	}
}
