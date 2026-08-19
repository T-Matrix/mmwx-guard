package telemetry

import (
	"math"
	"testing"
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
