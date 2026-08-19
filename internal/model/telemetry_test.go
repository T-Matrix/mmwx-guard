package model

import (
	"math"
	"testing"
	"time"
)

func validTelemetry(now time.Time) Telemetry {
	return Telemetry{
		CollectedAt: now.Format(time.RFC3339Nano), CPUUsage: 12.5, Load1: 1.2, Load5: 1.1,
		MemoryUsed: 512, MemoryTotal: 1024, Sockets: SocketStats{Total: 20, Established: 8, TimeWait: 10},
		Conntrack: 20, ConntrackMax: 1024, TopSources: []SourceCount{{IP: "203.0.113.8", Connections: 4}},
	}
}

func TestTelemetryValidate(t *testing.T) {
	now := time.Date(2026, 8, 19, 0, 0, 0, 0, time.UTC)
	if err := validTelemetry(now).Validate(now); err != nil {
		t.Fatalf("valid telemetry rejected: %v", err)
	}
	tests := []struct {
		name string
		edit func(*Telemetry)
	}{
		{"nan cpu", func(value *Telemetry) { value.CPUUsage = math.NaN() }},
		{"negative sockets", func(value *Telemetry) { value.Sockets.Total = -1 }},
		{"state exceeds total", func(value *Telemetry) { value.Sockets.Established = 21 }},
		{"invalid source", func(value *Telemetry) { value.TopSources[0].IP = "not-an-ip" }},
		{"stale collection", func(value *Telemetry) { value.CollectedAt = now.Add(-6 * time.Minute).Format(time.RFC3339Nano) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := validTelemetry(now)
			test.edit(&value)
			if err := value.Validate(now); err == nil {
				t.Fatal("invalid telemetry accepted")
			}
		})
	}
}

func TestTelemetryValidateRejectsOversizedIntegrations(t *testing.T) {
	now := time.Now()
	value := validTelemetry(now)
	value.Integrations.MMW = &MMWIntegration{Nodes: make([]MMWNodeListener, MaxMMWNodes+1)}
	if err := value.Validate(now); err == nil {
		t.Fatal("oversized integration accepted")
	}
}
