package agent

import (
	"context"
	"math"
	"testing"

	"github.com/T-Matrix/mmwx-guard/internal/firewall"
	"github.com/T-Matrix/mmwx-guard/internal/model"
)

func TestAdaptiveControllerRequiresSustainedPressureAndRecovery(t *testing.T) {
	manager := firewall.NewManager(t.TempDir(), true)
	policy := model.DefaultPolicy()
	policy.Adaptive.Enabled = true
	if err := manager.Apply(context.Background(), policy); err != nil {
		t.Fatal(err)
	}
	controller := newAdaptiveController(manager)
	high := model.Telemetry{Sockets: model.SocketStats{Total: policy.Adaptive.TriggerConnections}}
	transition, err := controller.Observe(context.Background(), &high)
	if err != nil || transition != "" || high.Adaptive.Emergency {
		t.Fatalf("first pressure sample = %q, %#v, %v", transition, high.Adaptive, err)
	}
	transition, err = controller.Observe(context.Background(), &high)
	if err != nil || transition != "activated" || !high.Adaptive.Emergency || !high.Adaptive.Enabled {
		t.Fatalf("second pressure sample = %q, %#v, %v", transition, high.Adaptive, err)
	}

	low := model.Telemetry{}
	for index := 0; index < adaptiveRecoverSamples-1; index++ {
		transition, err = controller.Observe(context.Background(), &low)
		if err != nil || transition != "" || !low.Adaptive.Emergency {
			t.Fatalf("recovery sample %d = %q, %#v, %v", index, transition, low.Adaptive, err)
		}
	}
	transition, err = controller.Observe(context.Background(), &low)
	if err != nil || transition != "recovered" || low.Adaptive.Emergency {
		t.Fatalf("final recovery sample = %q, %#v, %v", transition, low.Adaptive, err)
	}
}

func TestAdaptivePressureReasonsAndHysteresis(t *testing.T) {
	rule := model.DefaultPolicy().Adaptive
	if reason, high := adaptivePressure(rule, model.Telemetry{Conntrack: 700, ConntrackMax: 1000}); !high || reason != "Conntrack 70%" {
		t.Fatalf("conntrack pressure = %q, %v", reason, high)
	}
	if reason, high := adaptivePressure(rule, model.Telemetry{Sockets: model.SocketStats{SynRecv: rule.TriggerSYN}}); !high || reason != "SYN 堆积 400" {
		t.Fatalf("SYN pressure = %q, %v", reason, high)
	}
	if adaptiveRecovered(rule, model.Telemetry{Sockets: model.SocketStats{Total: rule.RecoverConnections + 1}}) {
		t.Fatal("connection count above recovery threshold was treated as recovered")
	}
	if reason, high := adaptivePressure(rule, model.Telemetry{Conntrack: math.MaxUint64, ConntrackMax: math.MaxUint64}); !high || reason != "Conntrack 100%" {
		t.Fatalf("maximum conntrack pressure = %q, %v", reason, high)
	}
}

func TestAdaptiveEmergencyStateSurvivesManagerRestart(t *testing.T) {
	stateDir := t.TempDir()
	manager := firewall.NewManager(stateDir, true)
	policy := model.DefaultPolicy()
	policy.Adaptive.Enabled = true
	if err := manager.Apply(context.Background(), policy); err != nil {
		t.Fatal(err)
	}
	if err := manager.SetAdaptiveEmergency(context.Background(), policy, true, "连接压力测试"); err != nil {
		t.Fatal(err)
	}
	restarted := firewall.NewManager(stateDir, true)
	status := restarted.AdaptiveStatus()
	if !status.Emergency || status.Reason != "连接压力测试" || status.Since == "" {
		t.Fatalf("restarted adaptive status = %#v", status)
	}
	if err := restarted.SetAdaptiveEmergency(context.Background(), policy, false, ""); err != nil {
		t.Fatal(err)
	}
	if firewall.NewManager(stateDir, true).AdaptiveStatus().Emergency {
		t.Fatal("recovered adaptive state returned after restart")
	}
}
