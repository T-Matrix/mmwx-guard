package store

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/T-Matrix/mmwx-guard/internal/model"
)

func TestRenameAgent(t *testing.T) {
	storage, err := Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	ctx := context.Background()
	if err := storage.CreateAgent(ctx, NewAgent{ID: "agent-1", Name: "旧名称", MachineID: "machine-1", SecretHash: "hash"}); err != nil {
		t.Fatal(err)
	}
	if err := storage.RenameAgent(ctx, "agent-1", "新名称"); err != nil {
		t.Fatal(err)
	}
	agents, err := storage.ListAgents(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(agents) != 1 || agents[0].Name != "新名称" {
		t.Fatalf("agents = %#v, want renamed agent", agents)
	}
}

func TestSummarySeparatesEstablishedAndTimeWait(t *testing.T) {
	storage, err := Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	ctx := context.Background()
	if err := storage.CreateAgent(ctx, NewAgent{ID: "agent-1", Name: "first", MachineID: "machine-1", SecretHash: "hash-1"}); err != nil {
		t.Fatal(err)
	}
	if err := storage.CreateAgent(ctx, NewAgent{ID: "agent-2", Name: "second", MachineID: "machine-2", SecretHash: "hash-2"}); err != nil {
		t.Fatal(err)
	}
	if err := storage.UpdateTelemetry(ctx, "agent-1", model.Telemetry{Sockets: model.SocketStats{Total: 120, Established: 40, TimeWait: 70}}); err != nil {
		t.Fatal(err)
	}
	if err := storage.UpdateTelemetry(ctx, "agent-2", model.Telemetry{Sockets: model.SocketStats{Total: 80, Established: 25, TimeWait: 45}}); err != nil {
		t.Fatal(err)
	}
	summary, err := storage.Summary(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if summary["sockets"] != 200 || summary["established"] != 65 || summary["time_wait"] != 115 {
		t.Fatalf("summary = %#v", summary)
	}
}
