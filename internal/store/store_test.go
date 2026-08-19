package store

import (
	"context"
	"path/filepath"
	"testing"
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
