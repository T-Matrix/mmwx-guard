package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/T-Matrix/mmwx-guard/internal/model"
)

func TestRollbackRestoresPolicyMetadataAndValidatesRuntimeState(t *testing.T) {
	stateDir := t.TempDir()
	previousPolicy := model.DefaultPolicy()
	previousPolicy.Name = "previous"
	previousPolicy.Adaptive.Enabled = true
	previousRules, err := Compile(previousPolicy)
	if err != nil {
		t.Fatal(err)
	}
	currentPolicy := model.DefaultPolicy()
	currentPolicy.Name = "current"
	currentRules, err := Compile(currentPolicy)
	if err != nil {
		t.Fatal(err)
	}
	writePolicyState(t, stateDir, "previous", previousPolicy, previousRules)
	writePolicyState(t, stateDir, "current", currentPolicy, currentRules)
	writeJSONFile(t, filepath.Join(stateDir, "manual-bans.json"), []model.BanTarget{{Address: "203.0.113.8"}})
	writeJSONFile(t, filepath.Join(stateDir, "adaptive-state.json"), adaptiveState{
		Emergency: true,
		Reason:    "test pressure",
		Since:     time.Now().UTC().Format(time.RFC3339Nano),
	})

	manager := NewManager(stateDir, true)
	if err := manager.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	gotPolicy, err := manager.CurrentPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if gotPolicy.Name != previousPolicy.Name {
		t.Fatalf("current policy name = %q, want %q", gotPolicy.Name, previousPolicy.Name)
	}
	gotRules, err := os.ReadFile(filepath.Join(stateDir, "current.nft"))
	if err != nil {
		t.Fatal(err)
	}
	if string(gotRules) != previousRules {
		t.Fatal("rollback did not restore the previous base rules")
	}
}

func TestRollbackRejectsInvalidPersistedBanWithoutChangingCurrentPolicy(t *testing.T) {
	stateDir := t.TempDir()
	previousPolicy := model.DefaultPolicy()
	previousPolicy.Name = "previous"
	previousRules, err := Compile(previousPolicy)
	if err != nil {
		t.Fatal(err)
	}
	currentPolicy := model.DefaultPolicy()
	currentPolicy.Name = "current"
	currentRules, err := Compile(currentPolicy)
	if err != nil {
		t.Fatal(err)
	}
	writePolicyState(t, stateDir, "previous", previousPolicy, previousRules)
	writePolicyState(t, stateDir, "current", currentPolicy, currentRules)
	writeJSONFile(t, filepath.Join(stateDir, "manual-bans.json"), []model.BanTarget{{Address: "127.0.0.1"}})

	manager := NewManager(stateDir, true)
	if err := manager.Rollback(context.Background()); err == nil {
		t.Fatal("rollback accepted an invalid persisted ban")
	}
	gotPolicy, err := manager.CurrentPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if gotPolicy.Name != currentPolicy.Name {
		t.Fatal("failed rollback changed the current policy")
	}
}

func TestSyncBansPersistsOnlyAfterRuntimeApplySucceeds(t *testing.T) {
	stateDir := t.TempDir()
	path := filepath.Join(stateDir, "manual-bans.json")
	original := []model.BanTarget{{Address: "203.0.113.8"}}
	writeJSONFile(t, path, original)
	manager := NewManager(stateDir, true)

	manager.mu.Lock()
	err := manager.syncBansLocked(context.Background(), []model.BanTarget{{Address: "203.0.113.9"}}, func(context.Context, []model.BanTarget) error {
		return errors.New("simulated nft failure")
	})
	manager.mu.Unlock()
	if err == nil {
		t.Fatal("failed runtime apply unexpectedly succeeded")
	}
	var afterFailure []model.BanTarget
	raw, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if json.Unmarshal(raw, &afterFailure) != nil || len(afterFailure) != 1 || afterFailure[0].Address != original[0].Address {
		t.Fatalf("failed runtime apply changed persisted bans: %#v", afterFailure)
	}

	replacement := []model.BanTarget{{Address: "203.0.113.10"}}
	manager.mu.Lock()
	err = manager.syncBansLocked(context.Background(), replacement, func(context.Context, []model.BanTarget) error { return nil })
	manager.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	raw, readErr = os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	var persisted []model.BanTarget
	if json.Unmarshal(raw, &persisted) != nil || len(persisted) != 1 || persisted[0].Address != replacement[0].Address {
		t.Fatalf("successful runtime apply did not persist bans: %#v", persisted)
	}
	info, statErr := os.Stat(path)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("persisted ban mode = %o, want 600", info.Mode().Perm())
	}
}

func writePolicyState(t *testing.T, stateDir, prefix string, policy model.Policy, rules string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(stateDir, prefix+".nft"), []byte(rules), 0600); err != nil {
		t.Fatal(err)
	}
	writeJSONFile(t, filepath.Join(stateDir, prefix+"-policy.json"), policy)
}

func writeJSONFile(t *testing.T, path string, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}
