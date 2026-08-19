package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/T-Matrix/mmwx-guard/internal/model"
)

type Manager struct {
	stateDir string
	dryRun   bool
	mu       sync.Mutex
}

func NewManager(stateDir string, dryRun bool) *Manager {
	return &Manager{stateDir: stateDir, dryRun: dryRun}
}

func (m *Manager) Apply(ctx context.Context, policy model.Policy) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rules, err := Compile(policy)
	if err != nil {
		return err
	}
	if m.dryRun {
		return m.persist(policy, rules)
	}
	if runtime.GOOS != "linux" {
		return errors.New("nftables policies can only be applied on Linux")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		return errors.New("nft executable not found")
	}
	if err := os.MkdirAll(m.stateDir, 0700); err != nil {
		return err
	}
	candidate := filepath.Join(m.stateDir, "candidate.nft")
	candidateRules := m.transactionRules(ctx, rules)
	if err := os.WriteFile(candidate, []byte(candidateRules), 0600); err != nil {
		return err
	}
	if out, err := exec.CommandContext(ctx, "nft", "-c", "-f", candidate).CombinedOutput(); err != nil {
		return fmt.Errorf("nft syntax check failed: %s", strings.TrimSpace(string(out)))
	}
	currentRules, _ := os.ReadFile(filepath.Join(m.stateDir, "current.nft"))
	currentPolicy, _ := os.ReadFile(filepath.Join(m.stateDir, "current-policy.json"))
	if len(currentRules) > 0 {
		_ = os.WriteFile(filepath.Join(m.stateDir, "previous.nft"), currentRules, 0600)
		_ = os.WriteFile(filepath.Join(m.stateDir, "previous-policy.json"), currentPolicy, 0600)
	}
	if out, err := exec.CommandContext(ctx, "nft", "-f", candidate).CombinedOutput(); err != nil {
		if len(currentRules) > 0 {
			rollbackFile := filepath.Join(m.stateDir, "rollback.nft")
			_ = os.WriteFile(rollbackFile, []byte(m.transactionRules(ctx, string(currentRules))), 0600)
			_ = exec.CommandContext(ctx, "nft", "-f", rollbackFile).Run()
		}
		return fmt.Errorf("nft apply failed: %s", strings.TrimSpace(string(out)))
	}
	// Keep host-wide kernel tuning under the server operator's control. This
	// manager owns only its dedicated nftables table.
	return m.persist(policy, rules)
}

func (m *Manager) Rollback(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	previous, err := os.ReadFile(filepath.Join(m.stateDir, "previous.nft"))
	if err != nil {
		return errors.New("no previous policy is available")
	}
	if m.dryRun {
		return os.WriteFile(filepath.Join(m.stateDir, "current.nft"), previous, 0600)
	}
	rollbackFile := filepath.Join(m.stateDir, "rollback.nft")
	transaction := m.transactionRules(ctx, string(previous))
	if err := os.WriteFile(rollbackFile, []byte(transaction), 0600); err != nil {
		return err
	}
	if out, err := exec.CommandContext(ctx, "nft", "-c", "-f", rollbackFile).CombinedOutput(); err != nil {
		return fmt.Errorf("rollback syntax check failed: %s", strings.TrimSpace(string(out)))
	}
	if out, err := exec.CommandContext(ctx, "nft", "-f", rollbackFile).CombinedOutput(); err != nil {
		return fmt.Errorf("rollback failed: %s", strings.TrimSpace(string(out)))
	}
	return os.WriteFile(filepath.Join(m.stateDir, "current.nft"), previous, 0600)
}

func (m *Manager) transactionRules(ctx context.Context, rules string) string {
	if exec.CommandContext(ctx, "nft", "list", "table", "inet", TableName).Run() == nil {
		return "delete table inet " + TableName + "\n" + rules
	}
	return rules
}

func (m *Manager) Ensure(ctx context.Context) error {
	if m.dryRun || runtime.GOOS != "linux" {
		return nil
	}
	if exec.CommandContext(ctx, "nft", "list", "table", "inet", TableName).Run() == nil {
		return nil
	}
	rules, err := os.ReadFile(filepath.Join(m.stateDir, "current.nft"))
	if err != nil || len(rules) == 0 {
		return nil
	}
	path := filepath.Join(m.stateDir, "ensure.nft")
	if err := os.WriteFile(path, rules, 0600); err != nil {
		return err
	}
	return exec.CommandContext(ctx, "nft", "-f", path).Run()
}

func (m *Manager) CurrentPolicy() (model.Policy, error) {
	raw, err := os.ReadFile(filepath.Join(m.stateDir, "current-policy.json"))
	if err != nil {
		return model.Policy{}, err
	}
	var policy model.Policy
	if err := json.Unmarshal(raw, &policy); err != nil {
		return model.Policy{}, err
	}
	return policy, nil
}

func (m *Manager) persist(policy model.Policy, rules string) error {
	if err := os.MkdirAll(m.stateDir, 0700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(m.stateDir, "current.nft"), []byte(rules), 0600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(m.stateDir, "current-policy.json"), raw, 0600)
}
