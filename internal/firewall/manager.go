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
	"time"

	"github.com/T-Matrix/mmwx-guard/internal/model"
)

type Manager struct {
	stateDir        string
	dryRun          bool
	mu              sync.Mutex
	emergency       bool
	emergencyReason string
	emergencySince  time.Time
}

func NewManager(stateDir string, dryRun bool) *Manager {
	manager := &Manager{stateDir: stateDir, dryRun: dryRun}
	var state adaptiveState
	if raw, err := os.ReadFile(filepath.Join(stateDir, "adaptive-state.json")); err == nil && json.Unmarshal(raw, &state) == nil && state.Emergency {
		manager.emergency = true
		manager.emergencyReason = state.Reason
		manager.emergencySince, _ = time.Parse(time.RFC3339Nano, state.Since)
	}
	return manager
}

type adaptiveState struct {
	Emergency bool   `json:"emergency"`
	Reason    string `json:"reason,omitempty"`
	Since     string `json:"since,omitempty"`
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
	bans, err := m.currentBansLocked()
	if errors.Is(err, os.ErrNotExist) {
		bans = nil
	} else if err != nil {
		return fmt.Errorf("load IP bans: %w", err)
	}
	runtimeRules, err := compileRuntimeRules(policy, rules, bans, m.emergency, time.Now())
	if err != nil {
		return err
	}
	candidate := filepath.Join(m.stateDir, "candidate.nft")
	candidateRules := m.transactionRules(ctx, runtimeRules)
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
		if len(currentRules) > 0 && len(currentPolicy) > 0 {
			var previousPolicy model.Policy
			if json.Unmarshal(currentPolicy, &previousPolicy) == nil {
				if restoreRules, compileErr := compileRuntimeRules(previousPolicy, string(currentRules), bans, m.emergency, time.Now()); compileErr == nil {
					rollbackFile := filepath.Join(m.stateDir, "rollback.nft")
					_ = os.WriteFile(rollbackFile, []byte(m.transactionRules(ctx, restoreRules)), 0600)
					_ = exec.CommandContext(ctx, "nft", "-f", rollbackFile).Run()
				}
			}
		}
		return fmt.Errorf("nft apply failed: %s", strings.TrimSpace(string(out)))
	}
	if !policy.Adaptive.Enabled {
		m.emergency = false
		m.emergencyReason = ""
		m.emergencySince = time.Time{}
		if err := m.persistAdaptiveStateLocked(); err != nil {
			return err
		}
	}
	// Keep host-wide kernel tuning under the server operator's control. This
	// manager owns only its dedicated nftables table.
	return m.persist(policy, rules)
}

func compileRuntimeRules(policy model.Policy, baseRules string, bans []model.BanTarget, emergency bool, now time.Time) (string, error) {
	var rules strings.Builder
	rules.WriteString(baseRules)
	if emergency && policy.Adaptive.Enabled {
		adaptiveRules, err := AdaptiveEmergencyCommands(policy, true)
		if err != nil {
			return "", fmt.Errorf("compile adaptive emergency rules: %w", err)
		}
		rules.WriteString(adaptiveRules)
	}
	banRules, err := SyncBanCommands(bans, now)
	if err != nil {
		return "", fmt.Errorf("compile IP bans: %w", err)
	}
	rules.WriteString(banRules)
	return rules.String(), nil
}

func (m *Manager) Rollback(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	previousRules, err := os.ReadFile(filepath.Join(m.stateDir, "previous.nft"))
	if err != nil {
		return errors.New("no previous policy is available")
	}
	previousPolicyRaw, err := os.ReadFile(filepath.Join(m.stateDir, "previous-policy.json"))
	if err != nil {
		return errors.New("no previous policy metadata is available")
	}
	var previousPolicy model.Policy
	if err := json.Unmarshal(previousPolicyRaw, &previousPolicy); err != nil {
		return fmt.Errorf("decode previous policy: %w", err)
	}
	bans, err := m.currentBansOrEmptyLocked()
	if err != nil {
		return fmt.Errorf("load IP bans: %w", err)
	}
	runtimeRules, err := compileRuntimeRules(previousPolicy, string(previousRules), bans, m.emergency, time.Now())
	if err != nil {
		return err
	}
	if m.dryRun {
		return m.persistSavedPolicyLocked(previousRules, previousPolicyRaw)
	}
	rollbackFile := filepath.Join(m.stateDir, "rollback.nft")
	transaction := m.transactionRules(ctx, runtimeRules)
	if err := os.WriteFile(rollbackFile, []byte(transaction), 0600); err != nil {
		return err
	}
	if out, err := exec.CommandContext(ctx, "nft", "-c", "-f", rollbackFile).CombinedOutput(); err != nil {
		return fmt.Errorf("rollback syntax check failed: %s", strings.TrimSpace(string(out)))
	}
	if out, err := exec.CommandContext(ctx, "nft", "-f", rollbackFile).CombinedOutput(); err != nil {
		return fmt.Errorf("rollback failed: %s", strings.TrimSpace(string(out)))
	}
	if !previousPolicy.Adaptive.Enabled && m.emergency {
		m.clearAdaptiveEmergencyLocked()
		if err := m.persistAdaptiveStateLocked(); err != nil {
			return err
		}
	}
	return m.persistSavedPolicyLocked(previousRules, previousPolicyRaw)
}

func (m *Manager) transactionRules(ctx context.Context, rules string) string {
	if exec.CommandContext(ctx, "nft", "list", "table", "inet", TableName).Run() == nil {
		return "delete table inet " + TableName + "\n" + rules
	}
	return rules
}

func (m *Manager) Ensure(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
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
	policy, err := m.currentPolicyLocked()
	if err != nil {
		return fmt.Errorf("load current policy: %w", err)
	}
	bans, err := m.currentBansOrEmptyLocked()
	if err != nil {
		return fmt.Errorf("load IP bans: %w", err)
	}
	runtimeRules, err := compileRuntimeRules(policy, string(rules), bans, m.emergency, time.Now())
	if err != nil {
		return err
	}
	path := filepath.Join(m.stateDir, "ensure.nft")
	if err := os.WriteFile(path, []byte(runtimeRules), 0600); err != nil {
		return err
	}
	if out, err := exec.CommandContext(ctx, "nft", "-c", "-f", path).CombinedOutput(); err != nil {
		return fmt.Errorf("ensure syntax check failed: %s", strings.TrimSpace(string(out)))
	}
	if out, err := exec.CommandContext(ctx, "nft", "-f", path).CombinedOutput(); err != nil {
		return fmt.Errorf("ensure failed: %s", strings.TrimSpace(string(out)))
	}
	if !policy.Adaptive.Enabled && m.emergency {
		m.clearAdaptiveEmergencyLocked()
		return m.persistAdaptiveStateLocked()
	}
	return nil
}

func (m *Manager) CurrentPolicy() (model.Policy, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.currentPolicyLocked()
}

func (m *Manager) currentPolicyLocked() (model.Policy, error) {
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

func (m *Manager) SetAdaptiveEmergency(ctx context.Context, policy model.Policy, active bool, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if active == m.emergency {
		return nil
	}
	if err := m.applyAdaptiveEmergencyLocked(ctx, policy, active); err != nil {
		return err
	}
	m.emergency = active
	if active {
		m.emergencyReason = reason
		m.emergencySince = time.Now().UTC()
	} else {
		m.emergencyReason = ""
		m.emergencySince = time.Time{}
	}
	return m.persistAdaptiveStateLocked()
}

func (m *Manager) persistAdaptiveStateLocked() error {
	if err := os.MkdirAll(m.stateDir, 0700); err != nil {
		return err
	}
	state := adaptiveState{Emergency: m.emergency, Reason: m.emergencyReason}
	if !m.emergencySince.IsZero() {
		state.Since = m.emergencySince.Format(time.RFC3339Nano)
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(m.stateDir, "adaptive-state.json"), raw, 0600)
}

func (m *Manager) AdaptiveStatus() model.AdaptiveStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	status := model.AdaptiveStatus{Emergency: m.emergency, Reason: m.emergencyReason}
	if !m.emergencySince.IsZero() {
		status.Since = m.emergencySince.Format(time.RFC3339Nano)
	}
	return status
}

func (m *Manager) SyncBans(ctx context.Context, bans []model.BanTarget) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.syncBansLocked(ctx, bans, m.applyBanSyncLocked)
}

func (m *Manager) syncBansLocked(ctx context.Context, bans []model.BanTarget, apply func(context.Context, []model.BanTarget) error) error {
	if _, err := SyncBanCommands(bans, time.Now()); err != nil {
		return err
	}
	if err := os.MkdirAll(m.stateDir, 0700); err != nil {
		return err
	}
	raw, err := json.Marshal(bans)
	if err != nil {
		return err
	}
	if err := apply(ctx, bans); err != nil {
		return err
	}
	return writeStateFileAtomic(filepath.Join(m.stateDir, "manual-bans.json"), raw)
}

func (m *Manager) currentBansLocked() ([]model.BanTarget, error) {
	raw, err := os.ReadFile(filepath.Join(m.stateDir, "manual-bans.json"))
	if err != nil {
		return nil, err
	}
	var bans []model.BanTarget
	if err := json.Unmarshal(raw, &bans); err != nil {
		return nil, err
	}
	active := bans[:0]
	now := time.Now()
	for _, ban := range bans {
		if ban.ExpiresAt == "" {
			active = append(active, ban)
			continue
		}
		expires, err := time.Parse(time.RFC3339Nano, ban.ExpiresAt)
		if err != nil {
			return nil, fmt.Errorf("invalid persisted expiry for banned IP %q", ban.Address)
		}
		if expires.After(now) {
			active = append(active, ban)
		}
	}
	return active, nil
}

func (m *Manager) currentBansOrEmptyLocked() ([]model.BanTarget, error) {
	bans, err := m.currentBansLocked()
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return bans, err
}

func (m *Manager) applyBanSyncLocked(ctx context.Context, bans []model.BanTarget) error {
	commands, err := SyncBanCommands(bans, time.Now())
	if err != nil {
		return err
	}
	if m.dryRun {
		return nil
	}
	if runtime.GOOS != "linux" {
		return errors.New("IP bans are available only on Linux")
	}
	path := filepath.Join(m.stateDir, "sync-bans.nft")
	if err := os.WriteFile(path, []byte(commands), 0600); err != nil {
		return err
	}
	if out, err := exec.CommandContext(ctx, "nft", "-c", "-f", path).CombinedOutput(); err != nil {
		return fmt.Errorf("IP ban syntax check failed: %s", strings.TrimSpace(string(out)))
	}
	if out, err := exec.CommandContext(ctx, "nft", "-f", path).CombinedOutput(); err != nil {
		return fmt.Errorf("IP ban apply failed: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func (m *Manager) applyAdaptiveEmergencyLocked(ctx context.Context, policy model.Policy, active bool) error {
	rules, err := AdaptiveEmergencyCommands(policy, active)
	if err != nil {
		return err
	}
	if m.dryRun {
		return nil
	}
	if runtime.GOOS != "linux" {
		return errors.New("adaptive emergency protection is available only on Linux")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		return errors.New("nft executable not found")
	}
	path := filepath.Join(m.stateDir, "adaptive-emergency.nft")
	if err := os.WriteFile(path, []byte(rules), 0600); err != nil {
		return err
	}
	if out, err := exec.CommandContext(ctx, "nft", "-c", "-f", path).CombinedOutput(); err != nil {
		return fmt.Errorf("adaptive emergency syntax check failed: %s", strings.TrimSpace(string(out)))
	}
	if out, err := exec.CommandContext(ctx, "nft", "-f", path).CombinedOutput(); err != nil {
		return fmt.Errorf("adaptive emergency apply failed: %s", strings.TrimSpace(string(out)))
	}
	return nil
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

func (m *Manager) persistSavedPolicyLocked(rules, policy []byte) error {
	if err := os.WriteFile(filepath.Join(m.stateDir, "current.nft"), rules, 0600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(m.stateDir, "current-policy.json"), policy, 0600)
}

func writeStateFileAtomic(path string, content []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".firewall-state-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func (m *Manager) clearAdaptiveEmergencyLocked() {
	m.emergency = false
	m.emergencyReason = ""
	m.emergencySince = time.Time{}
}
