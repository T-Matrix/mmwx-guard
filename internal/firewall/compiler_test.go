package firewall

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/T-Matrix/mmwx-guard/internal/model"
)

func TestCompileDefaultPolicy(t *testing.T) {
	rules, err := Compile(model.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"table inet mmwx_guard",
		"tcp dport 15542",
		"limit rate over 100/second burst 500 packets",
		"ip saddr 0.0.0.0/0 limit rate over 300/second",
		"ip6 saddr ::/0 limit rate over 300/second",
		"tcp dport != { 22, 48357 }",
		"priority raw + 5",
		"chain adaptive_emergency",
		"jump adaptive_emergency",
		"set manual_bans_v4",
		"@temporary_bans_v6",
	} {
		if !strings.Contains(rules, want) {
			t.Fatalf("compiled rules do not contain %q:\n%s", want, rules)
		}
	}
}

func TestSyncBanCommandsSeparatesPermanentTemporaryAndFamilies(t *testing.T) {
	now := time.Date(2026, 8, 19, 0, 0, 0, 0, time.UTC)
	rules, err := SyncBanCommands([]model.BanTarget{
		{Address: "203.0.113.8"},
		{Address: "2001:db8::8", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano)},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"flush set inet mmwx_guard manual_bans_v4",
		"add element inet mmwx_guard manual_bans_v4 { 203.0.113.8 }",
		"add element inet mmwx_guard temporary_bans_v6 { 2001:db8::8 timeout 3600s }",
	} {
		if !strings.Contains(rules, want) {
			t.Fatalf("ban sync does not contain %q:\n%s", want, rules)
		}
	}
}

func TestAdaptiveEmergencyCommandsPreserveExemptPorts(t *testing.T) {
	policy := model.DefaultPolicy()
	policy.Adaptive.Enabled = true
	rules, err := AdaptiveEmergencyCommands(policy, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"flush chain inet mmwx_guard adaptive_emergency",
		"tcp dport != { 22, 48357 }",
		"limit rate over 200/second burst 600 packets",
		"adaptive emergency IPv4",
		"adaptive emergency IPv6",
	} {
		if !strings.Contains(rules, want) {
			t.Fatalf("adaptive rules do not contain %q:\n%s", want, rules)
		}
	}
	disabled, err := AdaptiveEmergencyCommands(policy, false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(disabled, "add rule") {
		t.Fatalf("disabled adaptive commands still add rules:\n%s", disabled)
	}
}

func TestCompileRuntimeRulesRestoresStateInSingleTransaction(t *testing.T) {
	policy := model.DefaultPolicy()
	policy.Adaptive.Enabled = true
	base, err := Compile(policy)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	rules, err := compileRuntimeRules(policy, base, []model.BanTarget{{Address: "203.0.113.8"}}, true, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"table inet mmwx_guard",
		"flush chain inet mmwx_guard adaptive_emergency",
		"adaptive emergency IPv4",
		"flush set inet mmwx_guard manual_bans_v4",
		"add element inet mmwx_guard manual_bans_v4 { 203.0.113.8 }",
	} {
		if !strings.Contains(rules, want) {
			t.Fatalf("runtime transaction does not contain %q:\n%s", want, rules)
		}
	}
}

func TestCompileRuntimeRulesRejectsInvalidPersistedBanBeforeApply(t *testing.T) {
	policy := model.DefaultPolicy()
	base, err := Compile(policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := compileRuntimeRules(policy, base, []model.BanTarget{{Address: "127.0.0.1"}}, false, time.Now()); err == nil {
		t.Fatal("invalid persisted ban was accepted")
	}
}

func TestCurrentBansIgnoresExpiredEntries(t *testing.T) {
	stateDir := t.TempDir()
	bans := []model.BanTarget{
		{Address: "203.0.113.8", ExpiresAt: time.Now().Add(-time.Minute).Format(time.RFC3339Nano)},
		{Address: "203.0.113.9", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339Nano)},
		{Address: "203.0.113.10"},
	}
	raw, err := json.Marshal(bans)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "manual-bans.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	manager := NewManager(stateDir, true)
	manager.mu.Lock()
	active, err := manager.currentBansLocked()
	manager.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 2 || active[0].Address != "203.0.113.9" || active[1].Address != "203.0.113.10" {
		t.Fatalf("active bans = %#v", active)
	}
}

func TestCompileTrustedCIDRs(t *testing.T) {
	p := model.DefaultPolicy()
	p.TrustedCIDRs = []string{"10.0.0.1", "2001:db8::/32"}
	rules, err := Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rules, "10.0.0.1/32") || !strings.Contains(rules, "2001:db8::/32") {
		t.Fatalf("trusted prefixes missing:\n%s", rules)
	}
}
