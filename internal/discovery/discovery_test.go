package discovery

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiscoverMMWAndForwardX(t *testing.T) {
	dir := t.TempDir()
	mmwPath := filepath.Join(dir, "mmw.yaml")
	forwardXPath := filepath.Join(dir, "forwardx.json")
	rulesDir := filepath.Join(dir, "realm")
	if err := os.Mkdir(rulesDir, 0700); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, mmwPath, "master_url: https://mmwx.example.com/\ntoken: do-not-report\nconnection_mode: websocket\nxray_mode: embedded\n")
	writeTestFile(t, forwardXPath, `{"panelUrl":"https://forwardx.example.com/","token":"do-not-report"}`)
	writeTestFile(t, filepath.Join(rulesDir, "forwardx-realm-both-15542.toml"), `
[network]
use_udp = true

[[endpoints]]
listen = "[::0]:15542"
remote = "156.229.164.222:15542"
`)
	active := map[string]bool{
		"mmw-agent.service": true, "forwardx-agent.service": true,
		"forwardx-realm-both-15542.service": true,
	}
	got := Discover(context.Background(), Options{
		MMWConfigPath: mmwPath, ForwardXConfigPath: forwardXPath, ForwardXRulesDir: rulesDir,
		ServiceActive: func(_ context.Context, unit string) bool { return active[unit] },
	})
	if got.MMW == nil || !got.MMW.Active || got.MMW.MasterURL != "https://mmwx.example.com" {
		t.Fatalf("MMW discovery = %#v", got.MMW)
	}
	if got.ForwardX == nil || !got.ForwardX.Active || len(got.ForwardX.Rules) != 1 {
		t.Fatalf("ForwardX discovery = %#v", got.ForwardX)
	}
	rule := got.ForwardX.Rules[0]
	if rule.Protocol != "tcp+udp" || rule.ListenPort != 15542 || rule.Remote != "156.229.164.222:15542" || !rule.Active {
		t.Fatalf("ForwardX rule = %#v", rule)
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "do-not-report") {
		t.Fatal("discovery output leaked an integration token")
	}
}

func TestDiscoverWithoutIntegrations(t *testing.T) {
	got := Discover(context.Background(), Options{
		MMWConfigPath:      filepath.Join(t.TempDir(), "missing-mmw"),
		ForwardXConfigPath: filepath.Join(t.TempDir(), "missing-forwardx"),
		ForwardXRulesDir:   filepath.Join(t.TempDir(), "missing-rules"),
		ServiceActive:      func(context.Context, string) bool { return false },
	})
	if got.MMW != nil || got.ForwardX != nil {
		t.Fatalf("unexpected integrations: %#v", got)
	}
}

func writeTestFile(t *testing.T, path, value string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(value), 0600); err != nil {
		t.Fatal(err)
	}
}
