package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/T-Matrix/mmwx-guard/internal/protocol"
)

func TestValidateControllerURL(t *testing.T) {
	for _, value := range []string{"https://guard.example.com", "http://localhost:9080", "http://127.0.0.1:9080"} {
		if err := validateControllerURL(value); err != nil {
			t.Fatalf("valid URL %q rejected: %v", value, err)
		}
	}
	for _, value := range []string{"http://guard.example.com", "https://user:pass@guard.example.com", "https://guard.example.com/path", "https://guard.example.com?secret=value", "ftp://guard.example.com"} {
		if err := validateControllerURL(value); err == nil {
			t.Fatalf("unsafe URL %q accepted", value)
		}
	}
}

func TestCredentialOverrideIsBoundToEnrollment(t *testing.T) {
	options := Options{StateDir: t.TempDir()}
	base := Config{ControllerURL: "https://guard.example.com", AgentID: "agent-1", Secret: "old-secret", ControllerPublicKey: "old-key"}
	override := base
	override.Secret = "new-secret"
	override.ControllerPublicKey = "new-key"
	if err := saveConfig(credentialOverridePath(options), override); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadCredentialOverride(options, base)
	if err != nil || loaded.Secret != "new-secret" || loaded.ControllerPublicKey != "new-key" {
		t.Fatalf("credential override = %#v, %v", loaded, err)
	}
	override.AgentID = "different-agent"
	if err := saveConfig(credentialOverridePath(options), override); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCredentialOverride(options, base); err == nil {
		t.Fatal("credential override for another Agent was accepted")
	}
}

func TestVerifyControllerPinsIdentityAndRejectsChanges(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	agentEphemeral, _ := protocol.GenerateEphemeralKey()
	controllerEphemeral, _ := protocol.GenerateEphemeralKey()
	cfg := Config{ControllerURL: "https://guard.example.com", AgentID: "agent-1", Secret: "secret", Name: "agent"}
	challenge := protocol.EncodeKey(make([]byte, 32))
	machineID := "machine-1"
	transcript := protocol.HandshakeTranscript(cfg.AgentID, machineID, challenge, agentEphemeral.PublicKey(), controllerEphemeral.PublicKey())
	ack := protocol.HelloAck{
		Secure: true, ControllerPublicKey: protocol.EncodeKey(public),
		ControllerEphemeralPublicKey: protocol.EncodeKey(controllerEphemeral.PublicKey()),
		Signature:                    protocol.EncodeKey(ed25519.Sign(private, transcript)),
	}
	options := Options{StateDir: t.TempDir()}
	client := &Client{config: cfg, options: options}
	if _, err := client.verifyControllerAndDerive(cfg, ack, agentEphemeral, challenge, machineID); err != nil {
		t.Fatalf("valid controller proof rejected: %v", err)
	}
	pinned, err := loadCredentialOverride(options, cfg)
	if err != nil || pinned.ControllerPublicKey != protocol.EncodeKey(public) {
		t.Fatalf("pinned controller identity = %#v, %v", pinned, err)
	}
	otherPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	ack.ControllerPublicKey = protocol.EncodeKey(otherPublic)
	if _, err := client.verifyControllerAndDerive(*pinned, ack, agentEphemeral, challenge, machineID); err == nil {
		t.Fatal("changed controller identity was accepted")
	}
	info, err := os.Stat(filepath.Join(options.StateDir, "agent-credentials.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("credential override mode = %v", info.Mode().Perm())
	}
}

func TestAcceptCommandRejectsReplay(t *testing.T) {
	client := &Client{seen: make(map[string]time.Time)}
	message, err := protocol.NewMessage(protocol.TypeApplyPolicy, "0123456789abcdef", map[string]bool{"ok": true})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.acceptCommand(message); err != nil {
		t.Fatalf("first command rejected: %v", err)
	}
	if err := client.acceptCommand(message); err == nil {
		t.Fatal("replayed command accepted")
	}
}
