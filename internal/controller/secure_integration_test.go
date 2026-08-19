package controller

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/T-Matrix/mmwx-guard/internal/agent"
	"github.com/T-Matrix/mmwx-guard/internal/protocol"
	"github.com/T-Matrix/mmwx-guard/internal/store"
	telemetrypkg "github.com/T-Matrix/mmwx-guard/internal/telemetry"
)

func TestAgentAndControllerEstablishVerifiedSecureChannel(t *testing.T) {
	t.Setenv("TURNSTILE_SITE_KEY", "")
	t.Setenv("TURNSTILE_SECRET", "")
	t.Setenv("TURNSTILE_HOSTNAMES", "")
	t.Setenv("TRUSTED_PROXY_CIDRS", "")

	temporary := t.TempDir()
	database, err := store.Open(filepath.Join(temporary, "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	secret := "agent-secret-with-more-than-twenty-characters"
	if err := database.CreateAgent(context.Background(), store.NewAgent{
		ID: "agent-integration", Name: "integration", MachineID: telemetrypkg.MachineID(), SecretHash: hashToken(secret),
	}); err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(database, nil, "v-test", "", temporary, filepath.Join(temporary, "controller-identity.key"), nil)
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()

	configPath := filepath.Join(temporary, "agent.json")
	config := agent.Config{
		ControllerURL: httpServer.URL, ControllerPublicKey: protocol.EncodeKey(server.identity.publicKey()),
		AgentID: "agent-integration", Secret: secret, Name: "integration",
	}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	client, err := agent.LoadOrEnroll(context.Background(), agent.Options{
		ConfigPath: configPath, StateDir: filepath.Join(temporary, "agent-state"), Version: "v-test", DryRun: true,
	}, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- client.Run(ctx) }()

	deadline := time.Now().Add(5 * time.Second)
	verified := false
	for time.Now().Before(deadline) {
		agents, listErr := database.ListAgents(context.Background())
		if listErr != nil {
			cancel()
			t.Fatal(listErr)
		}
		if len(agents) == 1 && agents[0].Status == "online" && agents[0].SecureChannel && agents[0].ControllerVerifiedAt != "" && agents[0].ControllerKeyFingerprint == server.identity.fingerprint() {
			verified = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	select {
	case runErr := <-errCh:
		if runErr != nil && !errors.Is(runErr, context.Canceled) {
			t.Fatalf("Agent stopped unexpectedly: %v", runErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Agent did not stop after cancellation")
	}
	if !verified {
		t.Fatal("Agent did not establish a controller-verified secure channel")
	}
}
