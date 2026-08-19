package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/T-Matrix/mmwx-guard/internal/model"
)

func TestOpenTightensDatabasePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "controller.db")
	if err := os.WriteFile(path, nil, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	storage, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	for _, suffix := range []string{"", "-wal", "-shm"} {
		info, err := os.Stat(path + suffix)
		if err != nil {
			t.Fatalf("stat database file %s: %v", suffix, err)
		}
		if got := info.Mode().Perm(); got != 0600 {
			t.Fatalf("database file %s mode = %o, want 600", suffix, got)
		}
	}
}

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

func TestAgentCredentialsReturnsMachineBinding(t *testing.T) {
	storage, err := Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	if err := storage.CreateAgent(context.Background(), NewAgent{ID: "agent-1", Name: "first", MachineID: "machine-1", SecretHash: "hash-1"}); err != nil {
		t.Fatal(err)
	}
	credentials, err := storage.AgentCredentials(context.Background(), "agent-1")
	if err != nil || credentials.SecretHash != "hash-1" || credentials.MachineID != "machine-1" {
		t.Fatalf("AgentCredentials() = %#v, %v", credentials, err)
	}
}

func TestCredentialRotationAndRevocation(t *testing.T) {
	storage, err := Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	ctx := context.Background()
	if err := storage.CreateAgent(ctx, NewAgent{ID: "agent-1", Name: "first", MachineID: "machine-1", SecretHash: "hash-1"}); err != nil {
		t.Fatal(err)
	}
	if err := storage.BeginCredentialRotation(ctx, "agent-1", "hash-2", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := storage.BeginCredentialRotation(ctx, "agent-1", "hash-3", time.Now().Add(time.Minute)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("overlapping credential rotation returned %v, want conflict", err)
	}
	agents, err := storage.ListAgents(ctx)
	if err != nil || len(agents) != 1 || agents[0].CredentialState != "rotation_pending" {
		t.Fatalf("rotation state = %#v, %v", agents, err)
	}
	if err := storage.PromoteCredential(ctx, "agent-1", "hash-2"); err != nil {
		t.Fatal(err)
	}
	credentials, err := storage.AgentCredentials(ctx, "agent-1")
	if err != nil || credentials.SecretHash != "hash-2" || credentials.PendingSecretHash != "" {
		t.Fatalf("promoted credentials = %#v, %v", credentials, err)
	}
	if err := storage.RevokeAgentCredential(ctx, "agent-1"); err != nil {
		t.Fatal(err)
	}
	agents, _ = storage.ListAgents(ctx)
	if agents[0].CredentialState != "revoked" || agents[0].SecureChannel {
		t.Fatalf("revoked Agent state = %#v", agents[0])
	}
}

func TestReenrollmentKeepsCurrentCredentialUntilReplacementConnects(t *testing.T) {
	storage, err := Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	ctx := context.Background()
	if err := storage.CreateAgent(ctx, NewAgent{ID: "agent-1", Name: "first", MachineID: "machine-1", SecretHash: "hash-1"}); err != nil {
		t.Fatal(err)
	}
	if err := storage.RevokeAgentCredential(ctx, "agent-1"); err != nil {
		t.Fatal(err)
	}
	if err := storage.PrepareAgentReenrollment(ctx, "agent-1", "different-machine", "hash-2", "linux", "amd64", "v1", "127.0.0.1", time.Now().Add(time.Minute)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("re-pairing accepted a different machine ID: %v", err)
	}
	if err := storage.PrepareAgentReenrollment(ctx, "agent-1", "machine-1", "hash-2", "linux", "amd64", "v1", "127.0.0.1", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	credentials, err := storage.AgentCredentials(ctx, "agent-1")
	if err != nil || credentials.SecretHash != "hash-1" || credentials.PendingSecretHash != "hash-2" || credentials.RevokedAt == "" {
		t.Fatalf("prepared re-enrollment = %#v, %v", credentials, err)
	}
	if err := storage.PromoteCredential(ctx, "agent-1", "hash-2"); err != nil {
		t.Fatal(err)
	}
	credentials, err = storage.AgentCredentials(ctx, "agent-1")
	if err != nil || credentials.SecretHash != "hash-2" || credentials.PendingSecretHash != "" || credentials.RevokedAt != "" {
		t.Fatalf("promoted re-enrollment = %#v, %v", credentials, err)
	}
}

func TestChangeAdminPasswordInvalidatesExistingSessions(t *testing.T) {
	storage, err := Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	ctx := context.Background()
	if err := storage.CreateAdmin(ctx, "admin", "old-hash"); err != nil {
		t.Fatal(err)
	}
	adminID, _, err := storage.AdminPasswordHash(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{"old-session-1", "old-session-2"} {
		if err := storage.CreateSession(ctx, token, adminID, time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	if err := storage.ChangeAdminPassword(ctx, "admin", "new-hash", "new-session", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{"old-session-1", "old-session-2"} {
		if _, err := storage.SessionAdmin(ctx, token); !errors.Is(err, ErrNotFound) {
			t.Fatalf("old session %q survived password change: %v", token, err)
		}
	}
	if username, err := storage.SessionAdmin(ctx, "new-session"); err != nil || username != "admin" {
		t.Fatalf("replacement session = %q, %v", username, err)
	}
	_, hash, err := storage.AdminPasswordHash(ctx, "admin")
	if err != nil || hash != "new-hash" {
		t.Fatalf("password hash = %q, %v", hash, err)
	}
}

func TestMigrateLegacyDatabaseAddsSecurityColumns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "controller.db")
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`
		CREATE TABLE enrollment_tokens (token_hash TEXT PRIMARY KEY,label TEXT NOT NULL,expires_at TEXT NOT NULL,used_at TEXT,created_at TEXT NOT NULL);
		CREATE TABLE agents (id TEXT PRIMARY KEY,name TEXT NOT NULL,machine_id TEXT NOT NULL UNIQUE,secret_hash TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'offline',ip_address TEXT NOT NULL DEFAULT '',os TEXT NOT NULL DEFAULT '',arch TEXT NOT NULL DEFAULT '',version TEXT NOT NULL DEFAULT '',last_seen TEXT NOT NULL DEFAULT '',policy_id INTEGER,policy_revision INTEGER NOT NULL DEFAULT 0,telemetry_json TEXT,created_at TEXT NOT NULL);
	`)
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	storage, err := Open(path)
	if err != nil {
		t.Fatalf("migrate legacy database: %v", err)
	}
	defer storage.Close()
	if err := storage.CreateAgent(context.Background(), NewAgent{ID: "agent-1", Name: "legacy", MachineID: "machine-1", SecretHash: "hash-1"}); err != nil {
		t.Fatal(err)
	}
	credentials, err := storage.AgentCredentials(context.Background(), "agent-1")
	if err != nil || credentials.SecretHash != "hash-1" || credentials.PendingSecretHash != "" {
		t.Fatalf("migrated credentials = %#v, %v", credentials, err)
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

func TestDeletePolicyIfUnassigned(t *testing.T) {
	storage, err := Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	ctx := context.Background()
	if err := storage.CreateAgent(ctx, NewAgent{ID: "agent-1", Name: "first", MachineID: "machine-1", SecretHash: "hash-1"}); err != nil {
		t.Fatal(err)
	}
	policy, err := storage.SavePolicy(ctx, model.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.AssignPolicy(ctx, "agent-1", policy.ID, policy.Revision); err != nil {
		t.Fatal(err)
	}
	if err := storage.DeletePolicyIfUnassigned(ctx, policy.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.GetPolicy(ctx, policy.ID); err != nil {
		t.Fatalf("assigned policy was deleted: %v", err)
	}
	if err := storage.DeleteAgent(ctx, "agent-1"); err != nil {
		t.Fatal(err)
	}
	if err := storage.DeletePolicyIfUnassigned(ctx, policy.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.GetPolicy(ctx, policy.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unassigned policy still exists: %v", err)
	}
}
