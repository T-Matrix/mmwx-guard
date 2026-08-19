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

func TestSetAgentPublicAddresses(t *testing.T) {
	storage, err := Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	ctx := context.Background()
	if err := storage.CreateAgent(ctx, NewAgent{ID: "agent-1", Name: "dual-stack", MachineID: "machine-1", SecretHash: "hash"}); err != nil {
		t.Fatal(err)
	}
	if err := storage.SetAgentPublicAddresses(ctx, "agent-1", "104.251.231.10", ""); err != nil {
		t.Fatal(err)
	}
	if err := storage.SetAgentPublicAddresses(ctx, "agent-1", "", "2605:52c0:1:1313:8022:3ff:fe12:4fce"); err != nil {
		t.Fatal(err)
	}
	agents, err := storage.ListAgents(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(agents) != 1 || agents[0].IPv4Address != "104.251.231.10" || agents[0].IPv6Address != "2605:52c0:1:1313:8022:3ff:fe12:4fce" || agents[0].AddressUpdatedAt == "" {
		t.Fatalf("public addresses = %#v", agents)
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

func TestEnrollmentCanBeCheckedBeforeConsumption(t *testing.T) {
	storage, err := Open(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	ctx := context.Background()
	if err := storage.CreateEnrollment(ctx, "token-hash", "new server", "", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if enrollment, err := storage.Enrollment(ctx, "token-hash"); err != nil || enrollment.Label != "new server" {
		t.Fatalf("Enrollment() = %#v, %v", enrollment, err)
	}
	if _, err := storage.Enrollment(ctx, "token-hash"); err != nil {
		t.Fatalf("preflight consumed enrollment: %v", err)
	}
	if _, err := storage.ConsumeEnrollment(ctx, "token-hash"); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Enrollment(ctx, "token-hash"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("consumed enrollment remained valid: %v", err)
	}
}

func TestAgentNameByMachineID(t *testing.T) {
	storage, err := Open(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	if err := storage.CreateAgent(context.Background(), NewAgent{ID: "agent-1", Name: "existing", MachineID: "cloned-machine", SecretHash: "hash"}); err != nil {
		t.Fatal(err)
	}
	name, err := storage.AgentNameByMachineID(context.Background(), "cloned-machine")
	if err != nil || name != "existing" {
		t.Fatalf("AgentNameByMachineID() = %q, %v", name, err)
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

func TestIPBanLifecycleAndExpiry(t *testing.T) {
	storage, err := Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	ctx := context.Background()
	if err := storage.CreateAgent(ctx, NewAgent{ID: "agent-1", Name: "first", MachineID: "machine-1", SecretHash: "hash-1"}); err != nil {
		t.Fatal(err)
	}
	permanent, err := storage.SaveIPBan(ctx, "agent-1", "203.0.113.8", "abuse", time.Time{})
	if err != nil || permanent.ID == 0 || permanent.ExpiresAt != "" || permanent.Applied {
		t.Fatalf("permanent ban = %#v, %v", permanent, err)
	}
	temporary, err := storage.SaveIPBan(ctx, "agent-1", "2001:db8::8", "burst", time.Now().Add(time.Hour))
	if err != nil || temporary.ExpiresAt == "" {
		t.Fatalf("temporary ban = %#v, %v", temporary, err)
	}
	if err := storage.SetIPBansApplyState(ctx, "agent-1", true, ""); err != nil {
		t.Fatal(err)
	}
	bans, err := storage.ListIPBans(ctx, "agent-1")
	if err != nil || len(bans) != 2 || !bans[0].Applied || !bans[1].Applied {
		t.Fatalf("bans = %#v, %v", bans, err)
	}
	updated, err := storage.SaveIPBan(ctx, "agent-1", "203.0.113.8", "extended", time.Now().Add(2*time.Hour))
	if err != nil || updated.ID != permanent.ID || updated.Reason != "extended" || updated.Applied {
		t.Fatalf("updated ban = %#v, %v", updated, err)
	}
	if err := storage.DeleteIPBan(ctx, "agent-1", temporary.ID); err != nil {
		t.Fatal(err)
	}
	if bans, err = storage.ListIPBans(ctx, "agent-1"); err != nil || len(bans) != 1 {
		t.Fatalf("bans after delete = %#v, %v", bans, err)
	}
	if err := storage.DeleteAgent(ctx, "agent-1"); err != nil {
		t.Fatal(err)
	}
	if bans, err = storage.ListIPBans(ctx, "agent-1"); err != nil || len(bans) != 0 {
		t.Fatalf("bans survived Agent deletion = %#v, %v", bans, err)
	}
}

func TestPolicyHistoryIsImmutableAndRetainedPerAgent(t *testing.T) {
	storage, err := Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	ctx := context.Background()
	if err := storage.CreateAgent(ctx, NewAgent{ID: "agent-1", Name: "first", MachineID: "machine-1", SecretHash: "hash-1"}); err != nil {
		t.Fatal(err)
	}
	for revision := int64(1); revision <= 101; revision++ {
		policy := model.DefaultPolicy()
		policy.Revision = revision
		policy.Global.Rate = 800 + int(revision)
		if _, err := storage.RecordPolicyHistory(ctx, "agent-1", "saved", "admin", "saved", policy); err != nil {
			t.Fatalf("record revision %d: %v", revision, err)
		}
	}
	history, err := storage.ListPolicyHistory(ctx, "agent-1", 100)
	if err != nil || len(history) != 100 {
		t.Fatalf("history length = %d, %v", len(history), err)
	}
	if history[0].Revision != 101 || history[len(history)-1].Revision != 2 {
		t.Fatalf("retained revisions = %d ... %d", history[0].Revision, history[len(history)-1].Revision)
	}
	if _, err := storage.RecordPolicyHistory(ctx, "agent-1", "saved", "admin", "duplicate", history[0].Policy); err == nil {
		t.Fatal("duplicate immutable history revision was accepted")
	}
	if _, err := storage.GetPolicyHistory(ctx, "agent-1", history[0].ID); err != nil {
		t.Fatalf("get policy history: %v", err)
	}
}

func TestAgentTaskLifecycleAndCoalescing(t *testing.T) {
	storage, err := Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	ctx := context.Background()
	if err := storage.CreateAgent(ctx, NewAgent{ID: "agent-1", Name: "first", MachineID: "machine-1", SecretHash: "hash-1"}); err != nil {
		t.Fatal(err)
	}
	first, err := storage.CreateAgentTask(ctx, "agent-1", "ban_sync", map[string]bool{"sync": true})
	if err != nil {
		t.Fatal(err)
	}
	second, err := storage.CreateAgentTask(ctx, "agent-1", "ban_sync", map[string]bool{"sync": true})
	if err != nil {
		t.Fatal(err)
	}
	firstAfter, _, err := storage.GetAgentTask(ctx, first.ID)
	if err != nil || firstAfter.State != "canceled" {
		t.Fatalf("superseded task = %#v, %v", firstAfter, err)
	}
	queued, err := storage.QueuedAgentTasks(ctx, "agent-1", 20)
	if err != nil || len(queued) != 1 || queued[0].ID != second.ID {
		t.Fatalf("queued tasks = %#v, %v", queued, err)
	}
	claimed, payload, err := storage.ClaimAgentTask(ctx, second.ID)
	if err != nil || claimed.State != "running" || claimed.Attempts != 1 || len(payload) == 0 {
		t.Fatalf("claimed task = %#v, %s, %v", claimed, payload, err)
	}
	if err := storage.FinishAgentTask(ctx, second.ID, false, "temporary failure"); err != nil {
		t.Fatal(err)
	}
	if err := storage.RequeueAgentTask(ctx, second.ID, "retry"); err != nil {
		t.Fatal(err)
	}
	if task, _, err := storage.ClaimAgentTask(ctx, second.ID); err != nil || task.Attempts != 2 {
		t.Fatalf("retried task = %#v, %v", task, err)
	}
	if err := storage.FinishAgentTask(ctx, second.ID, true, "done"); err != nil {
		t.Fatal(err)
	}
	completed, _, err := storage.GetAgentTask(ctx, second.ID)
	if err != nil || completed.State != "succeeded" || completed.Message != "done" {
		t.Fatalf("completed task = %#v, %v", completed, err)
	}
}

func TestAgentTaskRecoveryAndAttemptLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "controller.db")
	storage, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := storage.CreateAgent(ctx, NewAgent{ID: "agent-1", Name: "first", MachineID: "machine-1", SecretHash: "hash-1"}); err != nil {
		t.Fatal(err)
	}
	task, err := storage.CreateAgentTask(ctx, "agent-1", "ban_sync", map[string]bool{"sync": true})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := storage.ClaimAgentTask(ctx, task.ID); err != nil {
		t.Fatal(err)
	}
	if err := storage.Close(); err != nil {
		t.Fatal(err)
	}

	storage, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	recovered, _, err := storage.GetAgentTask(ctx, task.ID)
	if err != nil || recovered.State != "queued" || recovered.Message != "主控重启后自动恢复排队" {
		t.Fatalf("recovered task = %#v, %v", recovered, err)
	}

	for attempt := recovered.Attempts + 1; attempt <= model.AgentTaskMaxAttempts; attempt++ {
		claimed, _, err := storage.ClaimAgentTask(ctx, task.ID)
		if err != nil || claimed.Attempts != attempt {
			t.Fatalf("claim attempt %d = %#v, %v", attempt, claimed, err)
		}
		err = storage.RequeueAgentTask(ctx, task.ID, "temporary transport failure")
		if attempt < model.AgentTaskMaxAttempts && err != nil {
			t.Fatalf("requeue attempt %d: %v", attempt, err)
		}
		if attempt == model.AgentTaskMaxAttempts && !errors.Is(err, ErrTaskAttemptsExhausted) {
			t.Fatalf("final requeue error = %v", err)
		}
	}
	exhausted, _, err := storage.GetAgentTask(ctx, task.ID)
	if err != nil || exhausted.State != "failed" || exhausted.Attempts != model.AgentTaskMaxAttempts {
		t.Fatalf("exhausted task = %#v, %v", exhausted, err)
	}
	if err := storage.RequeueAgentTask(ctx, task.ID, "manual retry"); !errors.Is(err, ErrTaskAttemptsExhausted) {
		t.Fatalf("exhausted task retry error = %v", err)
	}
	if err := storage.CancelAgentTask(ctx, task.ID); err != nil {
		t.Fatal(err)
	}
	if err := storage.RequeueAgentTask(ctx, task.ID, "must stay canceled"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("canceled task retry error = %v", err)
	}
}

func TestHistoricalMetricsUpsertAggregateAndRetention(t *testing.T) {
	storage, err := Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	ctx := context.Background()
	if err := storage.CreateAgent(ctx, NewAgent{ID: "agent-1", Name: "first", MachineID: "machine-1", SecretHash: "hash-1"}); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 8, 19, 10, 1, 0, 0, time.UTC)
	write := func(at time.Time, cpu float64, dropped uint64, emergency bool) {
		t.Helper()
		telemetry := model.Telemetry{
			CollectedAt: at.Format(time.RFC3339Nano), CPUUsage: cpu,
			MemoryUsed: 50, MemoryTotal: 100,
			Network:   model.NetworkStats{ReceiveBytesPerSecond: 1000, TransmitBytesPerSecond: 500},
			Sockets:   model.SocketStats{Total: 200, Established: 100, TimeWait: 50, SynRecv: 5},
			Conntrack: 250, ConntrackMax: 1000, DroppedTotal: dropped,
			Adaptive: model.AdaptiveStatus{Emergency: emergency},
		}
		if err := storage.UpdateTelemetry(ctx, "agent-1", telemetry); err != nil {
			t.Fatal(err)
		}
	}
	write(base, 10, 100, false)
	write(base.Add(20*time.Second), 30, 110, false)
	write(base.Add(time.Minute), 50, 110, false)
	write(base.Add(5*time.Minute), 70, 130, true)

	minutePoints, err := storage.ListMetricSamples(ctx, "agent-1", base.Add(-time.Minute), time.Minute)
	if err != nil || len(minutePoints) != 3 {
		t.Fatalf("minute points = %#v, %v", minutePoints, err)
	}
	if minutePoints[0].CPUUsage != 30 {
		t.Fatalf("same-minute sample was not replaced: %#v", minutePoints[0])
	}
	aggregated, err := storage.ListMetricSamples(ctx, "agent-1", base.Add(-time.Minute), 5*time.Minute)
	if err != nil || len(aggregated) != 2 {
		t.Fatalf("aggregated points = %#v, %v", aggregated, err)
	}
	if aggregated[0].CPUUsage != 40 || aggregated[0].MemoryPercent != 50 || aggregated[0].ConntrackPercent != 25 {
		t.Fatalf("first aggregate = %#v", aggregated[0])
	}
	if aggregated[1].DroppedDelta != 20 || !aggregated[1].Emergency {
		t.Fatalf("second aggregate = %#v", aggregated[1])
	}

	write(base.Add(-31*24*time.Hour), 1, 1, false)
	write(time.Date(2026, 8, 19, 11, 0, 0, 0, time.UTC), 80, 140, false)
	retained, err := storage.ListMetricSamples(ctx, "agent-1", base.Add(-32*24*time.Hour), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(retained) != 4 {
		t.Fatalf("retained points = %d, want 4 after old sample cleanup", len(retained))
	}
}
