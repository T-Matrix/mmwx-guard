package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	_ "modernc.org/sqlite"

	"github.com/T-Matrix/mmwx-guard/internal/model"
)

var (
	ErrNotFound              = errors.New("not found")
	ErrTaskAttemptsExhausted = errors.New("task attempts exhausted")
)

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if err := os.Chmod(path+suffix, 0600); err != nil && !errors.Is(err, os.ErrNotExist) {
			db.Close()
			return nil, fmt.Errorf("secure database file %s: %w", path+suffix, err)
		}
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	const schema = `
CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    admin_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS enrollment_tokens (
    token_hash TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT,
	agent_id TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    revision INTEGER NOT NULL,
    config_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS agents (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    machine_id TEXT NOT NULL UNIQUE,
    secret_hash TEXT NOT NULL,
	pending_secret_hash TEXT NOT NULL DEFAULT '',
	pending_secret_expires_at TEXT NOT NULL DEFAULT '',
	credential_rotated_at TEXT NOT NULL DEFAULT '',
	credential_revoked_at TEXT NOT NULL DEFAULT '',
	last_authenticated_at TEXT NOT NULL DEFAULT '',
	controller_key_fingerprint TEXT NOT NULL DEFAULT '',
	controller_verified_at TEXT NOT NULL DEFAULT '',
	secure_channel INTEGER NOT NULL DEFAULT 0,
	connection_transport TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'offline',
    ip_address TEXT NOT NULL DEFAULT '',
	ipv4_address TEXT NOT NULL DEFAULT '',
	ipv6_address TEXT NOT NULL DEFAULT '',
	address_updated_at TEXT NOT NULL DEFAULT '',
    os TEXT NOT NULL DEFAULT '',
    arch TEXT NOT NULL DEFAULT '',
    version TEXT NOT NULL DEFAULT '',
    last_seen TEXT NOT NULL DEFAULT '',
    policy_id INTEGER REFERENCES policies(id) ON DELETE SET NULL,
    policy_revision INTEGER NOT NULL DEFAULT 0,
    telemetry_json TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    level TEXT NOT NULL,
    kind TEXT NOT NULL,
    agent_id TEXT,
    message TEXT NOT NULL,
    data_json TEXT,
    created_at TEXT NOT NULL
);
	CREATE TABLE IF NOT EXISTS ip_bans (
	    id INTEGER PRIMARY KEY AUTOINCREMENT,
	    agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
	    address TEXT NOT NULL,
	    reason TEXT NOT NULL DEFAULT '',
	    expires_at TEXT NOT NULL DEFAULT '',
	    created_at TEXT NOT NULL,
	    applied INTEGER NOT NULL DEFAULT 0,
	    last_error TEXT NOT NULL DEFAULT '',
	    UNIQUE(agent_id, address)
	);
	CREATE TABLE IF NOT EXISTS policy_history (
	    id INTEGER PRIMARY KEY AUTOINCREMENT,
	    agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
	    revision INTEGER NOT NULL,
	    source TEXT NOT NULL,
	    author TEXT NOT NULL,
	    message TEXT NOT NULL DEFAULT '',
	    policy_json TEXT NOT NULL,
	    created_at TEXT NOT NULL,
	    UNIQUE(agent_id, revision)
	);
	CREATE TABLE IF NOT EXISTS agent_tasks (
	    id INTEGER PRIMARY KEY AUTOINCREMENT,
	    agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
	    kind TEXT NOT NULL,
	    state TEXT NOT NULL,
	    payload_json TEXT NOT NULL,
	    message TEXT NOT NULL DEFAULT '',
	    attempts INTEGER NOT NULL DEFAULT 0,
	    created_at TEXT NOT NULL,
	    started_at TEXT NOT NULL DEFAULT '',
	    finished_at TEXT NOT NULL DEFAULT '',
	    updated_at TEXT NOT NULL
	);
	CREATE TABLE IF NOT EXISTS metric_samples (
		agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
		bucket INTEGER NOT NULL,
		cpu_usage REAL NOT NULL,
		memory_used REAL NOT NULL,
		memory_total REAL NOT NULL,
		receive_rate REAL NOT NULL,
		transmit_rate REAL NOT NULL,
		established REAL NOT NULL,
		time_wait REAL NOT NULL,
		syn_recv REAL NOT NULL,
		conntrack REAL NOT NULL,
		conntrack_max REAL NOT NULL,
		dropped_total REAL NOT NULL,
		emergency INTEGER NOT NULL,
		PRIMARY KEY(agent_id, bucket)
	);
	CREATE INDEX IF NOT EXISTS idx_events_created ON events(id DESC);
	CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status);
	CREATE INDEX IF NOT EXISTS idx_ip_bans_agent ON ip_bans(agent_id, id DESC);
	CREATE INDEX IF NOT EXISTS idx_policy_history_agent ON policy_history(agent_id, id DESC);
	CREATE INDEX IF NOT EXISTS idx_agent_tasks_agent_state ON agent_tasks(agent_id, state, id);
	CREATE INDEX IF NOT EXISTS idx_metric_samples_bucket ON metric_samples(bucket);
	CREATE TRIGGER IF NOT EXISTS trim_events AFTER INSERT ON events
	WHEN NEW.id % 100 = 0
	BEGIN
	    DELETE FROM events WHERE id < NEW.id - 10000;
	END;
	CREATE TRIGGER IF NOT EXISTS trim_metric_samples AFTER INSERT ON metric_samples
	WHEN NEW.bucket % 3600 = 0
	BEGIN
		DELETE FROM metric_samples WHERE bucket < NEW.bucket - 2592000;
	END;
	`
	if _, err := s.db.Exec(schema); err != nil {
		return err
	}
	columns := []struct {
		table, name, definition string
	}{
		{"enrollment_tokens", "agent_id", "TEXT NOT NULL DEFAULT ''"},
		{"agents", "pending_secret_hash", "TEXT NOT NULL DEFAULT ''"},
		{"agents", "pending_secret_expires_at", "TEXT NOT NULL DEFAULT ''"},
		{"agents", "credential_rotated_at", "TEXT NOT NULL DEFAULT ''"},
		{"agents", "credential_revoked_at", "TEXT NOT NULL DEFAULT ''"},
		{"agents", "last_authenticated_at", "TEXT NOT NULL DEFAULT ''"},
		{"agents", "controller_key_fingerprint", "TEXT NOT NULL DEFAULT ''"},
		{"agents", "controller_verified_at", "TEXT NOT NULL DEFAULT ''"},
		{"agents", "secure_channel", "INTEGER NOT NULL DEFAULT 0"},
		{"agents", "connection_transport", "TEXT NOT NULL DEFAULT ''"},
		{"agents", "ipv4_address", "TEXT NOT NULL DEFAULT ''"},
		{"agents", "ipv6_address", "TEXT NOT NULL DEFAULT ''"},
		{"agents", "address_updated_at", "TEXT NOT NULL DEFAULT ''"},
	}
	for _, column := range columns {
		if err := s.ensureColumn(column.table, column.name, column.definition); err != nil {
			return err
		}
	}
	stamp := now()
	if _, err := s.db.Exec(`UPDATE agent_tasks
		SET state=CASE WHEN attempts>=? THEN 'failed' ELSE 'queued' END,
			message=CASE WHEN attempts>=? THEN '任务已达到最大尝试次数' ELSE '主控重启后自动恢复排队' END,
			started_at=CASE WHEN attempts>=? THEN started_at ELSE '' END,
			finished_at=CASE WHEN attempts>=? THEN ? ELSE '' END,
			updated_at=?
		WHERE state='running'`, model.AgentTaskMaxAttempts, model.AgentTaskMaxAttempts, model.AgentTaskMaxAttempts, model.AgentTaskMaxAttempts, stamp, stamp); err != nil {
		return err
	}
	return nil
}

func (s *Store) ensureColumn(table, name, definition string) error {
	rows, err := s.db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return err
	}
	found := false
	for rows.Next() {
		var cid int
		var columnName, columnType string
		var notNull, primaryKey int
		var defaultValue sql.NullString
		if err := rows.Scan(&cid, &columnName, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			rows.Close()
			return err
		}
		if columnName == name {
			found = true
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if found {
		return nil
	}
	_, err = s.db.Exec(`ALTER TABLE ` + table + ` ADD COLUMN ` + name + ` ` + definition)
	return err
}

func now() string { return time.Now().UTC().Format(time.RFC3339Nano) }

func (s *Store) HasAdmin(ctx context.Context) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM admins`).Scan(&count)
	return count > 0, err
}

func (s *Store) CreateAdmin(ctx context.Context, username, passwordHash string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO admins(username,password_hash,created_at) VALUES(?,?,?)`, username, passwordHash, now())
	return err
}

func (s *Store) AdminPasswordHash(ctx context.Context, username string) (int64, string, error) {
	var id int64
	var hash string
	if err := s.db.QueryRowContext(ctx, `SELECT id,password_hash FROM admins WHERE username=?`, username).Scan(&id, &hash); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, "", ErrNotFound
		}
		return 0, "", err
	}
	return id, hash, nil
}

func (s *Store) CreateSession(ctx context.Context, tokenHash string, adminID int64, expires time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO sessions(token_hash,admin_id,expires_at,created_at) VALUES(?,?,?,?)`, tokenHash, adminID, expires.UTC().Format(time.RFC3339Nano), now())
	return err
}

func (s *Store) SessionAdmin(ctx context.Context, tokenHash string) (string, error) {
	var username string
	err := s.db.QueryRowContext(ctx, `SELECT a.username FROM sessions s JOIN admins a ON a.id=s.admin_id WHERE s.token_hash=? AND s.expires_at>?`, tokenHash, now()).Scan(&username)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return username, err
}

func (s *Store) DeleteSession(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash=?`, tokenHash)
	return err
}

func (s *Store) ChangeAdminPassword(ctx context.Context, username, passwordHash, sessionHash string, expires time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var adminID int64
	if err := tx.QueryRowContext(ctx, `SELECT id FROM admins WHERE username=?`, username).Scan(&adminID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE admins SET password_hash=? WHERE id=?`, passwordHash, adminID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE admin_id=?`, adminID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO sessions(token_hash,admin_id,expires_at,created_at) VALUES(?,?,?,?)`, sessionHash, adminID, expires.UTC().Format(time.RFC3339Nano), now()); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) CreateEnrollment(ctx context.Context, tokenHash, label, agentID string, expires time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO enrollment_tokens(token_hash,label,agent_id,expires_at,created_at) VALUES(?,?,?,?,?)`, tokenHash, label, agentID, expires.UTC().Format(time.RFC3339Nano), now())
	return err
}

type Enrollment struct {
	Label   string
	AgentID string
}

func (s *Store) Enrollment(ctx context.Context, tokenHash string) (Enrollment, error) {
	var enrollment Enrollment
	err := s.db.QueryRowContext(ctx, `SELECT label,agent_id FROM enrollment_tokens WHERE token_hash=? AND used_at IS NULL AND expires_at>?`, tokenHash, now()).Scan(&enrollment.Label, &enrollment.AgentID)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return enrollment, err
}

func (s *Store) ConsumeEnrollment(ctx context.Context, tokenHash string) (Enrollment, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Enrollment{}, err
	}
	defer tx.Rollback()
	var enrollment Enrollment
	if err := tx.QueryRowContext(ctx, `SELECT label,agent_id FROM enrollment_tokens WHERE token_hash=? AND used_at IS NULL AND expires_at>?`, tokenHash, now()).Scan(&enrollment.Label, &enrollment.AgentID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Enrollment{}, ErrNotFound
		}
		return Enrollment{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE enrollment_tokens SET used_at=? WHERE token_hash=?`, now(), tokenHash); err != nil {
		return Enrollment{}, err
	}
	return enrollment, tx.Commit()
}

type NewAgent struct {
	ID, Name, MachineID, SecretHash, OS, Arch, Version, IPAddress string
}

func (s *Store) CreateAgent(ctx context.Context, a NewAgent) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO agents(id,name,machine_id,secret_hash,status,ip_address,os,arch,version,last_seen,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		a.ID, a.Name, a.MachineID, a.SecretHash, "offline", a.IPAddress, a.OS, a.Arch, a.Version, now(), now())
	return err
}

func (s *Store) AgentSecretHash(ctx context.Context, id string) (string, error) {
	var hash string
	err := s.db.QueryRowContext(ctx, `SELECT secret_hash FROM agents WHERE id=?`, id).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return hash, err
}

func (s *Store) AgentName(ctx context.Context, id string) (string, error) {
	var name string
	err := s.db.QueryRowContext(ctx, `SELECT name FROM agents WHERE id=?`, id).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return name, err
}

func (s *Store) AgentNameByMachineID(ctx context.Context, machineID string) (string, error) {
	var name string
	err := s.db.QueryRowContext(ctx, `SELECT name FROM agents WHERE machine_id=?`, machineID).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return name, err
}

type AgentCredentials struct {
	SecretHash           string
	PendingSecretHash    string
	PendingSecretExpires string
	MachineID            string
	RevokedAt            string
}

func (s *Store) AgentCredentials(ctx context.Context, id string) (credentials AgentCredentials, err error) {
	err = s.db.QueryRowContext(ctx, `SELECT secret_hash,pending_secret_hash,pending_secret_expires_at,machine_id,credential_revoked_at FROM agents WHERE id=?`, id).Scan(
		&credentials.SecretHash, &credentials.PendingSecretHash, &credentials.PendingSecretExpires, &credentials.MachineID, &credentials.RevokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return
}

func (s *Store) SetAgentConnected(ctx context.Context, id, ip, osName, arch, version, transport string, secure bool) error {
	_, err := s.db.ExecContext(ctx, `UPDATE agents SET status='online',ip_address=?,os=?,arch=?,version=?,last_seen=?,last_authenticated_at=?,secure_channel=?,connection_transport=?,controller_key_fingerprint='',controller_verified_at='' WHERE id=?`, ip, osName, arch, version, now(), now(), secure, transport, id)
	return err
}

func (s *Store) SetAgentPublicAddresses(ctx context.Context, id, ipv4, ipv6 string) error {
	result, err := s.db.ExecContext(ctx, `UPDATE agents SET
		ipv4_address=CASE WHEN ?<>'' THEN ? ELSE ipv4_address END,
		ipv6_address=CASE WHEN ?<>'' THEN ? ELSE ipv6_address END,
		address_updated_at=? WHERE id=?`, ipv4, ipv4, ipv6, ipv6, now(), id)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) MarkControllerVerified(ctx context.Context, id, fingerprint string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE agents SET controller_key_fingerprint=?,controller_verified_at=? WHERE id=?`, fingerprint, now(), id)
	return err
}

func (s *Store) BeginCredentialRotation(ctx context.Context, id, pendingHash string, expires time.Time) error {
	currentTime := now()
	res, err := s.db.ExecContext(ctx, `UPDATE agents SET pending_secret_hash=?,pending_secret_expires_at=? WHERE id=? AND credential_revoked_at='' AND (pending_secret_hash='' OR pending_secret_expires_at='' OR pending_secret_expires_at<=?)`, pendingHash, expires.UTC().Format(time.RFC3339Nano), id, currentTime)
	if err != nil {
		return err
	}
	if count, _ := res.RowsAffected(); count == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) ClearCredentialRotation(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE agents SET pending_secret_hash='',pending_secret_expires_at='' WHERE id=?`, id)
	return err
}

func (s *Store) PromoteCredential(ctx context.Context, id, pendingHash string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE agents SET secret_hash=pending_secret_hash,pending_secret_hash='',pending_secret_expires_at='',credential_rotated_at=?,credential_revoked_at='' WHERE id=? AND pending_secret_hash=? AND pending_secret_expires_at>?`, now(), id, pendingHash, now())
	if err != nil {
		return err
	}
	if count, _ := res.RowsAffected(); count == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) RevokeAgentCredential(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE agents SET credential_revoked_at=?,pending_secret_hash='',pending_secret_expires_at='',status='offline',secure_channel=0 WHERE id=?`, now(), id)
	if err != nil {
		return err
	}
	if count, _ := res.RowsAffected(); count == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) PrepareAgentReenrollment(ctx context.Context, id, machineID, pendingHash, osName, arch, version, ip string, expires time.Time) error {
	res, err := s.db.ExecContext(ctx, `UPDATE agents SET pending_secret_hash=?,pending_secret_expires_at=?,status='offline',secure_channel=0,os=?,arch=?,version=?,ip_address=?,last_seen=? WHERE id=? AND machine_id=?`, pendingHash, expires.UTC().Format(time.RFC3339Nano), osName, arch, version, ip, now(), id, machineID)
	if err != nil {
		return err
	}
	if count, _ := res.RowsAffected(); count == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) TouchAgent(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE agents SET status='online',last_seen=? WHERE id=?`, now(), id)
	return err
}

func (s *Store) SetAgentOffline(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE agents SET status='offline',secure_channel=0 WHERE id=?`, id)
	return err
}

func (s *Store) UpdateTelemetry(ctx context.Context, id string, telemetry model.Telemetry) error {
	raw, err := json.Marshal(telemetry)
	if err != nil {
		return err
	}
	collectedAt, err := time.Parse(time.RFC3339Nano, telemetry.CollectedAt)
	if err != nil {
		collectedAt = time.Now()
	}
	bucket := collectedAt.UTC().Truncate(time.Minute).Unix()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE agents SET telemetry_json=?,last_seen=?,status='online',policy_revision=? WHERE id=?`, string(raw), now(), telemetry.PolicyRevision, id)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return ErrNotFound
	}
	emergency := 0
	if telemetry.Adaptive.Emergency {
		emergency = 1
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO metric_samples(
		agent_id,bucket,cpu_usage,memory_used,memory_total,receive_rate,transmit_rate,established,time_wait,syn_recv,conntrack,conntrack_max,dropped_total,emergency
	) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(agent_id,bucket) DO UPDATE SET
		cpu_usage=excluded.cpu_usage,memory_used=excluded.memory_used,memory_total=excluded.memory_total,
		receive_rate=excluded.receive_rate,transmit_rate=excluded.transmit_rate,established=excluded.established,
		time_wait=excluded.time_wait,syn_recv=excluded.syn_recv,conntrack=excluded.conntrack,
		conntrack_max=excluded.conntrack_max,dropped_total=excluded.dropped_total,emergency=excluded.emergency`,
		id, bucket, telemetry.CPUUsage, float64(telemetry.MemoryUsed), float64(telemetry.MemoryTotal),
		float64(telemetry.Network.ReceiveBytesPerSecond), float64(telemetry.Network.TransmitBytesPerSecond),
		telemetry.Sockets.Established, telemetry.Sockets.TimeWait, telemetry.Sockets.SynRecv,
		float64(telemetry.Conntrack), float64(telemetry.ConntrackMax), float64(telemetry.DroppedTotal), emergency)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ListMetricSamples(ctx context.Context, agentID string, since time.Time, step time.Duration) ([]model.MetricPoint, error) {
	stepSeconds := int64(step / time.Second)
	if stepSeconds < 60 || stepSeconds > int64(24*time.Hour/time.Second) {
		return nil, errors.New("invalid metric aggregation step")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT
		(bucket / ?) * ?,
		AVG(cpu_usage),
		AVG(CASE WHEN memory_total>0 THEN memory_used*100.0/memory_total ELSE 0 END),
		AVG(receive_rate),AVG(transmit_rate),AVG(established),AVG(time_wait),AVG(syn_recv),AVG(conntrack),
		AVG(CASE WHEN conntrack_max>0 THEN conntrack*100.0/conntrack_max ELSE 0 END),
		MAX(dropped_total),MAX(emergency)
		FROM metric_samples WHERE agent_id=? AND bucket>=?
		GROUP BY (bucket / ?) ORDER BY (bucket / ?) LIMIT 1000`,
		stepSeconds, stepSeconds, agentID, since.UTC().Unix(), stepSeconds, stepSeconds)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	points := make([]model.MetricPoint, 0)
	var previousDropped uint64
	for rows.Next() {
		var timestamp int64
		var cpu, memory, receive, transmit, established, timeWait, synRecv, conntrack, conntrackPercent, dropped float64
		var emergency int
		if err := rows.Scan(&timestamp, &cpu, &memory, &receive, &transmit, &established, &timeWait, &synRecv, &conntrack, &conntrackPercent, &dropped, &emergency); err != nil {
			return nil, err
		}
		point := model.MetricPoint{
			Timestamp: time.Unix(timestamp, 0).UTC().Format(time.RFC3339), CPUUsage: cpu, MemoryPercent: memory,
			ReceiveRate: roundedUint64(receive), TransmitRate: roundedUint64(transmit),
			Established: int(established + 0.5), TimeWait: int(timeWait + 0.5), SynRecv: int(synRecv + 0.5),
			Conntrack: roundedUint64(conntrack), ConntrackPercent: conntrackPercent,
			DroppedTotal: roundedUint64(dropped), Emergency: emergency != 0,
		}
		if len(points) > 0 {
			if point.DroppedTotal >= previousDropped {
				point.DroppedDelta = point.DroppedTotal - previousDropped
			} else {
				point.DroppedDelta = point.DroppedTotal
			}
		}
		previousDropped = point.DroppedTotal
		points = append(points, point)
	}
	return points, rows.Err()
}

func roundedUint64(value float64) uint64 {
	if value <= 0 {
		return 0
	}
	return uint64(value + 0.5)
}

func (s *Store) ListAgents(ctx context.Context) ([]model.AgentSummary, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT a.id,a.name,a.status,a.ip_address,a.ipv4_address,a.ipv6_address,a.address_updated_at,a.os,a.arch,a.version,a.last_seen,COALESCE(a.policy_id,0),COALESCE(p.name,''),a.policy_revision,a.telemetry_json,a.pending_secret_hash,a.pending_secret_expires_at,a.credential_rotated_at,a.credential_revoked_at,a.last_authenticated_at,a.controller_key_fingerprint,a.controller_verified_at,a.secure_channel,a.connection_transport FROM agents a LEFT JOIN policies p ON p.id=a.policy_id ORDER BY a.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.AgentSummary
	for rows.Next() {
		var a model.AgentSummary
		var telemetry sql.NullString
		var pendingHash, pendingExpires string
		if err := rows.Scan(&a.ID, &a.Name, &a.Status, &a.IPAddress, &a.IPv4Address, &a.IPv6Address, &a.AddressUpdatedAt, &a.OS, &a.Arch, &a.Version, &a.LastSeen, &a.PolicyID, &a.PolicyName, &a.PolicyRevision, &telemetry, &pendingHash, &pendingExpires, &a.CredentialRotatedAt, &a.CredentialRevokedAt, &a.LastAuthenticatedAt, &a.ControllerKeyFingerprint, &a.ControllerVerifiedAt, &a.SecureChannel, &a.ConnectionTransport); err != nil {
			return nil, err
		}
		a.CredentialState = "active"
		if a.CredentialRevokedAt != "" {
			a.CredentialState = "revoked"
		} else if expires, parseErr := time.Parse(time.RFC3339Nano, pendingExpires); pendingHash != "" && parseErr == nil && expires.After(time.Now()) {
			a.CredentialState = "rotation_pending"
		}
		if telemetry.Valid && telemetry.String != "" {
			var value model.Telemetry
			if json.Unmarshal([]byte(telemetry.String), &value) == nil {
				a.Telemetry = &value
			}
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) SavePolicy(ctx context.Context, p model.Policy) (model.Policy, error) {
	p.Normalize()
	if err := p.Validate(); err != nil {
		return model.Policy{}, err
	}
	stamp := now()
	if p.ID == 0 {
		raw, _ := json.Marshal(p)
		res, err := s.db.ExecContext(ctx, `INSERT INTO policies(name,revision,config_json,created_at,updated_at) VALUES(?,?,?,?,?)`, p.Name, p.Revision, string(raw), stamp, stamp)
		if err != nil {
			return model.Policy{}, err
		}
		p.ID, _ = res.LastInsertId()
		p.UpdatedAt = stamp
		raw, _ = json.Marshal(p)
		_, err = s.db.ExecContext(ctx, `UPDATE policies SET config_json=? WHERE id=?`, string(raw), p.ID)
		return p, err
	}
	current, err := s.GetPolicy(ctx, p.ID)
	if err != nil {
		return model.Policy{}, err
	}
	p.Revision = current.Revision + 1
	p.UpdatedAt = stamp
	raw, _ := json.Marshal(p)
	_, err = s.db.ExecContext(ctx, `UPDATE policies SET name=?,revision=?,config_json=?,updated_at=? WHERE id=?`, p.Name, p.Revision, string(raw), stamp, p.ID)
	return p, err
}

func (s *Store) EnsureDefaultPolicy(ctx context.Context) error {
	var count int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM policies`).Scan(&count); err != nil || count > 0 {
		return err
	}
	_, err := s.SavePolicy(ctx, model.DefaultPolicy())
	return err
}

func (s *Store) GetPolicy(ctx context.Context, id int64) (model.Policy, error) {
	var raw string
	if err := s.db.QueryRowContext(ctx, `SELECT config_json FROM policies WHERE id=?`, id).Scan(&raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.Policy{}, ErrNotFound
		}
		return model.Policy{}, err
	}
	var p model.Policy
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return model.Policy{}, err
	}
	p.Normalize()
	return p, nil
}

func (s *Store) ListPolicies(ctx context.Context) ([]model.Policy, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT config_json FROM policies ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Policy
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var p model.Policy
		if err := json.Unmarshal([]byte(raw), &p); err != nil {
			return nil, err
		}
		p.Normalize()
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) AssignPolicy(ctx context.Context, agentID string, policyID, revision int64) error {
	res, err := s.db.ExecContext(ctx, `UPDATE agents SET policy_id=?,policy_revision=? WHERE id=?`, policyID, revision, agentID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) AgentPolicy(ctx context.Context, agentID string) (model.Policy, error) {
	var policyID sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `SELECT policy_id FROM agents WHERE id=?`, agentID).Scan(&policyID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.Policy{}, ErrNotFound
		}
		return model.Policy{}, err
	}
	if !policyID.Valid || policyID.Int64 == 0 {
		return model.Policy{}, ErrNotFound
	}
	return s.GetPolicy(ctx, policyID.Int64)
}

func (s *Store) AgentExists(ctx context.Context, agentID string) (bool, error) {
	var exists int
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM agents WHERE id=?)`, agentID).Scan(&exists)
	return exists == 1, err
}

func (s *Store) DeletePolicyIfUnassigned(ctx context.Context, policyID int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM policies WHERE id=? AND NOT EXISTS(SELECT 1 FROM agents WHERE policy_id=?)`, policyID, policyID)
	return err
}

func (s *Store) DeleteAgent(ctx context.Context, agentID string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM agents WHERE id=?`, agentID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) RenameAgent(ctx context.Context, agentID, name string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE agents SET name=? WHERE id=?`, name, agentID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) SaveIPBan(ctx context.Context, agentID, address, reason string, expiresAt time.Time) (model.IPBan, error) {
	expires := ""
	if !expiresAt.IsZero() {
		expires = expiresAt.UTC().Format(time.RFC3339Nano)
	}
	stamp := now()
	_, err := s.db.ExecContext(ctx, `INSERT INTO ip_bans(agent_id,address,reason,expires_at,created_at,applied,last_error)
		VALUES(?,?,?,?,?,0,'') ON CONFLICT(agent_id,address) DO UPDATE SET reason=excluded.reason,expires_at=excluded.expires_at,created_at=excluded.created_at,applied=0,last_error=''`, agentID, address, reason, expires, stamp)
	if err != nil {
		return model.IPBan{}, err
	}
	return s.GetIPBan(ctx, agentID, address)
}

func (s *Store) GetIPBan(ctx context.Context, agentID, address string) (model.IPBan, error) {
	var ban model.IPBan
	var applied int
	err := s.db.QueryRowContext(ctx, `SELECT id,agent_id,address,reason,expires_at,created_at,applied,last_error FROM ip_bans WHERE agent_id=? AND address=?`, agentID, address).Scan(&ban.ID, &ban.AgentID, &ban.Address, &ban.Reason, &ban.ExpiresAt, &ban.CreatedAt, &applied, &ban.LastError)
	ban.Applied = applied != 0
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return ban, err
}

func (s *Store) ListIPBans(ctx context.Context, agentID string) ([]model.IPBan, error) {
	_, _ = s.db.ExecContext(ctx, `DELETE FROM ip_bans WHERE agent_id=? AND expires_at<>'' AND expires_at<=?`, agentID, now())
	rows, err := s.db.QueryContext(ctx, `SELECT id,agent_id,address,reason,expires_at,created_at,applied,last_error FROM ip_bans WHERE agent_id=? ORDER BY CASE WHEN expires_at='' THEN 0 ELSE 1 END,id DESC`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	bans := make([]model.IPBan, 0)
	for rows.Next() {
		var ban model.IPBan
		var applied int
		if err := rows.Scan(&ban.ID, &ban.AgentID, &ban.Address, &ban.Reason, &ban.ExpiresAt, &ban.CreatedAt, &applied, &ban.LastError); err != nil {
			return nil, err
		}
		ban.Applied = applied != 0
		bans = append(bans, ban)
	}
	return bans, rows.Err()
}

func (s *Store) DeleteIPBan(ctx context.Context, agentID string, banID int64) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM ip_bans WHERE id=? AND agent_id=?`, banID, agentID)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) SetIPBansApplyState(ctx context.Context, agentID string, applied bool, lastError string) error {
	if len(lastError) > 2048 {
		lastError = lastError[:2048]
	}
	_, err := s.db.ExecContext(ctx, `UPDATE ip_bans SET applied=?,last_error=? WHERE agent_id=?`, applied, lastError, agentID)
	return err
}

func (s *Store) RecordPolicyHistory(ctx context.Context, agentID, source, author, message string, policy model.Policy) (model.PolicyHistory, error) {
	policy.Normalize()
	if err := policy.Validate(); err != nil {
		return model.PolicyHistory{}, err
	}
	if source != "saved" && source != "restored" {
		return model.PolicyHistory{}, errors.New("invalid policy history source")
	}
	if len(author) > 80 || len(message) > 2048 {
		return model.PolicyHistory{}, errors.New("policy history metadata is too long")
	}
	raw, err := json.Marshal(policy)
	if err != nil {
		return model.PolicyHistory{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return model.PolicyHistory{}, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `INSERT INTO policy_history(agent_id,revision,source,author,message,policy_json,created_at) VALUES(?,?,?,?,?,?,?)`, agentID, policy.Revision, source, author, message, string(raw), now())
	if err != nil {
		return model.PolicyHistory{}, err
	}
	id, _ := result.LastInsertId()
	if _, err := tx.ExecContext(ctx, `DELETE FROM policy_history WHERE agent_id=? AND id NOT IN (SELECT id FROM policy_history WHERE agent_id=? ORDER BY id DESC LIMIT 100)`, agentID, agentID); err != nil {
		return model.PolicyHistory{}, err
	}
	if err := tx.Commit(); err != nil {
		return model.PolicyHistory{}, err
	}
	return s.GetPolicyHistory(ctx, agentID, id)
}

func (s *Store) GetPolicyHistory(ctx context.Context, agentID string, historyID int64) (model.PolicyHistory, error) {
	var history model.PolicyHistory
	var raw string
	err := s.db.QueryRowContext(ctx, `SELECT id,agent_id,revision,source,author,message,policy_json,created_at FROM policy_history WHERE id=? AND agent_id=?`, historyID, agentID).Scan(&history.ID, &history.AgentID, &history.Revision, &history.Source, &history.Author, &history.Message, &raw, &history.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.PolicyHistory{}, ErrNotFound
	}
	if err != nil {
		return model.PolicyHistory{}, err
	}
	if err := json.Unmarshal([]byte(raw), &history.Policy); err != nil {
		return model.PolicyHistory{}, err
	}
	history.Policy.Normalize()
	return history, nil
}

func (s *Store) ListPolicyHistory(ctx context.Context, agentID string, limit int) ([]model.PolicyHistory, error) {
	if limit < 1 || limit > 100 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,agent_id,revision,source,author,message,policy_json,created_at FROM policy_history WHERE agent_id=? ORDER BY id DESC LIMIT ?`, agentID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	history := make([]model.PolicyHistory, 0)
	for rows.Next() {
		var item model.PolicyHistory
		var raw string
		if err := rows.Scan(&item.ID, &item.AgentID, &item.Revision, &item.Source, &item.Author, &item.Message, &raw, &item.CreatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(raw), &item.Policy); err != nil {
			return nil, err
		}
		item.Policy.Normalize()
		history = append(history, item)
	}
	return history, rows.Err()
}

func (s *Store) CreateAgentTask(ctx context.Context, agentID, kind string, payload any) (model.AgentTask, error) {
	if kind != "policy_deploy" && kind != "ban_sync" {
		return model.AgentTask{}, errors.New("invalid Agent task kind")
	}
	raw, err := json.Marshal(payload)
	if err != nil || len(raw) > 64<<10 {
		return model.AgentTask{}, errors.New("Agent task payload is invalid")
	}
	stamp := now()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return model.AgentTask{}, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE agent_tasks SET state='canceled',message='已由较新的同类任务取代',finished_at=?,updated_at=? WHERE agent_id=? AND kind=? AND state='queued'`, stamp, stamp, agentID, kind); err != nil {
		return model.AgentTask{}, err
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO agent_tasks(agent_id,kind,state,payload_json,created_at,updated_at) VALUES(?,?,'queued',?,?,?)`, agentID, kind, string(raw), stamp, stamp)
	if err != nil {
		return model.AgentTask{}, err
	}
	id, _ := result.LastInsertId()
	if _, err := tx.ExecContext(ctx, `DELETE FROM agent_tasks WHERE id NOT IN (SELECT id FROM agent_tasks ORDER BY id DESC LIMIT 5000)`); err != nil {
		return model.AgentTask{}, err
	}
	if err := tx.Commit(); err != nil {
		return model.AgentTask{}, err
	}
	task, _, err := s.GetAgentTask(ctx, id)
	return task, err
}

func (s *Store) GetAgentTask(ctx context.Context, taskID int64) (model.AgentTask, json.RawMessage, error) {
	var task model.AgentTask
	var raw string
	err := s.db.QueryRowContext(ctx, `SELECT id,agent_id,kind,state,payload_json,message,attempts,created_at,started_at,finished_at,updated_at FROM agent_tasks WHERE id=?`, taskID).Scan(&task.ID, &task.AgentID, &task.Kind, &task.State, &raw, &task.Message, &task.Attempts, &task.CreatedAt, &task.StartedAt, &task.FinishedAt, &task.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return task, json.RawMessage(raw), err
}

func (s *Store) ListAgentTasks(ctx context.Context, limit int) ([]model.AgentTask, error) {
	if limit < 1 || limit > 500 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,agent_id,kind,state,message,attempts,created_at,started_at,finished_at,updated_at FROM agent_tasks ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	tasks := make([]model.AgentTask, 0)
	for rows.Next() {
		var task model.AgentTask
		if err := rows.Scan(&task.ID, &task.AgentID, &task.Kind, &task.State, &task.Message, &task.Attempts, &task.CreatedAt, &task.StartedAt, &task.FinishedAt, &task.UpdatedAt); err != nil {
			return nil, err
		}
		tasks = append(tasks, task)
	}
	return tasks, rows.Err()
}

func (s *Store) ListAgentTasksForAgent(ctx context.Context, agentID string, limit int) ([]model.AgentTask, error) {
	if limit < 1 || limit > 200 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,agent_id,kind,state,message,attempts,created_at,started_at,finished_at,updated_at FROM agent_tasks WHERE agent_id=? ORDER BY id DESC LIMIT ?`, agentID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	tasks := make([]model.AgentTask, 0)
	for rows.Next() {
		var task model.AgentTask
		if err := rows.Scan(&task.ID, &task.AgentID, &task.Kind, &task.State, &task.Message, &task.Attempts, &task.CreatedAt, &task.StartedAt, &task.FinishedAt, &task.UpdatedAt); err != nil {
			return nil, err
		}
		tasks = append(tasks, task)
	}
	return tasks, rows.Err()
}

func (s *Store) QueuedAgentTasks(ctx context.Context, agentID string, limit int) ([]model.AgentTask, error) {
	if limit < 1 || limit > 100 {
		limit = 20
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,agent_id,kind,state,message,attempts,created_at,started_at,finished_at,updated_at FROM agent_tasks WHERE agent_id=? AND state='queued' ORDER BY id LIMIT ?`, agentID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	tasks := make([]model.AgentTask, 0)
	for rows.Next() {
		var task model.AgentTask
		if err := rows.Scan(&task.ID, &task.AgentID, &task.Kind, &task.State, &task.Message, &task.Attempts, &task.CreatedAt, &task.StartedAt, &task.FinishedAt, &task.UpdatedAt); err != nil {
			return nil, err
		}
		tasks = append(tasks, task)
	}
	return tasks, rows.Err()
}

func (s *Store) ClaimAgentTask(ctx context.Context, taskID int64) (model.AgentTask, json.RawMessage, error) {
	stamp := now()
	result, err := s.db.ExecContext(ctx, `UPDATE agent_tasks SET state='running',attempts=attempts+1,started_at=?,finished_at='',updated_at=? WHERE id=? AND state='queued' AND attempts<?`, stamp, stamp, taskID, model.AgentTaskMaxAttempts)
	if err != nil {
		return model.AgentTask{}, nil, err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return model.AgentTask{}, nil, ErrNotFound
	}
	return s.GetAgentTask(ctx, taskID)
}

func (s *Store) FinishAgentTask(ctx context.Context, taskID int64, success bool, message string) error {
	state := "failed"
	if success {
		state = "succeeded"
	}
	if len(message) > 2048 {
		message = message[:2048]
	}
	stamp := now()
	result, err := s.db.ExecContext(ctx, `UPDATE agent_tasks SET state=?,message=?,finished_at=?,updated_at=? WHERE id=? AND state='running'`, state, message, stamp, stamp, taskID)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) RequeueAgentTask(ctx context.Context, taskID int64, message string) error {
	if len(message) > 2048 {
		message = message[:2048]
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var state string
	var attempts int
	if err := tx.QueryRowContext(ctx, `SELECT state,attempts FROM agent_tasks WHERE id=?`, taskID).Scan(&state, &attempts); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	if state != "running" && state != "failed" {
		return ErrNotFound
	}
	stamp := now()
	if attempts >= model.AgentTaskMaxAttempts {
		if state == "running" {
			if _, err := tx.ExecContext(ctx, `UPDATE agent_tasks SET state='failed',message='任务已达到最大尝试次数',finished_at=?,updated_at=? WHERE id=?`, stamp, stamp, taskID); err != nil {
				return err
			}
			if err := tx.Commit(); err != nil {
				return err
			}
		}
		return ErrTaskAttemptsExhausted
	}
	if _, err := tx.ExecContext(ctx, `UPDATE agent_tasks SET state='queued',message=?,started_at='',finished_at='',updated_at=? WHERE id=?`, message, stamp, taskID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) CancelAgentTask(ctx context.Context, taskID int64) error {
	stamp := now()
	result, err := s.db.ExecContext(ctx, `UPDATE agent_tasks SET state='canceled',message='管理员已取消',finished_at=?,updated_at=? WHERE id=? AND state IN ('queued','failed')`, stamp, stamp, taskID)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return ErrNotFound
	}
	return nil
}

type Event struct {
	ID        int64           `json:"id"`
	Level     string          `json:"level"`
	Kind      string          `json:"kind"`
	AgentID   string          `json:"agent_id,omitempty"`
	Message   string          `json:"message"`
	Data      json.RawMessage `json:"data,omitempty"`
	CreatedAt string          `json:"created_at"`
}

func (s *Store) AddEvent(ctx context.Context, level, kind, agentID, message string, data any) error {
	if len(message) > 4096 {
		message = message[:4096]
	}
	var raw []byte
	if data != nil {
		raw, _ = json.Marshal(data)
		if len(raw) > 64<<10 {
			raw = []byte(`{"truncated":true}`)
		}
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO events(level,kind,agent_id,message,data_json,created_at) VALUES(?,?,?,?,?,?)`, level, kind, agentID, message, string(raw), now())
	return err
}

func (s *Store) ListEvents(ctx context.Context, limit int) ([]Event, error) {
	if limit < 1 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,level,kind,COALESCE(agent_id,''),message,COALESCE(data_json,''),created_at FROM events ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		var raw string
		if err := rows.Scan(&e.ID, &e.Level, &e.Kind, &e.AgentID, &e.Message, &raw, &e.CreatedAt); err != nil {
			return nil, err
		}
		if raw != "" {
			e.Data = json.RawMessage(raw)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) ListEventsForAgent(ctx context.Context, agentID string, limit int) ([]Event, error) {
	if limit < 1 || limit > 200 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,level,kind,COALESCE(agent_id,''),message,created_at FROM events WHERE agent_id=? ORDER BY id DESC LIMIT ?`, agentID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events := make([]Event, 0)
	for rows.Next() {
		var event Event
		if err := rows.Scan(&event.ID, &event.Level, &event.Kind, &event.AgentID, &event.Message, &event.CreatedAt); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func (s *Store) Summary(ctx context.Context) (map[string]any, error) {
	agents, err := s.ListAgents(ctx)
	if err != nil {
		return nil, err
	}
	result := map[string]any{"agents_total": len(agents), "agents_online": 0, "sockets": 0, "established": 0, "time_wait": 0, "conntrack": uint64(0), "dropped": uint64(0), "protected": 0}
	for _, a := range agents {
		if a.Status == "online" {
			result["agents_online"] = result["agents_online"].(int) + 1
		}
		if a.Telemetry != nil {
			result["sockets"] = result["sockets"].(int) + a.Telemetry.Sockets.Total
			result["established"] = result["established"].(int) + a.Telemetry.Sockets.Established
			result["time_wait"] = result["time_wait"].(int) + a.Telemetry.Sockets.TimeWait
			result["conntrack"] = result["conntrack"].(uint64) + a.Telemetry.Conntrack
			result["dropped"] = result["dropped"].(uint64) + a.Telemetry.DroppedTotal
			if a.Telemetry.Protected {
				result["protected"] = result["protected"].(int) + 1
			}
		}
	}
	return result, nil
}

func (s *Store) DebugCounts(ctx context.Context) (string, error) {
	var agents, policies, events int
	if err := s.db.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM agents),(SELECT COUNT(*) FROM policies),(SELECT COUNT(*) FROM events)`).Scan(&agents, &policies, &events); err != nil {
		return "", err
	}
	return fmt.Sprintf("agents=%d policies=%d events=%d", agents, policies, events), nil
}
