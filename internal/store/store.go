package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"

	"github.com/T-Matrix/mmwx-guard/internal/model"
)

var ErrNotFound = errors.New("not found")

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
    status TEXT NOT NULL DEFAULT 'offline',
    ip_address TEXT NOT NULL DEFAULT '',
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
	CREATE INDEX IF NOT EXISTS idx_events_created ON events(id DESC);
	CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status);
	CREATE TRIGGER IF NOT EXISTS trim_events AFTER INSERT ON events
	WHEN NEW.id % 100 = 0
	BEGIN
	    DELETE FROM events WHERE id < NEW.id - 10000;
	END;
	`
	_, err := s.db.Exec(schema)
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

func (s *Store) CreateEnrollment(ctx context.Context, tokenHash, label string, expires time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO enrollment_tokens(token_hash,label,expires_at,created_at) VALUES(?,?,?,?)`, tokenHash, label, expires.UTC().Format(time.RFC3339Nano), now())
	return err
}

func (s *Store) ConsumeEnrollment(ctx context.Context, tokenHash string) (string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var label string
	if err := tx.QueryRowContext(ctx, `SELECT label FROM enrollment_tokens WHERE token_hash=? AND used_at IS NULL AND expires_at>?`, tokenHash, now()).Scan(&label); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE enrollment_tokens SET used_at=? WHERE token_hash=?`, now(), tokenHash); err != nil {
		return "", err
	}
	return label, tx.Commit()
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

func (s *Store) AgentCredentials(ctx context.Context, id string) (secretHash, machineID string, err error) {
	err = s.db.QueryRowContext(ctx, `SELECT secret_hash,machine_id FROM agents WHERE id=?`, id).Scan(&secretHash, &machineID)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return
}

func (s *Store) SetAgentConnected(ctx context.Context, id, ip, osName, arch, version string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE agents SET status='online',ip_address=?,os=?,arch=?,version=?,last_seen=? WHERE id=?`, ip, osName, arch, version, now(), id)
	return err
}

func (s *Store) TouchAgent(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE agents SET status='online',last_seen=? WHERE id=?`, now(), id)
	return err
}

func (s *Store) SetAgentOffline(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE agents SET status='offline' WHERE id=?`, id)
	return err
}

func (s *Store) UpdateTelemetry(ctx context.Context, id string, telemetry model.Telemetry) error {
	raw, err := json.Marshal(telemetry)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE agents SET telemetry_json=?,last_seen=?,status='online',policy_revision=? WHERE id=?`, string(raw), now(), telemetry.PolicyRevision, id)
	return err
}

func (s *Store) ListAgents(ctx context.Context) ([]model.AgentSummary, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT a.id,a.name,a.status,a.ip_address,a.os,a.arch,a.version,a.last_seen,COALESCE(a.policy_id,0),COALESCE(p.name,''),a.policy_revision,a.telemetry_json FROM agents a LEFT JOIN policies p ON p.id=a.policy_id ORDER BY a.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.AgentSummary
	for rows.Next() {
		var a model.AgentSummary
		var telemetry sql.NullString
		if err := rows.Scan(&a.ID, &a.Name, &a.Status, &a.IPAddress, &a.OS, &a.Arch, &a.Version, &a.LastSeen, &a.PolicyID, &a.PolicyName, &a.PolicyRevision, &telemetry); err != nil {
			return nil, err
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
