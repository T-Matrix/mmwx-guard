package controller

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/T-Matrix/mmwx-guard/internal/model"
	"github.com/T-Matrix/mmwx-guard/internal/store"
)

const maxDiagnosticBundleBytes = 8 << 20

var diagnosticSecretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+`),
	regexp.MustCompile(`(?i)(--(?:token|secret|password|api-key)(?:=|\s+))["']?[^\s"']+["']?`),
	regexp.MustCompile(`(?i)((?:token|secret|password|authorization|cookie|api[_-]?key)\s*[=:]\s*)["']?[A-Za-z0-9._~+/=-]{8,}["']?`),
}

type diagnosticAgent struct {
	ID                   string `json:"id"`
	Name                 string `json:"name"`
	Status               string `json:"status"`
	ControlAddress       string `json:"control_address,omitempty"`
	IPv4Address          string `json:"ipv4_address,omitempty"`
	IPv6Address          string `json:"ipv6_address,omitempty"`
	AddressUpdatedAt     string `json:"address_updated_at,omitempty"`
	OS                   string `json:"os"`
	Arch                 string `json:"arch"`
	Version              string `json:"version"`
	LastSeen             string `json:"last_seen"`
	PolicyID             int64  `json:"policy_id,omitempty"`
	PolicyName           string `json:"policy_name,omitempty"`
	PolicyRevision       int64  `json:"policy_revision,omitempty"`
	CredentialState      string `json:"credential_state"`
	CredentialRotatedAt  string `json:"credential_rotated_at,omitempty"`
	CredentialRevokedAt  string `json:"credential_revoked_at,omitempty"`
	LastAuthenticatedAt  string `json:"last_authenticated_at,omitempty"`
	ControllerVerifiedAt string `json:"controller_verified_at,omitempty"`
	SecureChannel        bool   `json:"secure_channel"`
	ConnectionTransport  string `json:"connection_transport,omitempty"`
}

type diagnosticCheck struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

type diagnosticEvent struct {
	ID        int64  `json:"id"`
	Level     string `json:"level"`
	Kind      string `json:"kind"`
	Message   string `json:"message"`
	CreatedAt string `json:"created_at"`
}

type diagnosticHistory struct {
	ID        int64  `json:"id"`
	Revision  int64  `json:"revision"`
	Source    string `json:"source"`
	Author    string `json:"author"`
	Message   string `json:"message,omitempty"`
	CreatedAt string `json:"created_at"`
}

func (s *Server) handleAgentDiagnostics(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("id")
	bundle, err := s.buildDiagnosticBundle(r.Context(), agentID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "服务器不存在")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "生成诊断包失败")
		return
	}
	stamp := time.Now().UTC().Format("20060102-150405")
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="mmwx-guard-diagnostic-%s.zip"`, stamp))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(bundle)
	admin, _ := s.currentAdmin(r)
	_ = s.store.AddEvent(r.Context(), "info", "diagnostic_bundle_downloaded", agentID, "管理员生成服务器诊断包", map[string]string{"admin": admin})
}

func (s *Server) buildDiagnosticBundle(ctx context.Context, agentID string) ([]byte, error) {
	agents, err := s.store.ListAgents(ctx)
	if err != nil {
		return nil, err
	}
	var agent *model.AgentSummary
	for index := range agents {
		if agents[index].ID == agentID {
			agent = &agents[index]
			break
		}
	}
	if agent == nil {
		return nil, store.ErrNotFound
	}

	var policy *model.Policy
	if value, policyErr := s.store.AgentPolicy(ctx, agentID); policyErr == nil {
		policy = &value
	} else if !errors.Is(policyErr, store.ErrNotFound) {
		return nil, policyErr
	}
	bans, err := s.store.ListIPBans(ctx, agentID)
	if err != nil {
		return nil, err
	}
	tasks, err := s.store.ListAgentTasksForAgent(ctx, agentID, 100)
	if err != nil {
		return nil, err
	}
	events, err := s.store.ListEventsForAgent(ctx, agentID, 100)
	if err != nil {
		return nil, err
	}
	history, err := s.store.ListPolicyHistory(ctx, agentID, 20)
	if err != nil {
		return nil, err
	}
	metrics, err := s.store.ListMetricSamples(ctx, agentID, time.Now().Add(-24*time.Hour), 15*time.Minute)
	if err != nil {
		return nil, err
	}

	generatedAt := time.Now().UTC()
	files := map[string]any{
		"manifest.json": map[string]any{
			"schema_version": 1, "generated_at": generatedAt.Format(time.RFC3339Nano),
			"controller_version": s.version, "agent_id": agent.ID,
			"redactions": []string{"credentials", "passwords", "tokens", "cookies", "authorization headers", "environment variables", "event metadata"},
		},
		"agent.json": diagnosticAgent{
			ID: agent.ID, Name: agent.Name, Status: agent.Status, ControlAddress: agent.IPAddress,
			IPv4Address: agent.IPv4Address, IPv6Address: agent.IPv6Address, AddressUpdatedAt: agent.AddressUpdatedAt,
			OS: agent.OS, Arch: agent.Arch, Version: agent.Version, LastSeen: agent.LastSeen,
			PolicyID: agent.PolicyID, PolicyName: agent.PolicyName, PolicyRevision: agent.PolicyRevision,
			CredentialState: agent.CredentialState, CredentialRotatedAt: agent.CredentialRotatedAt,
			CredentialRevokedAt: agent.CredentialRevokedAt, LastAuthenticatedAt: agent.LastAuthenticatedAt,
			ControllerVerifiedAt: agent.ControllerVerifiedAt, SecureChannel: agent.SecureChannel,
			ConnectionTransport: agent.ConnectionTransport,
		},
		"checks.json":    diagnosticChecks(*agent, s.hub.Online(agentID), policy, tasks, generatedAt),
		"telemetry.json": agent.Telemetry,
		"policy.json":    policy,
		"bans.json":      bans,
		"tasks.json":     tasks,
		"metrics-24h.json": map[string]any{
			"step_seconds": 900,
			"points":       metrics,
		},
	}
	diagnosticEvents := make([]diagnosticEvent, 0, len(events))
	for _, event := range events {
		diagnosticEvents = append(diagnosticEvents, diagnosticEvent{ID: event.ID, Level: event.Level, Kind: event.Kind, Message: event.Message, CreatedAt: event.CreatedAt})
	}
	files["events.json"] = diagnosticEvents
	diagnosticHistoryItems := make([]diagnosticHistory, 0, len(history))
	for _, item := range history {
		diagnosticHistoryItems = append(diagnosticHistoryItems, diagnosticHistory{ID: item.ID, Revision: item.Revision, Source: item.Source, Author: item.Author, Message: item.Message, CreatedAt: item.CreatedAt})
	}
	files["policy-history.json"] = diagnosticHistoryItems

	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	readme := "妙妙屋X安全防护诊断包\n\n此文件由主控基于已保存的只读状态生成。\n不包含数据库、环境变量、管理员凭据、Agent密钥、注册令牌或会话。\n诊断包仍包含服务器地址、来源IP、策略和端口信息，请仅交给可信人员。\n"
	if err := writeDiagnosticFile(writer, "README.txt", []byte(readme), generatedAt); err != nil {
		return nil, err
	}
	for _, name := range []string{"manifest.json", "checks.json", "agent.json", "telemetry.json", "policy.json", "bans.json", "tasks.json", "events.json", "policy-history.json", "metrics-24h.json"} {
		raw, err := diagnosticJSON(files[name])
		if err != nil {
			return nil, err
		}
		if err := writeDiagnosticFile(writer, name, raw, generatedAt); err != nil {
			return nil, err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	if buffer.Len() > maxDiagnosticBundleBytes {
		return nil, errors.New("diagnostic bundle exceeds size limit")
	}
	return buffer.Bytes(), nil
}

func writeDiagnosticFile(writer *zip.Writer, name string, content []byte, modified time.Time) error {
	header := &zip.FileHeader{Name: name, Method: zip.Deflate}
	header.SetModTime(modified)
	file, err := writer.CreateHeader(header)
	if err != nil {
		return err
	}
	_, err = file.Write(content)
	return err
}

func diagnosticJSON(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var document any
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, err
	}
	return json.MarshalIndent(redactDiagnosticValue(document), "", "  ")
}

func redactDiagnosticValue(value any) any {
	switch current := value.(type) {
	case map[string]any:
		redacted := make(map[string]any, len(current))
		for key, item := range current {
			if sensitiveDiagnosticKey(key) {
				redacted[key] = "[REDACTED]"
			} else {
				redacted[key] = redactDiagnosticValue(item)
			}
		}
		return redacted
	case []any:
		redacted := make([]any, len(current))
		for index, item := range current {
			redacted[index] = redactDiagnosticValue(item)
		}
		return redacted
	case string:
		return redactDiagnosticText(current)
	default:
		return value
	}
}

func sensitiveDiagnosticKey(key string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(key, "-", "_"))
	for _, part := range []string{"password", "secret", "token", "cookie", "authorization", "private_key", "session"} {
		if strings.Contains(normalized, part) {
			return true
		}
	}
	return normalized == "credential_hash" || normalized == "secret_hash"
}

func redactDiagnosticText(value string) string {
	for _, pattern := range diagnosticSecretPatterns {
		value = pattern.ReplaceAllString(value, `${1}[REDACTED]`)
	}
	return value
}

func diagnosticChecks(agent model.AgentSummary, online bool, policy *model.Policy, tasks []model.AgentTask, now time.Time) []diagnosticCheck {
	checks := make([]diagnosticCheck, 0, 8)
	add := func(id, status, message string) {
		checks = append(checks, diagnosticCheck{ID: id, Status: status, Message: message})
	}
	if online {
		add("agent_connection", "pass", "Agent当前与主控保持连接")
	} else {
		add("agent_connection", "warning", "Agent当前未与主控保持活动连接")
	}
	if agent.SecureChannel {
		add("secure_channel", "pass", "控制通道使用端到端加密")
	} else {
		add("secure_channel", "warning", "Agent未报告端到端加密通道")
	}
	if agent.ControllerVerifiedAt != "" {
		add("controller_identity", "pass", "Agent已验证主控身份")
	} else {
		add("controller_identity", "warning", "尚无Agent验证主控身份的记录")
	}
	if agent.IPv4Address != "" || agent.IPv6Address != "" {
		add("public_address", "pass", "至少已探测到一个公网地址")
	} else {
		add("public_address", "warning", "尚未探测到公网IPv4或IPv6地址")
	}
	if agent.Telemetry == nil {
		add("telemetry_freshness", "warning", "主控尚未保存Agent遥测")
	} else if collectedAt, err := time.Parse(time.RFC3339Nano, agent.Telemetry.CollectedAt); err != nil || now.Sub(collectedAt) > 30*time.Second {
		add("telemetry_freshness", "warning", "最近遥测超过30秒或时间格式无效")
	} else {
		add("telemetry_freshness", "pass", "最近遥测在30秒以内")
	}
	if policy == nil {
		add("policy_sync", "info", "这台服务器尚未配置防护策略")
	} else if agent.Telemetry == nil || agent.Telemetry.PolicyRevision != policy.Revision || (policy.Enabled && !agent.Telemetry.Protected) {
		add("policy_sync", "warning", "主控策略与Agent上报状态不一致")
	} else {
		add("policy_sync", "pass", "主控策略版本与Agent上报一致")
	}
	unhealthy, unsupported := 0, 0
	if agent.Telemetry != nil {
		for _, health := range agent.Telemetry.PortHealth {
			if health.Status == "unhealthy" {
				unhealthy++
			} else if health.Status == "unsupported" {
				unsupported++
			}
		}
	}
	if agent.Telemetry == nil || len(agent.Telemetry.PortHealth) == 0 {
		add("port_health", "info", "尚无TCP端口探测结果")
	} else if unhealthy > 0 {
		add("port_health", "warning", fmt.Sprintf("%d个TCP监听无法连接，%d个非TCP监听未探测", unhealthy, unsupported))
	} else {
		add("port_health", "pass", fmt.Sprintf("TCP监听均可连接，%d个非TCP监听未探测", unsupported))
	}
	failed, queued := 0, 0
	for _, task := range tasks {
		if task.State == "failed" {
			failed++
		} else if task.State == "queued" || task.State == "running" {
			queued++
		}
	}
	if failed > 0 {
		add("task_queue", "warning", fmt.Sprintf("最近任务中有%d个失败、%d个等待或执行中", failed, queued))
	} else {
		add("task_queue", "pass", fmt.Sprintf("最近任务无失败，%d个等待或执行中", queued))
	}
	return checks
}
