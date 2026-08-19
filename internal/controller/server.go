package controller

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"golang.org/x/crypto/bcrypt"

	"github.com/T-Matrix/mmwx-guard/internal/model"
	"github.com/T-Matrix/mmwx-guard/internal/protocol"
	"github.com/T-Matrix/mmwx-guard/internal/store"
	"github.com/T-Matrix/mmwx-guard/internal/updater"
)

type Server struct {
	store     *store.Store
	hub       *Hub
	web       http.Handler
	version   string
	publicURL string
	agentDir  string
	updater   *updater.Manager
}

func NewServer(database *store.Store, web http.Handler, version, publicURL, agentDir string, updateManager *updater.Manager) *Server {
	return &Server{store: database, hub: NewHub(), web: web, version: version, publicURL: strings.TrimRight(publicURL, "/"), agentDir: agentDir, updater: updateManager}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "version": s.version})
	})
	mux.HandleFunc("GET /api/status", s.handleStatus)
	mux.HandleFunc("POST /api/setup", s.handleSetup)
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/logout", s.handleLogout)
	mux.HandleFunc("GET /install-agent.sh", s.handleInstallAgent)
	mux.HandleFunc("GET /downloads/{filename}", s.handleAgentDownload)
	mux.HandleFunc("POST /api/agent/enroll", s.handleAgentEnroll)
	mux.HandleFunc("GET /api/agent/ws", s.handleAgentWS)
	admin := http.NewServeMux()
	admin.HandleFunc("GET /api/admin/summary", s.handleSummary)
	admin.HandleFunc("GET /api/admin/agents", s.handleAgents)
	admin.HandleFunc("PATCH /api/admin/agents/{id}", s.handleRenameAgent)
	admin.HandleFunc("DELETE /api/admin/agents/{id}", s.handleDeleteAgent)
	admin.HandleFunc("GET /api/admin/agents/{id}/protection", s.handleAgentProtection)
	admin.HandleFunc("PUT /api/admin/agents/{id}/protection", s.handleSaveAgentProtection)
	admin.HandleFunc("POST /api/admin/enrollments", s.handleCreateEnrollment)
	admin.HandleFunc("GET /api/admin/policies", s.handlePolicies)
	admin.HandleFunc("POST /api/admin/policies", s.handleSavePolicy)
	admin.HandleFunc("POST /api/admin/policies/{id}/deploy", s.handleDeployPolicy)
	admin.HandleFunc("GET /api/admin/events", s.handleEvents)
	admin.HandleFunc("GET /api/admin/update", s.handleUpdateInfo)
	admin.HandleFunc("POST /api/admin/update/controller", s.handleControllerUpdate)
	admin.HandleFunc("POST /api/admin/update/agents", s.handleAgentUpdates)
	mux.Handle("/api/admin/", s.requireAdmin(admin))
	if s.web != nil {
		mux.Handle("/", s.web)
	}
	return requestLogger(securityHeaders(mux))
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	setup, err := s.store.HasAdmin(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "读取系统状态失败")
		return
	}
	admin, authenticated := s.currentAdmin(r)
	writeJSON(w, http.StatusOK, map[string]any{"setup": setup, "authenticated": authenticated, "admin": admin, "name": "妙妙屋X安全防护", "version": s.version})
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	hasAdmin, err := s.store.HasAdmin(r.Context())
	if err != nil || hasAdmin {
		writeError(w, http.StatusConflict, "系统已经完成初始化")
		return
	}
	var req struct{ Username, Password string }
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if len(req.Username) < 3 || len(req.Password) < 10 {
		writeError(w, http.StatusBadRequest, "管理员名称至少3位，密码至少10位")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), 12)
	if err != nil || s.store.CreateAdmin(r.Context(), req.Username, string(hash)) != nil {
		writeError(w, http.StatusInternalServerError, "创建管理员失败")
		return
	}
	s.createSession(w, r, req.Username, req.Password)
	_ = s.store.AddEvent(r.Context(), "info", "system_setup", "", "系统初始化完成", nil)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct{ Username, Password string }
	if !decodeJSON(w, r, &req) {
		return
	}
	s.createSession(w, r, strings.TrimSpace(req.Username), req.Password)
}

func (s *Server) createSession(w http.ResponseWriter, r *http.Request, username, password string) {
	adminID, hash, err := s.store.AdminPasswordHash(r.Context(), username)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		time.Sleep(300 * time.Millisecond)
		writeError(w, http.StatusUnauthorized, "用户名或密码错误")
		return
	}
	token, err := randomToken(32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "创建登录会话失败")
		return
	}
	expires := time.Now().Add(24 * time.Hour)
	if err := s.store.CreateSession(r.Context(), hashToken(token), adminID, expires); err != nil {
		writeError(w, http.StatusInternalServerError, "创建登录会话失败")
		return
	}
	setSessionCookie(w, r, token, expires)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "username": username})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		_ = s.store.DeleteSession(r.Context(), hashToken(cookie.Value))
	}
	clearSessionCookie(w)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleCreateEnrollment(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Label string `json:"label"`
		TTL   int    `json:"ttl_minutes"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Label = strings.TrimSpace(req.Label)
	if req.Label == "" {
		req.Label = "新服务器"
	}
	if req.TTL < 5 || req.TTL > 1440 {
		req.TTL = 30
	}
	token, err := randomToken(32)
	if err != nil || s.store.CreateEnrollment(r.Context(), hashToken(token), req.Label, time.Now().Add(time.Duration(req.TTL)*time.Minute)) != nil {
		writeError(w, http.StatusInternalServerError, "创建安装令牌失败")
		return
	}
	base := s.publicURL
	if base == "" {
		scheme := "http"
		if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
			scheme = "https"
		}
		base = scheme + "://" + r.Host
	}
	command := fmt.Sprintf("curl -fsSL %s/install-agent.sh | sudo bash -s -- --controller %s --token %s --name %s", shellQuote(base), shellQuote(base), shellQuote(token), shellQuote(req.Label))
	_ = s.store.AddEvent(r.Context(), "info", "enrollment_created", "", "创建服务器安装令牌: "+req.Label, nil)
	writeJSON(w, http.StatusCreated, map[string]any{"token": token, "expires_in_minutes": req.TTL, "install_command": command})
}

func (s *Server) handleAgentEnroll(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token     string `json:"token"`
		Name      string `json:"name"`
		MachineID string `json:"machine_id"`
		OS        string `json:"os"`
		Arch      string `json:"arch"`
		Version   string `json:"version"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	label, err := s.store.ConsumeEnrollment(r.Context(), hashToken(req.Token))
	if err != nil {
		writeError(w, http.StatusUnauthorized, "安装令牌无效、已使用或已过期")
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		req.Name = label
	}
	id, _ := randomToken(12)
	secret, _ := randomToken(32)
	ip := clientIP(r)
	err = s.store.CreateAgent(r.Context(), store.NewAgent{ID: id, Name: req.Name, MachineID: req.MachineID, SecretHash: hashToken(secret), OS: req.OS, Arch: req.Arch, Version: req.Version, IPAddress: ip})
	if err != nil {
		writeError(w, http.StatusConflict, "这台机器已经注册，请先在面板删除旧记录")
		return
	}
	_ = s.store.AddEvent(r.Context(), "info", "agent_enrolled", id, "Agent 注册成功: "+req.Name, map[string]string{"ip": ip})
	writeJSON(w, http.StatusCreated, map[string]string{"agent_id": id, "secret": secret})
}

func (s *Server) handleAgentWS(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("agent_id")
	secret := bearerToken(r)
	expected, err := s.store.AgentSecretHash(r.Context(), id)
	if err != nil || subtle.ConstantTimeCompare([]byte(hashToken(secret)), []byte(expected)) != 1 {
		writeError(w, http.StatusUnauthorized, "Agent 认证失败")
		return
	}
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionContextTakeover})
	if err != nil {
		return
	}
	defer conn.Close(websocket.StatusNormalClosure, "connection closed")
	conn.SetReadLimit(2 << 20)
	readCtx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	var first protocol.Message
	err = wsjson.Read(readCtx, conn, &first)
	cancel()
	if err != nil || first.Type != protocol.TypeHello {
		_ = conn.Close(websocket.StatusPolicyViolation, "hello required")
		return
	}
	var hello protocol.Hello
	if json.Unmarshal(first.Payload, &hello) != nil {
		_ = conn.Close(websocket.StatusInvalidFramePayloadData, "invalid hello")
		return
	}
	s.hub.Register(id, conn)
	defer func() {
		s.hub.Unregister(id, conn)
		if !s.hub.Online(id) {
			_ = s.store.SetAgentOffline(context.Background(), id)
		}
	}()
	_ = s.store.SetAgentConnected(r.Context(), id, clientIP(r), hello.OS, hello.Arch, hello.Version)
	_ = s.store.AddEvent(r.Context(), "info", "agent_online", id, "Agent 已连接", nil)
	ack, _ := protocol.NewMessage(protocol.TypeHelloAck, "", map[string]string{"version": s.version})
	writeCtx, stopWrite := context.WithTimeout(r.Context(), 10*time.Second)
	if err := wsjson.Write(writeCtx, conn, ack); err != nil {
		stopWrite()
		return
	}
	stopWrite()
	if policy, policyErr := s.store.AgentPolicy(r.Context(), id); policyErr == nil {
		go func() {
			ctx, stop := context.WithTimeout(context.Background(), 45*time.Second)
			defer stop()
			result, sendErr := s.hub.ApplyPolicy(ctx, id, policy)
			if sendErr == nil && result.Success {
				_ = s.store.AssignPolicy(context.Background(), id, policy.ID, policy.Revision)
			}
		}()
	}
	for {
		var msg protocol.Message
		if err := wsjson.Read(r.Context(), conn, &msg); err != nil {
			return
		}
		switch msg.Type {
		case protocol.TypeTelemetry:
			var value model.Telemetry
			if json.Unmarshal(msg.Payload, &value) == nil {
				_ = s.store.UpdateTelemetry(r.Context(), id, value)
			}
		case protocol.TypeApplyResult, protocol.TypeUpdateResult:
			var result protocol.ApplyResult
			if json.Unmarshal(msg.Payload, &result) == nil {
				s.hub.Resolve(msg.RequestID, result)
			}
		case protocol.TypePong:
			_ = s.store.TouchAgent(r.Context(), id)
		}
	}
}

func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	value, err := s.store.Summary(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "读取概览失败")
		return
	}
	writeJSON(w, http.StatusOK, value)
}

func (s *Server) handleAgents(w http.ResponseWriter, r *http.Request) {
	agents, err := s.store.ListAgents(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "读取服务器失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"agents": agents})
}

func (s *Server) handleRenameAgent(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if count := utf8.RuneCountInString(req.Name); count < 1 || count > 80 {
		writeError(w, http.StatusBadRequest, "服务器名称长度应为 1 到 80 个字符")
		return
	}
	id := r.PathValue("id")
	if err := s.store.RenameAgent(r.Context(), id, req.Name); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "服务器不存在")
		} else {
			writeError(w, http.StatusInternalServerError, "修改服务器名称失败")
		}
		return
	}
	_ = s.store.AddEvent(r.Context(), "info", "agent_renamed", id, "服务器已重命名: "+req.Name, nil)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "name": req.Name})
}

func (s *Server) handleDeleteAgent(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if s.hub.Online(id) {
		writeError(w, http.StatusConflict, "请先停止这台机器上的 Agent 再删除")
		return
	}
	if err := s.store.DeleteAgent(r.Context(), id); err != nil {
		writeError(w, http.StatusNotFound, "服务器不存在")
		return
	}
	_ = s.store.AddEvent(r.Context(), "warning", "agent_deleted", id, "删除 Agent 记录", nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAgentProtection(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("id")
	policy, err := s.store.AgentPolicy(r.Context(), agentID)
	if err == nil {
		writeJSON(w, http.StatusOK, map[string]any{"policy": policy})
		return
	}
	if !errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusInternalServerError, "读取服务器防护设置失败")
		return
	}
	exists, existsErr := s.store.AgentExists(r.Context(), agentID)
	if existsErr != nil {
		writeError(w, http.StatusInternalServerError, "读取服务器失败")
		return
	}
	if !exists {
		writeError(w, http.StatusNotFound, "服务器不存在")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"policy": nil})
}

func (s *Server) handleSaveAgentProtection(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("id")
	if !s.hub.Online(agentID) {
		writeError(w, http.StatusConflict, "服务器当前离线，无法验证并应用防护设置")
		return
	}
	var policy model.Policy
	if !decodeJSON(w, r, &policy) {
		return
	}
	current, currentErr := s.store.AgentPolicy(r.Context(), agentID)
	switch {
	case currentErr == nil:
		policy.ID = 0
		policy.Revision = current.Revision + 1
	case errors.Is(currentErr, store.ErrNotFound):
		exists, err := s.store.AgentExists(r.Context(), agentID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "读取服务器失败")
			return
		}
		if !exists {
			writeError(w, http.StatusNotFound, "服务器不存在")
			return
		}
		policy.ID = 0
		policy.Revision = 1
	default:
		writeError(w, http.StatusInternalServerError, "读取服务器防护设置失败")
		return
	}
	saved, err := s.store.SavePolicy(r.Context(), policy)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
	result, err := s.hub.ApplyPolicy(ctx, agentID, saved)
	cancel()
	if err != nil {
		_ = s.store.DeletePolicyIfUnassigned(r.Context(), saved.ID)
		_ = s.store.AddEvent(r.Context(), "error", "policy_deploy", agentID, err.Error(), map[string]any{"policy_id": saved.ID, "revision": saved.Revision})
		writeError(w, http.StatusBadGateway, "下发失败: "+err.Error())
		return
	}
	if !result.Success {
		_ = s.store.DeletePolicyIfUnassigned(r.Context(), saved.ID)
		_ = s.store.AddEvent(r.Context(), "error", "policy_deploy", agentID, result.Message, map[string]any{"policy_id": saved.ID, "revision": saved.Revision})
		writeError(w, http.StatusBadRequest, "应用失败: "+result.Message)
		return
	}
	if err := s.store.AssignPolicy(r.Context(), agentID, saved.ID, saved.Revision); err != nil {
		writeError(w, http.StatusInternalServerError, "防护已应用，但保存服务器归属失败")
		return
	}
	if currentErr == nil {
		_ = s.store.DeletePolicyIfUnassigned(r.Context(), current.ID)
	}
	_ = s.store.AddEvent(r.Context(), "info", "policy_deploy", agentID, "服务器防护设置已保存并应用", map[string]any{"policy_id": saved.ID, "revision": saved.Revision})
	writeJSON(w, http.StatusOK, map[string]any{"policy": saved, "message": result.Message})
}

func (s *Server) handlePolicies(w http.ResponseWriter, r *http.Request) {
	policies, err := s.store.ListPolicies(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "读取策略失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"policies": policies})
}

func (s *Server) handleSavePolicy(w http.ResponseWriter, r *http.Request) {
	var policy model.Policy
	if !decodeJSON(w, r, &policy) {
		return
	}
	saved, err := s.store.SavePolicy(r.Context(), policy)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = s.store.AddEvent(r.Context(), "info", "policy_saved", "", "保存防护策略: "+saved.Name, map[string]any{"policy_id": saved.ID, "revision": saved.Revision})
	writeJSON(w, http.StatusOK, saved)
}

func (s *Server) handleDeployPolicy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "策略编号无效")
		return
	}
	policy, err := s.store.GetPolicy(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "策略不存在")
		return
	}
	var req struct {
		AgentIDs []string `json:"agent_ids"`
	}
	if !decodeJSON(w, r, &req) || len(req.AgentIDs) == 0 {
		return
	}
	type deployResult struct {
		AgentID string `json:"agent_id"`
		Success bool   `json:"success"`
		Message string `json:"message"`
	}
	results := make([]deployResult, 0, len(req.AgentIDs))
	for _, agentID := range req.AgentIDs {
		ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
		result, sendErr := s.hub.ApplyPolicy(ctx, agentID, policy)
		cancel()
		row := deployResult{AgentID: agentID}
		if sendErr != nil {
			row.Message = sendErr.Error()
		} else {
			row.Success, row.Message = result.Success, result.Message
			if result.Success {
				_ = s.store.AssignPolicy(r.Context(), agentID, policy.ID, policy.Revision)
			}
		}
		level := "info"
		if !row.Success {
			level = "error"
		}
		_ = s.store.AddEvent(r.Context(), level, "policy_deploy", agentID, row.Message, map[string]any{"policy_id": policy.ID, "revision": policy.Revision})
		results = append(results, row)
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	events, err := s.store.ListEvents(r.Context(), 200)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "读取事件失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}

func (s *Server) handleUpdateInfo(w http.ResponseWriter, r *http.Request) {
	if s.updater == nil {
		writeError(w, http.StatusServiceUnavailable, "当前主控未配置在线更新")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	info, err := s.updater.Check(ctx)
	if err != nil {
		writeError(w, http.StatusBadGateway, "检查 GitHub Release 失败: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, info)
}

func (s *Server) handleControllerUpdate(w http.ResponseWriter, r *http.Request) {
	if s.updater == nil {
		writeError(w, http.StatusServiceUnavailable, "当前主控未配置在线更新")
		return
	}
	var req struct {
		Version string `json:"version"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	status, err := s.updater.RequestUpdate(ctx, strings.TrimSpace(req.Version))
	if err != nil {
		writeError(w, http.StatusBadRequest, "提交主控更新失败: "+err.Error())
		return
	}
	_ = s.store.AddEvent(r.Context(), "warning", "controller_update_queued", "", "主控更新已提交: "+status.Version, map[string]string{"version": status.Version})
	writeJSON(w, http.StatusAccepted, status)
}

func (s *Server) handleAgentUpdates(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AgentIDs []string `json:"agent_ids"`
	}
	if !decodeJSON(w, r, &req) || len(req.AgentIDs) == 0 {
		return
	}
	if len(req.AgentIDs) > 200 {
		writeError(w, http.StatusBadRequest, "一次最多更新 200 台 Agent")
		return
	}
	agents, err := s.store.ListAgents(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "读取 Agent 信息失败")
		return
	}
	architectures := make(map[string]string, len(agents))
	for _, agent := range agents {
		architectures[agent.ID] = agent.Arch
	}
	type updateResult struct {
		AgentID string `json:"agent_id"`
		Success bool   `json:"success"`
		Message string `json:"message"`
	}
	results := make([]updateResult, 0, len(req.AgentIDs))
	seen := make(map[string]bool, len(req.AgentIDs))
	for _, agentID := range req.AgentIDs {
		row := updateResult{AgentID: agentID}
		if agentID == "" || seen[agentID] {
			row.Message = "Agent 编号无效或重复"
			results = append(results, row)
			continue
		}
		seen[agentID] = true
		arch := architectures[agentID]
		if arch != "amd64" && arch != "arm64" {
			row.Message = "Agent 架构不支持在线更新"
			results = append(results, row)
			continue
		}
		path := filepath.Join(s.agentDir, "mmwx-guard-agent-linux-"+arch)
		asset, assetErr := localAsset(path)
		if assetErr != nil {
			row.Message = "读取新版 Agent 失败: " + assetErr.Error()
			results = append(results, row)
			continue
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		result, sendErr := s.hub.UpdateAgent(ctx, agentID, protocol.AgentUpdate{Version: s.version, SHA256: asset.SHA256, Size: asset.Size})
		cancel()
		if sendErr != nil {
			row.Message = sendErr.Error()
		} else {
			row.Success, row.Message = result.Success, result.Message
		}
		level := "info"
		if !row.Success {
			level = "error"
		}
		_ = s.store.AddEvent(r.Context(), level, "agent_update", agentID, row.Message, map[string]string{"version": s.version})
		results = append(results, row)
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": s.version, "results": results})
}

func localAsset(path string) (updater.Asset, error) {
	file, err := os.Open(path)
	if err != nil {
		return updater.Asset{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return updater.Asset{}, err
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return updater.Asset{}, err
	}
	return updater.Asset{SHA256: fmt.Sprintf("%x", hash.Sum(nil)), Size: info.Size()}, nil
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, "请求内容无效: "+err.Error())
		return false
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		writeError(w, http.StatusBadRequest, "请求只能包含一个 JSON 对象")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func clientIP(r *http.Request) string {
	if value := validIP(r.Header.Get("CF-Connecting-IP")); value != "" {
		return value
	}
	if value := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); value != "" {
		for _, candidate := range strings.Split(value, ",") {
			if value := validIP(candidate); value != "" {
				return value
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && validIP(host) != "" {
		return host
	}
	return r.RemoteAddr
}

func validIP(value string) string {
	value = strings.TrimSpace(value)
	if net.ParseIP(value) == nil {
		return ""
	}
	return value
}

func requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		if strings.HasPrefix(r.URL.Path, "/api/") && r.URL.Path != "/api/agent/ws" {
			log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start).Round(time.Millisecond))
		}
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		next.ServeHTTP(w, r)
	})
}

var _ = errors.Is
