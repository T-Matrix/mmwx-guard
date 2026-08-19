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
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
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
	store         *store.Store
	hub           *Hub
	web           http.Handler
	version       string
	publicURL     string
	agentDir      string
	updater       *updater.Manager
	login         *loginLimiter
	turnstile     *turnstileVerifier
	telemetryMu   sync.Mutex
	telemetryAt   map[string]time.Time
	connectionMu  sync.Mutex
	connectionAt  map[string][]time.Time
	adaptiveMu    sync.Mutex
	adaptiveState map[string]bool
	taskMu        sync.Mutex
	taskRunning   map[string]bool
	proxyCIDRs    []netip.Prefix
	identity      *controllerIdentity
}

const dummyPasswordHash = "$2y$12$QYiadX9ftra/wDA5wE0ype4OwM7vOikc9zWS0BHtvnZcmVKgz36Iy"

func NewServer(database *store.Store, web http.Handler, version, publicURL, agentDir, identityKeyPath string, updateManager *updater.Manager) (*Server, error) {
	turnstile, err := turnstileFromEnv()
	if err != nil {
		return nil, err
	}
	proxyCIDRs, err := proxyCIDRsFromEnv()
	if err != nil {
		return nil, err
	}
	identity, err := loadOrCreateControllerIdentity(identityKeyPath)
	if err != nil {
		return nil, err
	}
	return &Server{store: database, hub: NewHub(), web: web, version: version, publicURL: strings.TrimRight(publicURL, "/"), agentDir: agentDir, updater: updateManager, login: newLoginLimiter(), turnstile: turnstile, telemetryAt: make(map[string]time.Time), connectionAt: make(map[string][]time.Time), adaptiveState: make(map[string]bool), taskRunning: make(map[string]bool), proxyCIDRs: proxyCIDRs, identity: identity}, nil
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
	mux.HandleFunc("POST /api/agent/address", s.handleAgentAddress)
	mux.HandleFunc("GET /api/agent/ws", s.handleAgentWS)
	mux.HandleFunc("POST /api/agent/https/open", s.handleAgentHTTPSOpen)
	mux.HandleFunc("POST /api/agent/https/exchange", s.handleAgentHTTPSExchange)
	admin := http.NewServeMux()
	admin.HandleFunc("GET /api/admin/summary", s.handleSummary)
	admin.HandleFunc("POST /api/admin/account/password", s.handleChangePassword)
	admin.HandleFunc("GET /api/admin/agents", s.handleAgents)
	admin.HandleFunc("PATCH /api/admin/agents/{id}", s.handleRenameAgent)
	admin.HandleFunc("DELETE /api/admin/agents/{id}", s.handleDeleteAgent)
	admin.HandleFunc("POST /api/admin/agents/{id}/credentials/rotate", s.handleRotateAgentCredential)
	admin.HandleFunc("POST /api/admin/agents/{id}/credentials/revoke", s.handleRevokeAgentCredential)
	admin.HandleFunc("POST /api/admin/agents/{id}/pairing", s.handleCreateAgentPairing)
	admin.HandleFunc("GET /api/admin/agents/{id}/protection", s.handleAgentProtection)
	admin.HandleFunc("GET /api/admin/agents/{id}/metrics", s.handleAgentMetrics)
	admin.HandleFunc("GET /api/admin/agents/{id}/diagnostics", s.handleAgentDiagnostics)
	admin.HandleFunc("PUT /api/admin/agents/{id}/protection", s.handleSaveAgentProtection)
	admin.HandleFunc("GET /api/admin/agents/{id}/policy-history", s.handlePolicyHistory)
	admin.HandleFunc("POST /api/admin/agents/{id}/policy-history/{history_id}/restore", s.handleRestorePolicyHistory)
	admin.HandleFunc("GET /api/admin/agents/{id}/bans", s.handleIPBans)
	admin.HandleFunc("POST /api/admin/agents/{id}/bans", s.handleCreateIPBan)
	admin.HandleFunc("DELETE /api/admin/agents/{id}/bans/{ban_id}", s.handleDeleteIPBan)
	admin.HandleFunc("POST /api/admin/enrollments", s.handleCreateEnrollment)
	admin.HandleFunc("GET /api/admin/policies", s.handlePolicies)
	admin.HandleFunc("POST /api/admin/policies", s.handleSavePolicy)
	admin.HandleFunc("POST /api/admin/policies/{id}/deploy", s.handleDeployPolicy)
	admin.HandleFunc("GET /api/admin/events", s.handleEvents)
	admin.HandleFunc("GET /api/admin/tasks", s.handleTasks)
	admin.HandleFunc("POST /api/admin/tasks/{id}/retry", s.handleRetryTask)
	admin.HandleFunc("POST /api/admin/tasks/{id}/cancel", s.handleCancelTask)
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
	status := map[string]any{"setup": setup, "authenticated": authenticated, "admin": admin, "name": "妙妙屋X安全防护", "version": s.version, "turnstile_enabled": s.turnstile != nil, "controller_fingerprint": s.identity.fingerprint()}
	if s.turnstile != nil {
		status["turnstile_site_key"] = s.turnstile.siteKey
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) {
		writeError(w, http.StatusForbidden, "请求来源验证失败")
		return
	}
	hasAdmin, err := s.store.HasAdmin(r.Context())
	if err != nil || hasAdmin {
		writeError(w, http.StatusConflict, "系统已经完成初始化")
		return
	}
	var req struct {
		Username       string `json:"username"`
		Password       string `json:"password"`
		TurnstileToken string `json:"turnstile_token"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if err := s.turnstile.verify(r.Context(), req.TurnstileToken, s.clientIP(r)); err != nil {
		writeError(w, http.StatusForbidden, "人机验证失败，请重试")
		return
	}
	usernameLength := utf8.RuneCountInString(req.Username)
	if usernameLength < 3 || usernameLength > 80 || len(req.Password) < 10 || len(req.Password) > 72 {
		writeError(w, http.StatusBadRequest, "管理员名称应为3到80个字符，密码应为10到72字节")
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
	if !s.sameOrigin(r) {
		writeError(w, http.StatusForbidden, "请求来源验证失败")
		return
	}
	var req struct {
		Username       string `json:"username"`
		Password       string `json:"password"`
		TurnstileToken string `json:"turnstile_token"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	username := strings.TrimSpace(req.Username)
	ip := s.clientIP(r)
	limitUsername := username
	if len(limitUsername) > 256 {
		limitUsername = ""
	}
	if retryAfter, allowed := s.login.check(ip, limitUsername); !allowed {
		w.Header().Set("Retry-After", strconv.Itoa(max(1, int(retryAfter.Seconds()))))
		_ = s.store.AddEvent(r.Context(), "warning", "login_limited", "", "管理员登录尝试已被限速", map[string]string{"ip": ip})
		writeError(w, http.StatusTooManyRequests, "登录尝试过多，请稍后再试")
		return
	}
	if len(username) > 256 || len(req.Password) > 1024 || s.turnstile.verify(r.Context(), req.TurnstileToken, ip) != nil {
		s.login.failure(ip, limitUsername)
		_ = s.store.AddEvent(r.Context(), "warning", "login_challenge_failed", "", "管理员人机验证失败", map[string]string{"ip": ip})
		writeError(w, http.StatusForbidden, "人机验证失败，请重试")
		return
	}
	s.createSession(w, r, username, req.Password)
}

func (s *Server) createSession(w http.ResponseWriter, r *http.Request, username, password string) {
	ip := s.clientIP(r)
	if retryAfter, allowed := s.login.check(ip, username); !allowed {
		w.Header().Set("Retry-After", strconv.Itoa(max(1, int(retryAfter.Seconds()))))
		_ = s.store.AddEvent(r.Context(), "warning", "login_limited", "", "管理员登录尝试已被限速", map[string]string{"ip": ip})
		writeError(w, http.StatusTooManyRequests, "登录尝试过多，请稍后再试")
		return
	}
	adminID, hash, err := s.store.AdminPasswordHash(r.Context(), username)
	if err != nil {
		hash = dummyPasswordHash
	}
	passwordErr := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil || passwordErr != nil {
		s.login.failure(ip, username)
		_ = s.store.AddEvent(r.Context(), "warning", "login_failed", "", "管理员登录失败", map[string]string{"ip": ip})
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
	s.login.success(ip, username)
	_ = s.store.AddEvent(r.Context(), "info", "login_succeeded", "", "管理员登录成功", map[string]string{"ip": ip})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "username": username})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) {
		writeError(w, http.StatusForbidden, "请求来源验证失败")
		return
	}
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		_ = s.store.DeleteSession(r.Context(), hashToken(cookie.Value))
	}
	clearSessionCookie(w, r)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	username, ok := s.currentAdmin(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "请先登录")
		return
	}
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if len(req.CurrentPassword) > 72 || len(req.NewPassword) < 10 || len(req.NewPassword) > 72 || req.CurrentPassword == req.NewPassword {
		writeError(w, http.StatusBadRequest, "新密码应为 10 到 72 字节，且不能与当前密码相同")
		return
	}
	_, currentHash, err := s.store.AdminPasswordHash(r.Context(), username)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(currentHash), []byte(req.CurrentPassword)) != nil {
		_ = s.store.AddEvent(r.Context(), "warning", "password_change_failed", "", "管理员密码修改失败", map[string]string{"ip": s.clientIP(r)})
		writeError(w, http.StatusUnauthorized, "当前密码错误")
		return
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), 12)
	newSession, tokenErr := randomToken(32)
	if err != nil || tokenErr != nil {
		writeError(w, http.StatusInternalServerError, "生成新凭据失败")
		return
	}
	expires := time.Now().Add(24 * time.Hour)
	if err := s.store.ChangeAdminPassword(r.Context(), username, string(newHash), hashToken(newSession), expires); err != nil {
		writeError(w, http.StatusInternalServerError, "修改密码失败")
		return
	}
	setSessionCookie(w, r, newSession, expires)
	_ = s.store.AddEvent(r.Context(), "warning", "password_changed", "", "管理员密码已修改，其他登录会话已失效", map[string]string{"ip": s.clientIP(r)})
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
	if count := utf8.RuneCountInString(req.Label); count < 1 || count > 80 {
		writeError(w, http.StatusBadRequest, "服务器名称长度应为 1 到 80 个字符")
		return
	}
	if req.TTL < 5 || req.TTL > 1440 {
		req.TTL = 30
	}
	token, err := randomToken(32)
	if err != nil || s.store.CreateEnrollment(r.Context(), hashToken(token), req.Label, "", time.Now().Add(time.Duration(req.TTL)*time.Minute)) != nil {
		writeError(w, http.StatusInternalServerError, "创建安装令牌失败")
		return
	}
	base := s.publicURL
	if base == "" {
		scheme := "http"
		if requestIsHTTPS(r) {
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
	req.Name = strings.TrimSpace(req.Name)
	req.MachineID = strings.TrimSpace(req.MachineID)
	if len(req.Token) < 20 || len(req.Token) > 128 || req.MachineID == "" || len(req.MachineID) > 256 || utf8.RuneCountInString(req.Name) > 80 || len(req.OS) > 64 || len(req.Arch) > 64 || len(req.Version) > 128 {
		writeError(w, http.StatusBadRequest, "Agent 机器标识无效")
		return
	}
	tokenHash := hashToken(req.Token)
	enrollment, err := s.store.Enrollment(r.Context(), tokenHash)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "安装令牌无效、已使用或已过期")
		return
	}
	if enrollment.AgentID == "" {
		existingName, lookupErr := s.store.AgentNameByMachineID(r.Context(), req.MachineID)
		if lookupErr == nil {
			writeError(w, http.StatusConflict, fmt.Sprintf("机器标识与已注册服务器“%s”重复，通常是 VPS 模板复制了系统 machine-id；本次令牌尚未消耗，请重新执行最新版安装命令", existingName))
			return
		}
		if !errors.Is(lookupErr, store.ErrNotFound) {
			writeError(w, http.StatusInternalServerError, "检查 Agent 机器标识失败")
			return
		}
	}
	enrollment, err = s.store.ConsumeEnrollment(r.Context(), tokenHash)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "安装令牌无效、已使用或已过期")
		return
	}
	if req.Name == "" {
		req.Name = enrollment.Label
	}
	secret, secretErr := randomToken(32)
	if secretErr != nil {
		writeError(w, http.StatusInternalServerError, "生成 Agent 凭据失败")
		return
	}
	ip := s.clientIP(r)
	id := enrollment.AgentID
	if id != "" {
		if err := s.store.PrepareAgentReenrollment(r.Context(), id, req.MachineID, hashToken(secret), req.OS, req.Arch, req.Version, ip, time.Now().Add(15*time.Minute)); err != nil {
			writeError(w, http.StatusConflict, "重新配对失败，机器标识与原服务器不一致")
			return
		}
		s.hub.Disconnect(id, "agent re-paired")
		_ = s.store.AddEvent(r.Context(), "warning", "agent_repaired", id, "Agent 已使用一次性命令重新配对", map[string]string{"ip": ip})
	} else {
		var idErr error
		id, idErr = randomToken(12)
		if idErr != nil {
			writeError(w, http.StatusInternalServerError, "生成 Agent 标识失败")
			return
		}
		err = s.store.CreateAgent(r.Context(), store.NewAgent{ID: id, Name: req.Name, MachineID: req.MachineID, SecretHash: hashToken(secret), OS: req.OS, Arch: req.Arch, Version: req.Version, IPAddress: ip})
		if err != nil {
			writeError(w, http.StatusConflict, "机器标识发生并发冲突，请重新执行安装命令")
			return
		}
		_ = s.store.AddEvent(r.Context(), "info", "agent_enrolled", id, "Agent 注册成功: "+req.Name, map[string]string{"ip": ip})
	}
	writeJSON(w, http.StatusCreated, map[string]string{"agent_id": id, "secret": secret, "controller_public_key": protocol.EncodeKey(s.identity.publicKey())})
}

func (s *Server) handleAgentWS(w http.ResponseWriter, r *http.Request) {
	auth, err := s.authenticateAgentRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Agent 认证失败")
		return
	}
	id := auth.id
	credentials := auth.credentials
	if !s.acceptAgentConnection(id, time.Now()) {
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, "Agent 重连过于频繁")
		return
	}
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	defer conn.Close(websocket.StatusNormalClosure, "connection closed")
	conn.SetReadLimit(protocol.MaxMessageBytes)
	readCtx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	var first protocol.Message
	err = wsjson.Read(readCtx, conn, &first)
	cancel()
	if err != nil || first.Type != protocol.TypeHello {
		_ = conn.Close(websocket.StatusPolicyViolation, "hello required")
		return
	}
	var hello protocol.Hello
	if json.Unmarshal(first.Payload, &hello) != nil || protocol.ValidateFresh(first, time.Now(), 2*time.Minute) != nil || protocol.ValidateHello(hello) != nil {
		_ = conn.Close(websocket.StatusInvalidFramePayloadData, "invalid hello")
		return
	}
	if subtle.ConstantTimeCompare([]byte(hello.MachineID), []byte(credentials.MachineID)) != 1 {
		_ = s.store.AddEvent(r.Context(), "error", "agent_identity_mismatch", id, "Agent 机器标识不匹配，连接已拒绝", map[string]string{"ip": s.clientIP(r)})
		_ = conn.Close(websocket.StatusPolicyViolation, "machine identity mismatch")
		return
	}
	if hello.ControllerKeyFingerprint != "" && subtle.ConstantTimeCompare([]byte(hello.ControllerKeyFingerprint), []byte(s.identity.fingerprint())) != 1 {
		_ = s.store.AddEvent(r.Context(), "error", "controller_identity_mismatch", id, "Agent 固定的主控身份与当前主控不一致，连接已拒绝", map[string]string{"ip": s.clientIP(r)})
		_ = conn.Close(websocket.StatusPolicyViolation, "controller identity mismatch")
		return
	}
	var secureSession *protocol.SecureSession
	ackPayload := protocol.HelloAck{Version: s.version}
	if hello.Challenge != "" && hello.AgentEphemeralPublicKey != "" {
		agentPublic, decodeErr := protocol.DecodeKey(hello.AgentEphemeralPublicKey, 32)
		if decodeErr != nil {
			_ = conn.Close(websocket.StatusInvalidFramePayloadData, "invalid secure handshake")
			return
		}
		controllerEphemeral, keyErr := protocol.GenerateEphemeralKey()
		if keyErr != nil {
			_ = conn.Close(websocket.StatusInternalError, "secure handshake failed")
			return
		}
		controllerPublic := controllerEphemeral.PublicKey()
		transcript := protocol.HandshakeTranscript(id, hello.MachineID, hello.Challenge, agentPublic, controllerPublic)
		secureSession, keyErr = protocol.DeriveSecureSession(controllerEphemeral, agentPublic, true)
		if keyErr != nil {
			_ = conn.Close(websocket.StatusPolicyViolation, "secure handshake failed")
			return
		}
		ackPayload.Secure = true
		ackPayload.ControllerPublicKey = protocol.EncodeKey(s.identity.publicKey())
		ackPayload.ControllerEphemeralPublicKey = protocol.EncodeKey(controllerPublic)
		ackPayload.Signature = protocol.EncodeKey(s.identity.sign(transcript))
	}
	ack, _ := protocol.NewMessage(protocol.TypeHelloAck, "", ackPayload)
	writeCtx, stopWrite := context.WithTimeout(r.Context(), 10*time.Second)
	if err := wsjson.Write(writeCtx, conn, ack); err != nil {
		stopWrite()
		return
	}
	stopWrite()
	if auth.pending {
		if err := s.promoteAgentCredential(r.Context(), auth); err != nil {
			_ = conn.Close(websocket.StatusPolicyViolation, "credential rotation state invalid")
			return
		}
	}
	s.hub.Register(id, conn, secureSession)
	defer func() {
		s.hub.Unregister(id, conn)
		if !s.hub.Online(id) {
			_ = s.store.SetAgentOffline(context.Background(), id)
		}
	}()
	_ = s.store.SetAgentConnected(r.Context(), id, s.clientIP(r), hello.OS, hello.Arch, hello.Version, "websocket", secureSession != nil)
	_ = s.store.AddEvent(r.Context(), "info", "agent_online", id, "Agent 已连接", map[string]bool{"secure_channel": secureSession != nil})
	s.startAgentSynchronization(id)
	var messageRate agentMessageRate
	for {
		msg, readErr := readAgentMessage(r.Context(), conn, secureSession)
		if readErr != nil {
			return
		}
		if !messageRate.allow(time.Now()) {
			_ = conn.Close(websocket.StatusPolicyViolation, "message rate exceeded")
			return
		}
		if err := s.handleAgentMessage(r.Context(), id, secureSession != nil, msg); err != nil {
			_ = conn.Close(websocket.StatusPolicyViolation, err.Error())
			return
		}
	}
}

func (s *Server) handleAgentHTTPSOpen(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	auth, err := s.authenticateAgentRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Agent 认证失败")
		return
	}
	if !s.acceptAgentConnection(auth.id, time.Now()) {
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, "Agent 重连过于频繁")
		return
	}
	var first protocol.Message
	if !decodeJSONLimit(w, r, &first, protocol.MaxMessageBytes) {
		return
	}
	if first.Type != protocol.TypeHello {
		writeError(w, http.StatusBadRequest, "HTTPS 备用通道必须先发送握手消息")
		return
	}
	var hello protocol.Hello
	if json.Unmarshal(first.Payload, &hello) != nil || protocol.ValidateFresh(first, time.Now(), 2*time.Minute) != nil || protocol.ValidateHello(hello) != nil || hello.Challenge == "" || hello.AgentEphemeralPublicKey == "" {
		writeError(w, http.StatusBadRequest, "安全握手内容无效")
		return
	}
	if subtle.ConstantTimeCompare([]byte(hello.MachineID), []byte(auth.credentials.MachineID)) != 1 {
		_ = s.store.AddEvent(r.Context(), "error", "agent_identity_mismatch", auth.id, "Agent 机器标识不匹配，HTTPS备用连接已拒绝", map[string]string{"ip": s.clientIP(r)})
		writeError(w, http.StatusForbidden, "Agent 机器标识不匹配")
		return
	}
	if hello.ControllerKeyFingerprint != "" && subtle.ConstantTimeCompare([]byte(hello.ControllerKeyFingerprint), []byte(s.identity.fingerprint())) != 1 {
		_ = s.store.AddEvent(r.Context(), "error", "controller_identity_mismatch", auth.id, "Agent 固定的主控身份与当前主控不一致，HTTPS备用连接已拒绝", map[string]string{"ip": s.clientIP(r)})
		writeError(w, http.StatusForbidden, "主控身份不匹配")
		return
	}
	agentPublic, err := protocol.DecodeKey(hello.AgentEphemeralPublicKey, 32)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Agent 临时密钥无效")
		return
	}
	controllerEphemeral, err := protocol.GenerateEphemeralKey()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "生成安全会话失败")
		return
	}
	controllerPublic := controllerEphemeral.PublicKey()
	session, err := protocol.DeriveSecureSession(controllerEphemeral, agentPublic, true)
	if err != nil {
		writeError(w, http.StatusForbidden, "建立安全会话失败")
		return
	}
	ackPayload := protocol.HelloAck{
		Version: s.version, Secure: true, ControllerPublicKey: protocol.EncodeKey(s.identity.publicKey()),
		ControllerEphemeralPublicKey: protocol.EncodeKey(controllerPublic),
		Signature:                    protocol.EncodeKey(s.identity.sign(protocol.HandshakeTranscript(auth.id, hello.MachineID, hello.Challenge, agentPublic, controllerPublic))),
	}
	ack, _ := protocol.NewMessage(protocol.TypeHelloAck, "", ackPayload)
	sessionID, err := randomToken(24)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "生成安全会话标识失败")
		return
	}
	if auth.pending {
		if err := s.promoteAgentCredential(r.Context(), auth); err != nil {
			writeError(w, http.StatusUnauthorized, "Agent 凭据轮换状态无效")
			return
		}
	}
	s.hub.RegisterHTTPS(auth.id, sessionID, session)
	_ = s.store.SetAgentConnected(r.Context(), auth.id, s.clientIP(r), hello.OS, hello.Arch, hello.Version, "https_pull", true)
	_ = s.store.AddEvent(r.Context(), "info", "agent_https_fallback", auth.id, "Agent 已切换到 HTTPS Push/Pull 备用通道", map[string]bool{"secure_channel": true})
	s.startAgentSynchronization(auth.id)
	go s.expireAgentHTTPSSession(auth.id, sessionID)
	writeJSON(w, http.StatusCreated, protocol.HTTPSOpenResponse{SessionID: sessionID, Message: ack})
}

func (s *Server) handleAgentHTTPSExchange(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	auth, err := s.authenticateAgentRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Agent 认证失败")
		return
	}
	var exchange protocol.HTTPSExchange
	if !decodeJSONLimit(w, r, &exchange, protocol.MaxMessageBytes) {
		return
	}
	if len(exchange.SessionID) < 20 || len(exchange.SessionID) > 128 {
		writeError(w, http.StatusBadRequest, "HTTPS 安全会话标识无效")
		return
	}
	release, err := s.hub.BeginHTTPSExchange(auth.id, exchange.SessionID)
	if errors.Is(err, errHTTPSExchangeBusy) {
		w.Header().Set("Retry-After", "1")
		writeError(w, http.StatusTooManyRequests, "同一 HTTPS 会话已有交换请求正在处理")
		return
	}
	if err != nil {
		writeError(w, http.StatusConflict, "HTTPS 安全会话已失效，请重新握手")
		return
	}
	defer release()
	if exchange.Envelope != nil {
		message, err := s.hub.DecryptHTTPS(auth.id, exchange.SessionID, *exchange.Envelope)
		if err != nil || s.handleAgentMessage(r.Context(), auth.id, true, message) != nil {
			s.hub.UnregisterHTTPS(auth.id, exchange.SessionID)
			_ = s.store.SetAgentOffline(context.Background(), auth.id)
			writeError(w, http.StatusForbidden, "加密消息无效或已重放")
			return
		}
	}
	pullCtx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	envelope, err := s.hub.NextHTTPSEnvelope(pullCtx, auth.id, exchange.SessionID)
	if err != nil {
		writeError(w, http.StatusConflict, "HTTPS 安全会话已被替换")
		return
	}
	writeJSON(w, http.StatusOK, protocol.HTTPSExchange{SessionID: exchange.SessionID, Envelope: envelope})
}

func (s *Server) expireAgentHTTPSSession(agentID, sessionID string) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		if s.hub.HTTPSSessionActive(agentID, sessionID, 45*time.Second) {
			continue
		}
		if s.hub.UnregisterHTTPS(agentID, sessionID) {
			_ = s.store.SetAgentOffline(context.Background(), agentID)
			_ = s.store.AddEvent(context.Background(), "warning", "agent_https_expired", agentID, "Agent HTTPS 备用会话超时", nil)
		}
		return
	}
}

func (s *Server) startAgentSynchronization(agentID string) {
	if policy, err := s.store.AgentPolicy(context.Background(), agentID); err == nil {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			result, sendErr := s.hub.ApplyPolicy(ctx, agentID, policy)
			if sendErr == nil && result.Success {
				_ = s.store.AssignPolicy(context.Background(), agentID, policy.ID, policy.Revision)
				_ = s.syncAgentBans(ctx, agentID)
			}
			go s.processQueuedAgentTasks(agentID)
		}()
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = s.syncAgentBans(ctx, agentID)
		go s.processQueuedAgentTasks(agentID)
	}()
}

func (s *Server) handleAgentMessage(ctx context.Context, agentID string, secure bool, message protocol.Message) error {
	if err := protocol.ValidateFresh(message, time.Now(), 2*time.Minute); err != nil {
		return err
	}
	switch message.Type {
	case protocol.TypeTelemetry:
		var value model.Telemetry
		if len(message.Payload) > protocol.MaxTelemetryPayloadBytes || json.Unmarshal(message.Payload, &value) != nil || value.Validate(time.Now()) != nil {
			return errors.New("invalid telemetry")
		}
		if s.acceptTelemetry(agentID, time.Now()) {
			_ = s.store.UpdateTelemetry(ctx, agentID, value)
			if transition := s.adaptiveTransition(agentID, value.Adaptive.Emergency); transition == "activated" {
				_ = s.store.AddEvent(ctx, "warning", "adaptive_emergency_activated", agentID, "自适应应急保护已启动: "+value.Adaptive.Reason, nil)
			} else if transition == "recovered" {
				_ = s.store.AddEvent(ctx, "info", "adaptive_emergency_recovered", agentID, "连接压力已恢复，自适应应急保护已退出", nil)
			}
		}
	case protocol.TypeApplyResult, protocol.TypeUpdateResult, protocol.TypeRotateResult:
		var result protocol.ApplyResult
		if json.Unmarshal(message.Payload, &result) != nil || protocol.ValidateResult(message, result) != nil {
			return errors.New("invalid Agent result")
		}
		s.hub.Resolve(message.RequestID, result)
	case protocol.TypePong:
		_ = s.store.TouchAgent(ctx, agentID)
	case protocol.TypeControllerVerified:
		var value protocol.ControllerVerified
		if !secure || json.Unmarshal(message.Payload, &value) != nil || subtle.ConstantTimeCompare([]byte(value.Fingerprint), []byte(s.identity.fingerprint())) != 1 {
			return errors.New("controller verification failed")
		}
		_ = s.store.MarkControllerVerified(ctx, agentID, value.Fingerprint)
	case protocol.TypeAddressReport:
		var value protocol.AddressReport
		if !secure || len(message.Payload) > 1024 || json.Unmarshal(message.Payload, &value) != nil || protocol.ValidateAddressReport(value) != nil {
			return errors.New("invalid address report")
		}
		_ = s.store.SetAgentPublicAddresses(ctx, agentID, value.IPv4, value.IPv6)
	default:
		return errors.New("unsupported Agent message")
	}
	return nil
}

func (s *Server) adaptiveTransition(agentID string, emergency bool) string {
	s.adaptiveMu.Lock()
	defer s.adaptiveMu.Unlock()
	if s.adaptiveState == nil {
		s.adaptiveState = make(map[string]bool)
	}
	previous, known := s.adaptiveState[agentID]
	s.adaptiveState[agentID] = emergency
	if !known {
		if emergency {
			return "activated"
		}
		return ""
	}
	if previous == emergency {
		return ""
	}
	if emergency {
		return "activated"
	}
	return "recovered"
}

type agentAuthentication struct {
	id            string
	credentials   store.AgentCredentials
	presentedHash string
	pending       bool
}

func (s *Server) promoteAgentCredential(ctx context.Context, auth agentAuthentication) error {
	if !auth.pending {
		return nil
	}
	if err := s.store.PromoteCredential(ctx, auth.id, auth.presentedHash); err != nil {
		return err
	}
	_ = s.store.AddEvent(ctx, "info", "agent_credential_rotated", auth.id, "Agent 新凭据已生效，旧凭据已失效", nil)
	return nil
}

func (s *Server) authenticateAgentRequest(r *http.Request) (agentAuthentication, error) {
	id := r.URL.Query().Get("agent_id")
	secret := bearerToken(r)
	if len(id) < 8 || len(id) > 128 || len(secret) < 20 || len(secret) > 128 {
		return agentAuthentication{}, errors.New("invalid Agent credentials")
	}
	credentials, err := s.store.AgentCredentials(r.Context(), id)
	if err != nil {
		return agentAuthentication{}, errors.New("invalid Agent credentials")
	}
	presentedHash := hashToken(secret)
	currentMatch := subtle.ConstantTimeCompare([]byte(presentedHash), []byte(credentials.SecretHash)) == 1
	pendingExpires, _ := time.Parse(time.RFC3339Nano, credentials.PendingSecretExpires)
	pendingMatch := credentials.PendingSecretHash != "" && pendingExpires.After(time.Now()) && subtle.ConstantTimeCompare([]byte(presentedHash), []byte(credentials.PendingSecretHash)) == 1
	if !pendingMatch && (credentials.RevokedAt != "" || !currentMatch) {
		return agentAuthentication{}, errors.New("invalid Agent credentials")
	}
	return agentAuthentication{id: id, credentials: credentials, presentedHash: presentedHash, pending: pendingMatch}, nil
}

func (s *Server) handleAgentAddress(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if _, err := s.authenticateAgentRequest(r); err != nil {
		writeError(w, http.StatusUnauthorized, "Agent 认证失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"address": s.clientIP(r)})
}

func (s *Server) handleRotateAgentCredential(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.hub.Online(id) {
		writeError(w, http.StatusConflict, "Agent 当前离线，请使用重新配对命令")
		return
	}
	if !s.hub.Secure(id) {
		writeError(w, http.StatusConflict, "请先把这台 Agent 更新到支持加密轮换的版本")
		return
	}
	secret, err := randomToken(32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "生成新凭据失败")
		return
	}
	if err := s.store.BeginCredentialRotation(r.Context(), id, hashToken(secret), time.Now().Add(15*time.Minute)); err != nil {
		writeError(w, http.StatusConflict, "Agent 已有待确认的轮换、已撤销或不存在")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	result, err := s.hub.RotateCredential(ctx, id, secret)
	if err != nil {
		_ = s.store.AddEvent(r.Context(), "warning", "agent_credential_rotation_pending", id, "Agent 凭据轮换结果待确认，将在重新连接时自动完成", nil)
		writeError(w, http.StatusGatewayTimeout, "轮换命令结果待确认；Agent 重新连接后会自动完成")
		return
	}
	if !result.Success {
		_ = s.store.ClearCredentialRotation(r.Context(), id)
		_ = s.store.AddEvent(r.Context(), "error", "agent_credential_rotation_failed", id, "Agent 凭据轮换失败: "+result.Message, nil)
		writeError(w, http.StatusBadGateway, "Agent 拒绝轮换: "+result.Message)
		return
	}
	_ = s.store.AddEvent(r.Context(), "info", "agent_credential_rotation_started", id, "Agent 已保存新凭据，等待加密重连确认", nil)
	writeJSON(w, http.StatusAccepted, map[string]string{"message": "新凭据已安全下发，Agent 正在重新连接"})
}

func (s *Server) handleRevokeAgentCredential(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.store.RevokeAgentCredential(r.Context(), id); err != nil {
		writeError(w, http.StatusNotFound, "服务器不存在")
		return
	}
	s.hub.Disconnect(id, "agent credential revoked")
	_ = s.store.AddEvent(r.Context(), "warning", "agent_credential_revoked", id, "Agent 凭据已撤销，后续连接将被拒绝", nil)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleCreateAgentPairing(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	name, err := s.store.AgentName(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "服务器不存在")
		return
	}
	var req struct {
		TTL int `json:"ttl_minutes"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.TTL < 5 || req.TTL > 60 {
		req.TTL = 15
	}
	token, err := randomToken(32)
	if err != nil || s.store.CreateEnrollment(r.Context(), hashToken(token), name, id, time.Now().Add(time.Duration(req.TTL)*time.Minute)) != nil {
		writeError(w, http.StatusInternalServerError, "创建重新配对令牌失败")
		return
	}
	base := s.publicURL
	if base == "" {
		scheme := "http"
		if requestIsHTTPS(r) {
			scheme = "https"
		}
		base = scheme + "://" + r.Host
	}
	command := fmt.Sprintf("curl -fsSL %s/install-agent.sh | sudo bash -s -- --controller %s --token %s --name %s --repair", shellQuote(base), shellQuote(base), shellQuote(token), shellQuote(name))
	_ = s.store.AddEvent(r.Context(), "warning", "agent_pairing_created", id, "已创建一次性重新配对命令", nil)
	writeJSON(w, http.StatusCreated, map[string]any{"install_command": command, "expires_in_minutes": req.TTL})
}

func readAgentMessage(ctx context.Context, conn *websocket.Conn, session *protocol.SecureSession) (protocol.Message, error) {
	if session == nil {
		var message protocol.Message
		err := wsjson.Read(ctx, conn, &message)
		return message, err
	}
	var envelope protocol.SecureEnvelope
	if err := wsjson.Read(ctx, conn, &envelope); err != nil {
		return protocol.Message{}, err
	}
	return session.DecryptMessage(envelope)
}

type agentMessageRate struct {
	window time.Time
	count  int
}

func (r *agentMessageRate) allow(now time.Time) bool {
	const (
		messageWindow = time.Minute
		maxMessages   = 60
	)
	if r.window.IsZero() || now.Sub(r.window) >= messageWindow {
		r.window = now
		r.count = 0
	}
	r.count++
	return r.count <= maxMessages
}

func (s *Server) acceptTelemetry(agentID string, now time.Time) bool {
	const minimumInterval = 4 * time.Second
	s.telemetryMu.Lock()
	defer s.telemetryMu.Unlock()
	if previous, ok := s.telemetryAt[agentID]; ok && now.Sub(previous) < minimumInterval {
		return false
	}
	s.telemetryAt[agentID] = now
	return true
}

func (s *Server) acceptAgentConnection(agentID string, now time.Time) bool {
	const (
		connectionWindow = time.Minute
		maxConnections   = 10
	)
	s.connectionMu.Lock()
	defer s.connectionMu.Unlock()
	previous := s.connectionAt[agentID]
	kept := previous[:0]
	for _, connectedAt := range previous {
		if now.Sub(connectedAt) < connectionWindow {
			kept = append(kept, connectedAt)
		}
	}
	if len(kept) >= maxConnections {
		s.connectionAt[agentID] = kept
		return false
	}
	s.connectionAt[agentID] = append(kept, now)
	return true
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

func (s *Server) handleAgentMetrics(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("id")
	if exists, err := s.store.AgentExists(r.Context(), agentID); err != nil {
		writeError(w, http.StatusInternalServerError, "读取服务器失败")
		return
	} else if !exists {
		writeError(w, http.StatusNotFound, "服务器不存在")
		return
	}
	type metricRange struct {
		duration time.Duration
		step     time.Duration
	}
	ranges := map[string]metricRange{
		"1h":  {duration: time.Hour, step: time.Minute},
		"6h":  {duration: 6 * time.Hour, step: 5 * time.Minute},
		"24h": {duration: 24 * time.Hour, step: 15 * time.Minute},
		"7d":  {duration: 7 * 24 * time.Hour, step: time.Hour},
		"30d": {duration: 30 * 24 * time.Hour, step: 6 * time.Hour},
	}
	rangeName := r.URL.Query().Get("range")
	if rangeName == "" {
		rangeName = "24h"
	}
	selected, ok := ranges[rangeName]
	if !ok {
		writeError(w, http.StatusBadRequest, "指标时间范围无效")
		return
	}
	points, err := s.store.ListMetricSamples(r.Context(), agentID, time.Now().Add(-selected.duration), selected.step)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "读取历史指标失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"range": rangeName, "step_seconds": int(selected.step / time.Second), "points": points})
}

func (s *Server) handleSaveAgentProtection(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("id")
	online := s.hub.Online(agentID)
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
	author, _ := s.currentAdmin(r)
	previousTasks, _ := s.store.QueuedAgentTasks(r.Context(), agentID, 100)
	task, err := s.store.CreateAgentTask(r.Context(), agentID, "policy_deploy", model.PolicyDeployTask{PolicyID: saved.ID, PreviousPolicyID: current.ID, Author: author, Source: "saved"})
	if err != nil {
		_ = s.store.DeletePolicyIfUnassigned(r.Context(), saved.ID)
		writeError(w, http.StatusInternalServerError, "创建策略下发任务失败")
		return
	}
	for _, previousTask := range previousTasks {
		if previousTask.Kind != "policy_deploy" {
			continue
		}
		_, payload, getErr := s.store.GetAgentTask(r.Context(), previousTask.ID)
		var previous model.PolicyDeployTask
		if getErr == nil && json.Unmarshal(payload, &previous) == nil && previous.PolicyID != saved.ID {
			_ = s.store.DeletePolicyIfUnassigned(r.Context(), previous.PolicyID)
		}
	}
	if !online {
		_ = s.store.AddEvent(r.Context(), "info", "policy_deploy_queued", agentID, "服务器离线，防护策略已加入等待队列", map[string]any{"task_id": task.ID, "revision": saved.Revision})
		writeJSON(w, http.StatusAccepted, map[string]any{"policy": saved, "message": "策略已保存，Agent上线后自动验证并下发", "queued": true, "task_id": task.ID})
		return
	}
	if _, _, err := s.store.ClaimAgentTask(r.Context(), task.ID); err != nil {
		writeError(w, http.StatusConflict, "策略任务状态已变化，请刷新后重试")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
	result, err := s.hub.ApplyPolicy(ctx, agentID, saved)
	cancel()
	if err != nil {
		_ = s.store.FinishAgentTask(r.Context(), task.ID, false, err.Error())
		_ = s.store.AddEvent(r.Context(), "error", "policy_deploy", agentID, err.Error(), map[string]any{"policy_id": saved.ID, "revision": saved.Revision})
		writeError(w, http.StatusBadGateway, "下发失败: "+err.Error())
		return
	}
	if !result.Success {
		_ = s.store.FinishAgentTask(r.Context(), task.ID, false, result.Message)
		_ = s.store.AddEvent(r.Context(), "error", "policy_deploy", agentID, result.Message, map[string]any{"policy_id": saved.ID, "revision": saved.Revision})
		writeError(w, http.StatusBadRequest, "应用失败: "+result.Message)
		return
	}
	if err := s.store.AssignPolicy(r.Context(), agentID, saved.ID, saved.Revision); err != nil {
		_ = s.store.FinishAgentTask(r.Context(), task.ID, false, "防护已应用，但保存服务器归属失败")
		writeError(w, http.StatusInternalServerError, "防护已应用，但保存服务器归属失败")
		return
	}
	if _, err := s.store.RecordPolicyHistory(r.Context(), agentID, "saved", author, "服务器防护设置已保存并应用", saved); err != nil {
		_ = s.store.AddEvent(r.Context(), "error", "policy_history_failed", agentID, "防护已应用，但历史快照保存失败: "+err.Error(), nil)
	}
	_ = s.store.FinishAgentTask(r.Context(), task.ID, true, "策略已验证并应用")
	if currentErr == nil {
		_ = s.store.DeletePolicyIfUnassigned(r.Context(), current.ID)
	}
	_ = s.syncAgentBans(r.Context(), agentID)
	_ = s.store.AddEvent(r.Context(), "info", "policy_deploy", agentID, "服务器防护设置已保存并应用", map[string]any{"policy_id": saved.ID, "revision": saved.Revision})
	writeJSON(w, http.StatusOK, map[string]any{"policy": saved, "message": result.Message})
}

func (s *Server) handlePolicyHistory(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("id")
	if exists, err := s.store.AgentExists(r.Context(), agentID); err != nil {
		writeError(w, http.StatusInternalServerError, "读取服务器失败")
		return
	} else if !exists {
		writeError(w, http.StatusNotFound, "服务器不存在")
		return
	}
	history, err := s.store.ListPolicyHistory(r.Context(), agentID, 100)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "读取策略历史失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"history": history})
}

func (s *Server) handleRestorePolicyHistory(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("id")
	if !s.hub.Online(agentID) {
		writeError(w, http.StatusConflict, "服务器当前离线，无法验证并恢复策略")
		return
	}
	historyID, err := strconv.ParseInt(r.PathValue("history_id"), 10, 64)
	if err != nil || historyID < 1 {
		writeError(w, http.StatusBadRequest, "历史记录编号无效")
		return
	}
	history, err := s.store.GetPolicyHistory(r.Context(), agentID, historyID)
	if err != nil {
		writeError(w, http.StatusNotFound, "策略历史不存在")
		return
	}
	current, err := s.store.AgentPolicy(r.Context(), agentID)
	if err != nil {
		writeError(w, http.StatusConflict, "服务器当前没有可恢复的防护策略")
		return
	}
	policy := history.Policy
	policy.ID = 0
	policy.Revision = current.Revision + 1
	saved, err := s.store.SavePolicy(r.Context(), policy)
	if err != nil {
		writeError(w, http.StatusBadRequest, "历史策略校验失败: "+err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
	result, applyErr := s.hub.ApplyPolicy(ctx, agentID, saved)
	cancel()
	if applyErr != nil || !result.Success {
		_ = s.store.DeletePolicyIfUnassigned(r.Context(), saved.ID)
		message := result.Message
		if applyErr != nil {
			message = applyErr.Error()
		}
		_ = s.store.AddEvent(r.Context(), "error", "policy_restore_failed", agentID, "策略恢复失败: "+message, map[string]any{"history_id": historyID})
		writeError(w, http.StatusBadGateway, "恢复失败: "+message)
		return
	}
	if err := s.store.AssignPolicy(r.Context(), agentID, saved.ID, saved.Revision); err != nil {
		writeError(w, http.StatusInternalServerError, "策略已恢复，但保存服务器归属失败")
		return
	}
	author, _ := s.currentAdmin(r)
	message := fmt.Sprintf("从 REV %d 恢复，生成 REV %d", history.Revision, saved.Revision)
	if _, err := s.store.RecordPolicyHistory(r.Context(), agentID, "restored", author, message, saved); err != nil {
		_ = s.store.AddEvent(r.Context(), "error", "policy_history_failed", agentID, "策略已恢复，但历史快照保存失败: "+err.Error(), nil)
	}
	_ = s.store.DeletePolicyIfUnassigned(r.Context(), current.ID)
	_ = s.syncAgentBans(r.Context(), agentID)
	_ = s.store.AddEvent(r.Context(), "warning", "policy_restored", agentID, message, map[string]any{"history_id": historyID, "revision": saved.Revision})
	writeJSON(w, http.StatusOK, map[string]any{"policy": saved, "message": message})
}

func (s *Server) handleIPBans(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("id")
	if exists, err := s.store.AgentExists(r.Context(), agentID); err != nil {
		writeError(w, http.StatusInternalServerError, "读取服务器失败")
		return
	} else if !exists {
		writeError(w, http.StatusNotFound, "服务器不存在")
		return
	}
	bans, err := s.store.ListIPBans(r.Context(), agentID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "读取IP封禁列表失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"bans": bans})
}

func (s *Server) handleCreateIPBan(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("id")
	policy, err := s.store.AgentPolicy(r.Context(), agentID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusConflict, "请先为服务器保存并下发防护策略")
		} else {
			writeError(w, http.StatusInternalServerError, "读取服务器防护设置失败")
		}
		return
	}
	var req struct {
		Address         string `json:"address"`
		Reason          string `json:"reason"`
		DurationMinutes int    `json:"duration_minutes"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	address, parseErr := netip.ParseAddr(strings.TrimSpace(req.Address))
	if parseErr != nil || address.IsUnspecified() || address.IsLoopback() || address.IsMulticast() || address.IsLinkLocalUnicast() {
		writeError(w, http.StatusBadRequest, "请输入有效的单个IPv4或IPv6地址")
		return
	}
	address = address.Unmap()
	if trustedAddress(policy, address) {
		writeError(w, http.StatusConflict, "该地址属于可信前置范围，不能加入黑名单")
		return
	}
	if req.DurationMinutes < 0 || req.DurationMinutes > 43200 {
		writeError(w, http.StatusBadRequest, "临时封禁时长应在1分钟到30天之间，0表示永久")
		return
	}
	req.Reason = strings.TrimSpace(req.Reason)
	if req.Reason == "" {
		req.Reason = "管理员手工封禁"
	}
	if utf8.RuneCountInString(req.Reason) > 200 {
		writeError(w, http.StatusBadRequest, "封禁原因不能超过200个字符")
		return
	}
	var expiresAt time.Time
	if req.DurationMinutes > 0 {
		expiresAt = time.Now().Add(time.Duration(req.DurationMinutes) * time.Minute)
	}
	ban, err := s.store.SaveIPBan(r.Context(), agentID, address.String(), req.Reason, expiresAt)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "保存IP封禁失败")
		return
	}
	task, err := s.store.CreateAgentTask(r.Context(), agentID, "ban_sync", map[string]bool{"sync": true})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "创建黑名单同步任务失败")
		return
	}
	status := http.StatusAccepted
	message := "Agent离线，封禁已保存，将在上线后自动应用"
	if s.hub.Online(agentID) {
		if syncErr := s.executeAgentTask(r.Context(), task.ID); syncErr == nil {
			status = http.StatusCreated
			message = "IP封禁已保存并应用"
		} else {
			message = "封禁已保存，同步任务失败，可在任务中心重试: " + syncErr.Error()
		}
	} else {
		status = http.StatusAccepted
	}
	updated, _ := s.store.GetIPBan(r.Context(), agentID, address.String())
	if updated.ID != 0 {
		ban = updated
	}
	_ = s.store.AddEvent(r.Context(), "warning", "ip_ban_created", agentID, "封禁IP: "+address.String(), map[string]any{"expires_at": ban.ExpiresAt, "reason": req.Reason})
	writeJSON(w, status, map[string]any{"ban": ban, "message": message})
}

func (s *Server) handleDeleteIPBan(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("id")
	banID, err := strconv.ParseInt(r.PathValue("ban_id"), 10, 64)
	if err != nil || banID < 1 {
		writeError(w, http.StatusBadRequest, "封禁记录编号无效")
		return
	}
	if err := s.store.DeleteIPBan(r.Context(), agentID, banID); err != nil {
		writeError(w, http.StatusNotFound, "封禁记录不存在")
		return
	}
	task, err := s.store.CreateAgentTask(r.Context(), agentID, "ban_sync", map[string]bool{"sync": true})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "创建解封同步任务失败")
		return
	}
	message := "解封已保存，将在Agent上线后同步"
	if s.hub.Online(agentID) {
		if syncErr := s.executeAgentTask(r.Context(), task.ID); syncErr == nil {
			message = "IP封禁已解除"
		} else {
			message = "解封已保存，同步任务失败，可在任务中心重试: " + syncErr.Error()
		}
	}
	_ = s.store.AddEvent(r.Context(), "info", "ip_ban_deleted", agentID, "IP封禁已解除", map[string]int64{"ban_id": banID})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": message})
}

func (s *Server) syncAgentBans(ctx context.Context, agentID string) error {
	bans, err := s.store.ListIPBans(ctx, agentID)
	if err != nil {
		return err
	}
	targets := make([]model.BanTarget, 0, len(bans))
	for _, ban := range bans {
		targets = append(targets, model.BanTarget{Address: ban.Address, ExpiresAt: ban.ExpiresAt})
	}
	syncCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	result, err := s.hub.SyncBans(syncCtx, agentID, targets)
	if err != nil {
		_ = s.store.SetIPBansApplyState(context.Background(), agentID, false, err.Error())
		return err
	}
	if !result.Success {
		_ = s.store.SetIPBansApplyState(context.Background(), agentID, false, result.Message)
		return errors.New(result.Message)
	}
	return s.store.SetIPBansApplyState(context.Background(), agentID, true, "")
}

func trustedAddress(policy model.Policy, address netip.Addr) bool {
	for _, raw := range policy.TrustedCIDRs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			trusted, addressErr := netip.ParseAddr(strings.TrimSpace(raw))
			if addressErr == nil && trusted.Unmap() == address {
				return true
			}
			continue
		}
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func (s *Server) handleTasks(w http.ResponseWriter, r *http.Request) {
	tasks, err := s.store.ListAgentTasks(r.Context(), 500)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "读取任务中心失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tasks": tasks})
}

func (s *Server) handleRetryTask(w http.ResponseWriter, r *http.Request) {
	taskID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || taskID < 1 {
		writeError(w, http.StatusBadRequest, "任务编号无效")
		return
	}
	task, _, err := s.store.GetAgentTask(r.Context(), taskID)
	if err != nil {
		writeError(w, http.StatusNotFound, "任务不存在")
		return
	}
	if task.State != "failed" {
		writeError(w, http.StatusConflict, "只有失败的任务可以重试")
		return
	}
	if err := s.store.RequeueAgentTask(r.Context(), taskID, "管理员请求重试"); err != nil {
		writeError(w, http.StatusConflict, "任务无法重试")
		return
	}
	if s.hub.Online(task.AgentID) {
		go s.processQueuedAgentTasks(task.AgentID)
	}
	writeJSON(w, http.StatusAccepted, map[string]bool{"ok": true})
}

func (s *Server) handleCancelTask(w http.ResponseWriter, r *http.Request) {
	taskID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || taskID < 1 {
		writeError(w, http.StatusBadRequest, "任务编号无效")
		return
	}
	task, payload, getErr := s.store.GetAgentTask(r.Context(), taskID)
	if getErr != nil {
		writeError(w, http.StatusNotFound, "任务不存在")
		return
	}
	if err := s.store.CancelAgentTask(r.Context(), taskID); err != nil {
		writeError(w, http.StatusConflict, "只有等待中或失败的任务可以取消")
		return
	}
	if task.Kind == "policy_deploy" {
		var request model.PolicyDeployTask
		if json.Unmarshal(payload, &request) == nil {
			_ = s.store.DeletePolicyIfUnassigned(r.Context(), request.PolicyID)
		}
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) processQueuedAgentTasks(agentID string) {
	s.taskMu.Lock()
	if s.taskRunning == nil {
		s.taskRunning = make(map[string]bool)
	}
	if s.taskRunning[agentID] {
		s.taskMu.Unlock()
		return
	}
	s.taskRunning[agentID] = true
	s.taskMu.Unlock()
	defer func() {
		s.taskMu.Lock()
		delete(s.taskRunning, agentID)
		s.taskMu.Unlock()
	}()
	for s.hub.Online(agentID) {
		tasks, err := s.store.QueuedAgentTasks(context.Background(), agentID, 20)
		if err != nil || len(tasks) == 0 {
			return
		}
		for _, task := range tasks {
			if !s.hub.Online(agentID) {
				return
			}
			if err := s.executeAgentTask(context.Background(), task.ID); err != nil && !s.hub.Online(agentID) {
				return
			}
		}
	}
}

func (s *Server) executeAgentTask(ctx context.Context, taskID int64) error {
	task, payload, err := s.store.ClaimAgentTask(ctx, taskID)
	if err != nil {
		return err
	}
	fail := func(runErr error, retry bool) error {
		if retry {
			if err := s.store.RequeueAgentTask(context.Background(), task.ID, runErr.Error()); errors.Is(err, store.ErrTaskAttemptsExhausted) {
				_ = s.store.AddEvent(context.Background(), "error", "agent_task_exhausted", task.AgentID, "任务已达到最大尝试次数: "+runErr.Error(), map[string]any{"task_id": task.ID, "kind": task.Kind})
			}
		} else {
			_ = s.store.FinishAgentTask(context.Background(), task.ID, false, runErr.Error())
		}
		return runErr
	}
	switch task.Kind {
	case "ban_sync":
		if err := s.syncAgentBans(ctx, task.AgentID); err != nil {
			return fail(err, !s.hub.Online(task.AgentID))
		}
		_ = s.store.FinishAgentTask(context.Background(), task.ID, true, "IP封禁列表已同步")
		return nil
	case "policy_deploy":
		var request model.PolicyDeployTask
		if json.Unmarshal(payload, &request) != nil || request.PolicyID < 1 {
			return fail(errors.New("策略任务载荷无效"), false)
		}
		policy, err := s.store.GetPolicy(ctx, request.PolicyID)
		if err != nil {
			return fail(errors.New("待下发策略不存在"), false)
		}
		applyCtx, cancel := context.WithTimeout(ctx, 40*time.Second)
		result, applyErr := s.hub.ApplyPolicy(applyCtx, task.AgentID, policy)
		cancel()
		if applyErr != nil {
			return fail(applyErr, !s.hub.Online(task.AgentID))
		}
		if !result.Success {
			return fail(errors.New(result.Message), false)
		}
		if err := s.store.AssignPolicy(ctx, task.AgentID, policy.ID, policy.Revision); err != nil {
			return fail(err, false)
		}
		message := "排队策略已验证并应用"
		if _, err := s.store.RecordPolicyHistory(ctx, task.AgentID, request.Source, request.Author, message, policy); err != nil {
			_ = s.store.AddEvent(context.Background(), "error", "policy_history_failed", task.AgentID, "策略已应用，但历史快照保存失败: "+err.Error(), nil)
		}
		if request.PreviousPolicyID != 0 {
			_ = s.store.DeletePolicyIfUnassigned(ctx, request.PreviousPolicyID)
		}
		_ = s.syncAgentBans(ctx, task.AgentID)
		_ = s.store.FinishAgentTask(context.Background(), task.ID, true, message)
		_ = s.store.AddEvent(context.Background(), "info", "policy_deploy_completed", task.AgentID, message, map[string]any{"task_id": task.ID, "revision": policy.Revision})
		return nil
	default:
		return fail(errors.New("不支持的任务类型"), false)
	}
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
	if len(req.AgentIDs) > 200 {
		writeError(w, http.StatusBadRequest, "一次最多下发到 200 台 Agent")
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
	return decodeJSONLimit(w, r, dst, 2<<20)
}

func decodeJSONLimit(w http.ResponseWriter, r *http.Request, dst any, limit int64) bool {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
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

func (s *Server) clientIP(r *http.Request) string {
	direct := directClientIP(r)
	if !trustedProxyRequest(r) {
		return direct
	}
	forwarded := forwardedIPs(r.Header.Get("X-Forwarded-For"))
	if len(forwarded) == 0 {
		return direct
	}
	upstream := forwarded[len(forwarded)-1]
	if !prefixContains(s.proxyCIDRs, upstream) {
		return upstream.String()
	}
	if value := validIP(r.Header.Get("CF-Connecting-IP")); value != "" {
		return value
	}
	for index := len(forwarded) - 1; index >= 0; index-- {
		if !prefixContains(s.proxyCIDRs, forwarded[index]) {
			return forwarded[index].String()
		}
	}
	return upstream.String()
}

func directClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && validIP(host) != "" {
		return host
	}
	return r.RemoteAddr
}

func forwardedIPs(value string) []netip.Addr {
	parts := strings.Split(value, ",")
	addresses := make([]netip.Addr, 0, len(parts))
	for _, part := range parts {
		if address, err := netip.ParseAddr(strings.TrimSpace(part)); err == nil {
			addresses = append(addresses, address.Unmap())
		}
	}
	return addresses
}

func prefixContains(prefixes []netip.Prefix, address netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func proxyCIDRsFromEnv() ([]netip.Prefix, error) {
	raw := strings.TrimSpace(os.Getenv("TRUSTED_PROXY_CIDRS"))
	if raw == "" {
		return nil, nil
	}
	parts := strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' })
	prefixes := make([]netip.Prefix, 0, len(parts))
	for _, part := range parts {
		prefix, err := netip.ParsePrefix(part)
		if err != nil {
			return nil, fmt.Errorf("invalid TRUSTED_PROXY_CIDRS entry %q", part)
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return prefixes, nil
}

func requestIsHTTPS(r *http.Request) bool {
	return r.TLS != nil || (trustedProxyRequest(r) && strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https"))
}

func trustedProxyRequest(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	return ip != nil && ip.IsLoopback()
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
		if requestIsHTTPS(r) {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; object-src 'none'; img-src 'self' data:; font-src 'self'; style-src 'self'; script-src 'self' https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; connect-src 'self' https://challenges.cloudflare.com")
		next.ServeHTTP(w, r)
	})
}

var _ = errors.Is
