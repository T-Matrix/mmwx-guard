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
	store        *store.Store
	hub          *Hub
	web          http.Handler
	version      string
	publicURL    string
	agentDir     string
	updater      *updater.Manager
	login        *loginLimiter
	turnstile    *turnstileVerifier
	telemetryMu  sync.Mutex
	telemetryAt  map[string]time.Time
	connectionMu sync.Mutex
	connectionAt map[string][]time.Time
	proxyCIDRs   []netip.Prefix
	identity     *controllerIdentity
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
	return &Server{store: database, hub: NewHub(), web: web, version: version, publicURL: strings.TrimRight(publicURL, "/"), agentDir: agentDir, updater: updateManager, login: newLoginLimiter(), turnstile: turnstile, telemetryAt: make(map[string]time.Time), connectionAt: make(map[string][]time.Time), proxyCIDRs: proxyCIDRs, identity: identity}, nil
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
	admin.HandleFunc("POST /api/admin/account/password", s.handleChangePassword)
	admin.HandleFunc("GET /api/admin/agents", s.handleAgents)
	admin.HandleFunc("PATCH /api/admin/agents/{id}", s.handleRenameAgent)
	admin.HandleFunc("DELETE /api/admin/agents/{id}", s.handleDeleteAgent)
	admin.HandleFunc("POST /api/admin/agents/{id}/credentials/rotate", s.handleRotateAgentCredential)
	admin.HandleFunc("POST /api/admin/agents/{id}/credentials/revoke", s.handleRevokeAgentCredential)
	admin.HandleFunc("POST /api/admin/agents/{id}/pairing", s.handleCreateAgentPairing)
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
	clearSessionCookie(w)
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
	enrollment, err := s.store.ConsumeEnrollment(r.Context(), hashToken(req.Token))
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
			writeError(w, http.StatusConflict, "这台机器已经注册，请使用服务器详情中的重新配对")
			return
		}
		_ = s.store.AddEvent(r.Context(), "info", "agent_enrolled", id, "Agent 注册成功: "+req.Name, map[string]string{"ip": ip})
	}
	writeJSON(w, http.StatusCreated, map[string]string{"agent_id": id, "secret": secret, "controller_public_key": protocol.EncodeKey(s.identity.publicKey())})
}

func (s *Server) handleAgentWS(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("agent_id")
	secret := bearerToken(r)
	if len(id) < 8 || len(id) > 128 || len(secret) < 20 || len(secret) > 128 {
		writeError(w, http.StatusUnauthorized, "Agent 认证失败")
		return
	}
	credentials, err := s.store.AgentCredentials(r.Context(), id)
	presentedHash := hashToken(secret)
	currentMatch := err == nil && subtle.ConstantTimeCompare([]byte(presentedHash), []byte(credentials.SecretHash)) == 1
	pendingExpires, _ := time.Parse(time.RFC3339Nano, credentials.PendingSecretExpires)
	pendingMatch := err == nil && credentials.PendingSecretHash != "" && pendingExpires.After(time.Now()) && subtle.ConstantTimeCompare([]byte(presentedHash), []byte(credentials.PendingSecretHash)) == 1
	if err != nil || (!pendingMatch && (credentials.RevokedAt != "" || !currentMatch)) {
		writeError(w, http.StatusUnauthorized, "Agent 认证失败")
		return
	}
	if pendingMatch {
		if err := s.store.PromoteCredential(r.Context(), id, presentedHash); err != nil {
			writeError(w, http.StatusUnauthorized, "Agent 凭据轮换状态无效")
			return
		}
		_ = s.store.AddEvent(r.Context(), "info", "agent_credential_rotated", id, "Agent 新凭据已生效，旧凭据已失效", nil)
	}
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
	s.hub.Register(id, conn, secureSession)
	defer func() {
		s.hub.Unregister(id, conn)
		if !s.hub.Online(id) {
			_ = s.store.SetAgentOffline(context.Background(), id)
		}
	}()
	_ = s.store.SetAgentConnected(r.Context(), id, s.clientIP(r), hello.OS, hello.Arch, hello.Version, secureSession != nil)
	_ = s.store.AddEvent(r.Context(), "info", "agent_online", id, "Agent 已连接", map[string]bool{"secure_channel": secureSession != nil})
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
		if err := protocol.ValidateFresh(msg, time.Now(), 2*time.Minute); err != nil {
			_ = conn.Close(websocket.StatusPolicyViolation, "stale or invalid message")
			return
		}
		switch msg.Type {
		case protocol.TypeTelemetry:
			var value model.Telemetry
			if len(msg.Payload) > protocol.MaxTelemetryPayloadBytes || json.Unmarshal(msg.Payload, &value) != nil || value.Validate(time.Now()) != nil {
				_ = conn.Close(websocket.StatusInvalidFramePayloadData, "invalid telemetry")
				return
			}
			if s.acceptTelemetry(id, time.Now()) {
				_ = s.store.UpdateTelemetry(r.Context(), id, value)
			}
		case protocol.TypeApplyResult, protocol.TypeUpdateResult, protocol.TypeRotateResult:
			var result protocol.ApplyResult
			if json.Unmarshal(msg.Payload, &result) == nil && protocol.ValidateResult(msg, result) == nil {
				s.hub.Resolve(msg.RequestID, result)
			}
		case protocol.TypePong:
			_ = s.store.TouchAgent(r.Context(), id)
		case protocol.TypeControllerVerified:
			var value protocol.ControllerVerified
			if secureSession == nil || json.Unmarshal(msg.Payload, &value) != nil || subtle.ConstantTimeCompare([]byte(value.Fingerprint), []byte(s.identity.fingerprint())) != 1 {
				_ = conn.Close(websocket.StatusPolicyViolation, "controller verification failed")
				return
			}
			_ = s.store.MarkControllerVerified(r.Context(), id, value.Fingerprint)
		}
	}
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
