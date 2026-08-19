package controller

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/T-Matrix/mmwx-guard/internal/store"
	"golang.org/x/crypto/bcrypt"
)

func TestClientIPPrefersCloudflareAddress(t *testing.T) {
	server := &Server{proxyCIDRs: []netip.Prefix{netip.MustParsePrefix("172.64.0.0/13")}}
	request := httptest.NewRequest("GET", "https://guard.example.com/api/agent/ws", nil)
	request.RemoteAddr = "127.0.0.1:12345"
	request.Header.Set("CF-Connecting-IP", "104.251.231.10")
	request.Header.Set("X-Forwarded-For", "104.251.231.10, 172.64.213.106")
	if got := server.clientIP(request); got != "104.251.231.10" {
		t.Fatalf("clientIP() = %q, want real Cloudflare client IP", got)
	}
}

func TestDummyPasswordHashIsValid(t *testing.T) {
	if cost, err := bcrypt.Cost([]byte(dummyPasswordHash)); err != nil || cost != 12 {
		t.Fatalf("dummy password hash cost = %d, %v", cost, err)
	}
}

func TestSecurityHeadersEnableHSTSOnlyForHTTPS(t *testing.T) {
	handler := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	for _, test := range []struct {
		name, url, remote, proto string
		wantHSTS                 bool
	}{
		{name: "direct HTTP", url: "http://guard.example.com", remote: "198.51.100.1:1234"},
		{name: "loopback HTTPS proxy", url: "http://guard.example.com", remote: "127.0.0.1:1234", proto: "https", wantHSTS: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest("GET", test.url, nil)
			request.RemoteAddr = test.remote
			request.Header.Set("X-Forwarded-Proto", test.proto)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if got := response.Header().Get("Strict-Transport-Security") != ""; got != test.wantHSTS {
				t.Fatalf("HSTS present = %v, want %v", got, test.wantHSTS)
			}
			if response.Header().Get("Cross-Origin-Opener-Policy") != "same-origin" || response.Header().Get("Cross-Origin-Resource-Policy") != "same-origin" {
				t.Fatal("cross-origin isolation headers are missing")
			}
		})
	}
}

func TestClientIPRejectsInvalidForwardedValues(t *testing.T) {
	server := &Server{}
	request := httptest.NewRequest("GET", "https://guard.example.com/api/agent/ws", nil)
	request.RemoteAddr = "127.0.0.1:12345"
	request.Header.Set("CF-Connecting-IP", "not-an-ip")
	request.Header.Set("X-Forwarded-For", "also-invalid, 203.0.113.8")
	if got := server.clientIP(request); got != "203.0.113.8" {
		t.Fatalf("clientIP() = %q, want direct upstream IP", got)
	}
}

func TestClientIPIgnoresForwardedHeadersFromUntrustedPeer(t *testing.T) {
	server := &Server{proxyCIDRs: []netip.Prefix{netip.MustParsePrefix("172.64.0.0/13")}}
	request := httptest.NewRequest("GET", "https://guard.example.com/api/login", nil)
	request.RemoteAddr = "198.51.100.10:12345"
	request.Header.Set("CF-Connecting-IP", "203.0.113.8")
	request.Header.Set("X-Forwarded-For", "203.0.113.9")
	if got := server.clientIP(request); got != "198.51.100.10" {
		t.Fatalf("clientIP() = %q, want direct peer address", got)
	}
}

func TestClientIPRejectsForgedCloudflareHeaderFromDirectOriginRequest(t *testing.T) {
	server := &Server{proxyCIDRs: []netip.Prefix{netip.MustParsePrefix("172.64.0.0/13")}}
	request := httptest.NewRequest("GET", "https://guard.example.com/api/login", nil)
	request.RemoteAddr = "127.0.0.1:12345"
	request.Header.Set("CF-Connecting-IP", "203.0.113.8")
	request.Header.Set("X-Forwarded-For", "198.51.100.10")
	if got := server.clientIP(request); got != "198.51.100.10" {
		t.Fatalf("clientIP() = %q, want untrusted direct origin client", got)
	}
}

func TestProxyCIDRsFromEnvRejectsInvalidEntry(t *testing.T) {
	t.Setenv("TRUSTED_PROXY_CIDRS", "172.64.0.0/13,not-a-prefix")
	if _, err := proxyCIDRsFromEnv(); err == nil {
		t.Fatal("invalid trusted proxy CIDR accepted")
	}
}

func TestRequestIsHTTPSOnlyTrustsLoopbackProxy(t *testing.T) {
	request := httptest.NewRequest("GET", "http://guard.example.com", nil)
	request.RemoteAddr = "198.51.100.10:12345"
	request.Header.Set("X-Forwarded-Proto", "https")
	if requestIsHTTPS(request) {
		t.Fatal("untrusted peer forged HTTPS proxy header")
	}
	request.RemoteAddr = "127.0.0.1:12345"
	if !requestIsHTTPS(request) {
		t.Fatal("loopback reverse proxy HTTPS header was ignored")
	}
}

func TestTelemetryWritesAreThrottledPerAgent(t *testing.T) {
	server := &Server{telemetryAt: make(map[string]time.Time)}
	now := time.Date(2026, 8, 19, 0, 0, 0, 0, time.UTC)
	if !server.acceptTelemetry("agent-1", now) {
		t.Fatal("first telemetry update rejected")
	}
	if server.acceptTelemetry("agent-1", now.Add(3*time.Second)) {
		t.Fatal("rapid telemetry update accepted")
	}
	if !server.acceptTelemetry("agent-1", now.Add(4*time.Second)) {
		t.Fatal("telemetry update after interval rejected")
	}
	if !server.acceptTelemetry("agent-2", now.Add(time.Second)) {
		t.Fatal("one Agent throttled another Agent")
	}
}

func TestAgentConnectionsAreRateLimited(t *testing.T) {
	server := &Server{connectionAt: make(map[string][]time.Time)}
	now := time.Date(2026, 8, 19, 0, 0, 0, 0, time.UTC)
	for index := 0; index < 10; index++ {
		if !server.acceptAgentConnection("agent-1", now.Add(time.Duration(index)*time.Second)) {
			t.Fatalf("connection %d unexpectedly rejected", index+1)
		}
	}
	if server.acceptAgentConnection("agent-1", now.Add(10*time.Second)) {
		t.Fatal("excessive Agent connection accepted")
	}
	if !server.acceptAgentConnection("agent-2", now.Add(10*time.Second)) {
		t.Fatal("one Agent rate limited another Agent")
	}
	if !server.acceptAgentConnection("agent-1", now.Add(61*time.Second)) {
		t.Fatal("Agent remained limited after the window")
	}
}

func TestAgentMessageRate(t *testing.T) {
	var rate agentMessageRate
	now := time.Date(2026, 8, 19, 0, 0, 0, 0, time.UTC)
	for index := 0; index < 60; index++ {
		if !rate.allow(now.Add(time.Duration(index) * time.Millisecond)) {
			t.Fatalf("message %d unexpectedly rejected", index+1)
		}
	}
	if rate.allow(now.Add(time.Second)) {
		t.Fatal("excessive Agent message accepted")
	}
	if !rate.allow(now.Add(time.Minute)) {
		t.Fatal("Agent remained limited after the window")
	}
}

func TestAgentAddressRequiresCredentialsAndEchoesClientAddress(t *testing.T) {
	database, err := store.Open(filepath.Join(t.TempDir(), "guard.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	secret := "0123456789abcdef0123456789abcdef"
	err = database.CreateAgent(t.Context(), store.NewAgent{
		ID: "agent-address-test", Name: "address test", MachineID: "machine-1", SecretHash: hashToken(secret),
	})
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{store: database}

	request := httptest.NewRequest(http.MethodPost, "/api/agent/address?agent_id=agent-address-test", nil)
	request.RemoteAddr = "104.251.231.10:54321"
	request.Header.Set("Authorization", "Bearer "+secret)
	response := httptest.NewRecorder()
	server.handleAgentAddress(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("address response = %d, Cache-Control %q", response.Code, response.Header().Get("Cache-Control"))
	}
	var payload struct {
		Address string `json:"address"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil || payload.Address != "104.251.231.10" {
		t.Fatalf("address payload = %#v, %v", payload, err)
	}

	request = httptest.NewRequest(http.MethodPost, "/api/agent/address?agent_id=agent-address-test", nil)
	request.Header.Set("Authorization", "Bearer wrong-secret-that-is-long-enough")
	response = httptest.NewRecorder()
	server.handleAgentAddress(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("invalid credential response = %d, want %d", response.Code, http.StatusUnauthorized)
	}
}

func TestDuplicateMachineIdentityDoesNotConsumeEnrollment(t *testing.T) {
	database, err := store.Open(filepath.Join(t.TempDir(), "guard.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.CreateAgent(t.Context(), store.NewAgent{ID: "existing-agent", Name: "Existing Server", MachineID: "cloned-machine-id", SecretHash: hashToken("existing-agent-secret")}); err != nil {
		t.Fatal(err)
	}
	token := "0123456789abcdef0123456789abcdef"
	if err := database.CreateEnrollment(t.Context(), hashToken(token), "New Server", "", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	server := &Server{store: database}
	body := `{"token":"` + token + `","name":"New Server","machine_id":"cloned-machine-id","os":"linux","arch":"amd64","version":"test"}`
	request := httptest.NewRequest(http.MethodPost, "/api/agent/enroll", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	server.handleAgentEnroll(response, request)

	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "Existing Server") {
		t.Fatalf("duplicate identity response = %d %s", response.Code, response.Body.String())
	}
	if _, err := database.Enrollment(t.Context(), hashToken(token)); err != nil {
		t.Fatalf("duplicate identity consumed enrollment token: %v", err)
	}
}
