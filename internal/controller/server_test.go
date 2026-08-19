package controller

import (
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
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
