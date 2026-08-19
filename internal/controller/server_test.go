package controller

import (
	"net/http/httptest"
	"testing"
)

func TestClientIPPrefersCloudflareAddress(t *testing.T) {
	request := httptest.NewRequest("GET", "https://guard.example.com/api/agent/ws", nil)
	request.RemoteAddr = "127.0.0.1:12345"
	request.Header.Set("CF-Connecting-IP", "104.251.231.10")
	request.Header.Set("X-Forwarded-For", "172.64.213.106")
	if got := clientIP(request); got != "104.251.231.10" {
		t.Fatalf("clientIP() = %q, want real Cloudflare client IP", got)
	}
}

func TestClientIPRejectsInvalidForwardedValues(t *testing.T) {
	request := httptest.NewRequest("GET", "https://guard.example.com/api/agent/ws", nil)
	request.RemoteAddr = "127.0.0.1:12345"
	request.Header.Set("CF-Connecting-IP", "not-an-ip")
	request.Header.Set("X-Forwarded-For", "also-invalid, 203.0.113.8")
	if got := clientIP(request); got != "203.0.113.8" {
		t.Fatalf("clientIP() = %q, want first valid forwarded IP", got)
	}
}
