package controller

import (
	"testing"
	"time"
)

func TestLoginLimiterLocksIPAndAccount(t *testing.T) {
	limiter := newLoginLimiter()
	now := time.Date(2026, 8, 19, 0, 0, 0, 0, time.UTC)
	limiter.now = func() time.Time { return now }
	for range loginMaxAttempts {
		if _, allowed := limiter.check("203.0.113.9", "admin"); !allowed {
			t.Fatal("login was locked before the configured number of failures")
		}
		limiter.failure("203.0.113.9", "admin")
	}
	if _, allowed := limiter.check("203.0.113.9", "another-user"); allowed {
		t.Fatal("IP was not locked")
	}
	if _, allowed := limiter.check("198.51.100.4", "ADMIN"); allowed {
		t.Fatal("account was not locked case-insensitively")
	}
	now = now.Add(loginLockout + time.Second)
	if _, allowed := limiter.check("203.0.113.9", "admin"); !allowed {
		t.Fatal("login remained locked after the lockout expired")
	}
}

func TestLoginLimiterSuccessClearsBothDimensions(t *testing.T) {
	limiter := newLoginLimiter()
	for range loginMaxAttempts {
		limiter.failure("203.0.113.9", "admin")
	}
	limiter.success("203.0.113.9", "admin")
	if _, allowed := limiter.check("203.0.113.9", "admin"); !allowed {
		t.Fatal("successful login did not clear attempts")
	}
}
