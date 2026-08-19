package controller

import (
	"strings"
	"sync"
	"time"
)

const (
	loginMaxAttempts = 5
	loginWindow      = 15 * time.Minute
	loginLockout     = 15 * time.Minute
)

type loginAttempt struct {
	count       int
	first       time.Time
	lockedUntil time.Time
}

type loginLimiter struct {
	mu       sync.Mutex
	attempts map[string]loginAttempt
	now      func() time.Time
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{attempts: make(map[string]loginAttempt), now: time.Now}
}

func (l *loginLimiter) check(ip, username string) (time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.cleanup(now)
	for _, key := range loginAttemptKeys(ip, username) {
		attempt := l.attempts[key]
		if attempt.lockedUntil.After(now) {
			return attempt.lockedUntil.Sub(now), false
		}
	}
	return 0, true
}

func (l *loginLimiter) failure(ip, username string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	for _, key := range loginAttemptKeys(ip, username) {
		attempt := l.attempts[key]
		if attempt.first.IsZero() || now.Sub(attempt.first) > loginWindow {
			attempt = loginAttempt{first: now}
		}
		attempt.count++
		if attempt.count >= loginMaxAttempts {
			attempt.lockedUntil = now.Add(loginLockout)
		}
		l.attempts[key] = attempt
	}
}

func (l *loginLimiter) success(ip, username string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, key := range loginAttemptKeys(ip, username) {
		delete(l.attempts, key)
	}
}

func (l *loginLimiter) cleanup(now time.Time) {
	for key, attempt := range l.attempts {
		if !attempt.lockedUntil.After(now) && now.Sub(attempt.first) > loginWindow {
			delete(l.attempts, key)
		}
	}
}

func loginAttemptKeys(ip, username string) []string {
	keys := []string{"ip:" + strings.TrimSpace(ip)}
	if username = strings.ToLower(strings.TrimSpace(username)); username != "" {
		keys = append(keys, "user:"+username)
	}
	return keys
}
