package controller

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestControllerIdentityPersistsWithPrivatePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "controller-identity.key")
	first, err := loadOrCreateControllerIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := loadOrCreateControllerIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.publicKey(), second.publicKey()) {
		t.Fatal("controller identity changed after reload")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("controller identity mode = %v", info.Mode().Perm())
	}
}

func TestControllerIdentityRejectsInvalidFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "controller-identity.key")
	if err := os.WriteFile(path, []byte("too-short"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateControllerIdentity(path); err == nil {
		t.Fatal("invalid controller identity length was accepted")
	}
	if err := os.WriteFile(path, make([]byte, 32), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateControllerIdentity(path); err == nil {
		t.Fatal("controller identity with broad permissions was accepted")
	}
}
