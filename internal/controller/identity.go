package controller

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/T-Matrix/mmwx-guard/internal/protocol"
)

type controllerIdentity struct {
	private ed25519.PrivateKey
	public  ed25519.PublicKey
}

func loadOrCreateControllerIdentity(path string) (*controllerIdentity, error) {
	seed, err := os.ReadFile(path)
	if err == nil {
		info, statErr := os.Stat(path)
		if statErr != nil || !info.Mode().IsRegular() {
			return nil, errors.New("controller identity is not a regular file")
		}
		if info.Mode().Perm()&0077 != 0 {
			return nil, fmt.Errorf("controller identity permissions %04o are too broad", info.Mode().Perm())
		}
		if len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("controller identity seed has invalid length %d", len(seed))
		}
		private := ed25519.NewKeyFromSeed(seed)
		return &controllerIdentity{private: private, public: private.Public().(ed25519.PublicKey)}, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read controller identity: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("create controller identity directory: %w", err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate controller identity: %w", err)
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".controller-identity-*")
	if err != nil {
		return nil, fmt.Errorf("create controller identity: %w", err)
	}
	temporaryPath := file.Name()
	defer os.Remove(temporaryPath)
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return nil, fmt.Errorf("secure controller identity: %w", err)
	}
	if _, err := file.Write(private.Seed()); err != nil {
		file.Close()
		return nil, fmt.Errorf("write controller identity: %w", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return nil, fmt.Errorf("sync controller identity: %w", err)
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("close controller identity: %w", err)
	}
	if err := os.Link(temporaryPath, path); errors.Is(err, os.ErrExist) {
		return loadOrCreateControllerIdentity(path)
	} else if err != nil {
		return nil, fmt.Errorf("publish controller identity: %w", err)
	}
	if directory, openErr := os.Open(filepath.Dir(path)); openErr == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
	return &controllerIdentity{private: private, public: public}, nil
}

func (i *controllerIdentity) publicKey() []byte          { return append([]byte(nil), i.public...) }
func (i *controllerIdentity) fingerprint() string        { return protocol.KeyFingerprint(i.public) }
func (i *controllerIdentity) sign(message []byte) []byte { return ed25519.Sign(i.private, message) }
