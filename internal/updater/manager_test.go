package updater

import (
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestWriteJSONAtomicUsesDirectoryOwnerAndRequestedMode(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "status.json")
	if err := writeJSONAtomic(path, Status{State: "completed", Version: "v1.2.3"}, 0600); err != nil {
		t.Fatalf("write initial status: %v", err)
	}
	if err := writeJSONAtomic(path, Status{State: "failed", Version: "v1.2.4"}, 0600); err != nil {
		t.Fatalf("replace status: %v", err)
	}

	directoryInfo, err := os.Stat(directory)
	if err != nil {
		t.Fatal(err)
	}
	fileInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	directoryOwner, directoryOK := directoryInfo.Sys().(*syscall.Stat_t)
	fileOwner, fileOK := fileInfo.Sys().(*syscall.Stat_t)
	if directoryOK && fileOK && (directoryOwner.Uid != fileOwner.Uid || directoryOwner.Gid != fileOwner.Gid) {
		t.Fatalf("status owner %d:%d does not match directory owner %d:%d", fileOwner.Uid, fileOwner.Gid, directoryOwner.Uid, directoryOwner.Gid)
	}
	if got := fileInfo.Mode().Perm(); got != 0600 {
		t.Fatalf("status mode = %o, want 600", got)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var status Status
	if err := json.Unmarshal(raw, &status); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if status.State != "failed" || status.Version != "v1.2.4" {
		t.Fatalf("unexpected status: %+v", status)
	}
}
