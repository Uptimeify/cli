//go:build unix

package auth

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The lock file is never reached through a symlink: someone with write access to the cache
// directory could otherwise aim it at a file of the user's.
func TestLockRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	path := lockPath(dir, "https://uptimeify.io")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, path); err != nil {
		t.Fatal(err)
	}
	release, err := acquireLock(context.Background(), path, time.Second)
	if err == nil {
		release()
		t.Fatal("acquireLock followed a symlink")
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Errorf("victim changed: %q", b)
	}
	if fi, _ := os.Stat(victim); fi.Mode().Perm() != 0o644 {
		t.Errorf("victim mode changed: %v", fi.Mode())
	}
}
