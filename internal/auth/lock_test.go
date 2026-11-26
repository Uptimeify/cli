package auth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/uptimeify/cli/internal/clierr"
)

func init() { helpers["lock"] = lockHelper }

// lockHelper takes the lock at UPTIMEIFY_AUTH_TEST_LOCK, prints "locked", creates the file
// UPTIMEIFY_AUTH_TEST_READY and holds the lock until the file UPTIMEIFY_AUTH_TEST_RELEASE exists.
func lockHelper() int {
	path := os.Getenv("UPTIMEIFY_AUTH_TEST_LOCK")
	ready := os.Getenv("UPTIMEIFY_AUTH_TEST_READY")
	release := os.Getenv("UPTIMEIFY_AUTH_TEST_RELEASE")
	unlock, err := acquireLock(context.Background(), path, 10*time.Second)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer unlock()
	fmt.Println("locked")
	if err := os.WriteFile(ready, nil, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err := os.Stat(release); err == nil {
			return 0
		}
		if time.Now().After(deadline) {
			fmt.Fprintln(os.Stderr, "the release file never appeared")
			return 1
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func lockWaitForFile(t *testing.T, path string, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s did not appear within %v", path, d)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestLockPathPerHost(t *testing.T) {
	dir := t.TempDir()
	a := lockPath(dir, "https://a.example")
	b := lockPath(dir, "https://b.example")
	if a == b {
		t.Fatalf("both hosts share the lock %s", a)
	}
	name := regexp.MustCompile(`^[0-9a-f]{32}\.lock$`)
	for _, p := range []string{a, b} {
		if got, want := filepath.Dir(p), filepath.Join(dir, "uptimeify", "locks"); got != want {
			t.Errorf("lock dir = %s, want %s", got, want)
		}
		if !name.MatchString(filepath.Base(p)) {
			t.Errorf("lock name = %s", filepath.Base(p))
		}
	}
}

func TestLockExcludesOtherProcess(t *testing.T) {
	dir := t.TempDir()
	path := lockPath(dir, "https://uptimeify.io")
	ready := filepath.Join(dir, "ready")
	release := filepath.Join(dir, "release")
	cmd := startHelper(t, "lock",
		"UPTIMEIFY_AUTH_TEST_LOCK="+path,
		"UPTIMEIFY_AUTH_TEST_READY="+ready,
		"UPTIMEIFY_AUTH_TEST_RELEASE="+release,
	)
	lockWaitForFile(t, ready, 10*time.Second)

	unlock, err := acquireLock(context.Background(), path, 200*time.Millisecond)
	if err == nil {
		unlock()
		t.Fatal("took the lock while the other process held it")
	}
	if !strings.Contains(err.Error(), "another uptimeify process") || clierr.ExitCode(err) != clierr.General {
		t.Fatalf("err = %v (exit %d)", err, clierr.ExitCode(err))
	}

	if err := os.WriteFile(release, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("helper: %v, stderr: %s", err, cmd.Stderr)
	}
	if got := cmd.Stdout.(*bytes.Buffer).String(); got != "locked\n" {
		t.Errorf("helper stdout = %q", got)
	}
	unlock, err = acquireLock(context.Background(), path, 5*time.Second)
	if err != nil {
		t.Fatalf("lock after release: %v", err)
	}
	unlock()
}

func TestLockHonoursContext(t *testing.T) {
	path := lockPath(t.TempDir(), "https://uptimeify.io")
	unlock, err := acquireLock(context.Background(), path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	second, err := acquireLock(ctx, path, 10*time.Second)
	if err == nil {
		second()
		t.Fatal("a second open file took the held lock")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}
}

func TestLockWithoutCacheDir(t *testing.T) {
	if p := lockPath("", "https://x"); p != "" {
		t.Fatalf("lockPath without dir = %q", p)
	}
	start := time.Now()
	_, err := acquireLock(context.Background(), "", time.Second)
	if err == nil || !strings.Contains(err.Error(), "no user cache directory") || clierr.ExitCode(err) != clierr.General {
		t.Fatalf("err = %v (exit %d)", err, clierr.ExitCode(err))
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Errorf("waited %v instead of failing at once", time.Since(start))
	}
}

func TestLockFileHasNoContent(t *testing.T) {
	path := lockPath(t.TempDir(), "https://uptimeify.io")
	unlock, err := acquireLock(context.Background(), path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	unlock()
	unlock() // a second release is harmless
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() != 0 {
		t.Errorf("lock file has %d bytes", fi.Size())
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("lock file mode = %v", fi.Mode().Perm())
	}
}
