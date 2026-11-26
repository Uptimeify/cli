package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/uptimeify/cli/internal/clierr"
)

// The server rotates the refresh token on every use and has no grace period: a refresh token that
// is presented twice revokes the whole device (cli-oauth-token.ts in the Uptimeify server). Two
// uptimeify processes renewing at the same moment would do exactly that. So renewing, storing a
// new sign-in and signing out run under an exclusive operating system lock, one lock per host. The
// lock file stays empty; it carries the lock and nothing else, never a secret.

// lockWait is how long a process waits for another one that is renewing the sign-in.
const lockWait = 45 * time.Second

// lockPoll is a variable only so tests can lower it.
var lockPoll = 50 * time.Millisecond

// lockPath returns the lock file for origin under the user cache directory dir, or "" when there
// is no cache directory.
func lockPath(dir, origin string) string {
	if dir == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(origin))
	return filepath.Join(dir, "uptimeify", "locks", hex.EncodeToString(sum[:])[:32]+".lock")
}

// acquireLock takes the exclusive lock on path. It retries every lockPoll until wait has passed or
// ctx ends. release unlocks and closes the file; calling it more than once is harmless.
func acquireLock(ctx context.Context, path string, wait time.Duration) (release func(), err error) {
	if path == "" {
		return nil, clierr.New(clierr.General, "no user cache directory for the sign-in lock: set HOME")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create the sign-in lock directory: %w", err)
	}
	f, err := openLockFile(path)
	if err != nil {
		return nil, fmt.Errorf("open the sign-in lock: %w", err)
	}
	deadline := time.Now().Add(wait)
	for reopened := 0; ; {
		ok, err := tryLock(f)
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("lock the sign-in: %w", err)
		}
		if ok && !sameAsPath(f, path) {
			// The path was replaced after the open (a swapped file or symlink): what is locked is
			// not the lock file. Let go and open the path again, a few times at most.
			_ = unlockFile(f)
			f.Close()
			if reopened++; reopened > 3 {
				return nil, clierr.New(clierr.General, "the sign-in lock file keeps changing under the CLI: check %s", filepath.Dir(path))
			}
			if f, err = openLockFile(path); err != nil {
				return nil, fmt.Errorf("open the sign-in lock: %w", err)
			}
			continue
		}
		if ok {
			var once sync.Once
			return func() {
				once.Do(func() {
					_ = unlockFile(f)
					_ = f.Close()
				})
			}, nil
		}
		if !time.Now().Before(deadline) {
			f.Close()
			return nil, clierr.New(clierr.General, "another uptimeify process is renewing the sign-in for this host: try again in a minute")
		}
		timer := time.NewTimer(lockPoll)
		select {
		case <-ctx.Done():
			timer.Stop()
			f.Close()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

// sameAsPath reports whether f is the regular file that path names now, not a symlink to it.
func sameAsPath(f *os.File, path string) bool {
	opened, err := f.Stat()
	if err != nil {
		return false
	}
	named, err := os.Lstat(path)
	return err == nil && named.Mode().IsRegular() && os.SameFile(opened, named)
}
