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
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open the sign-in lock: %w", err)
	}
	deadline := time.Now().Add(wait)
	for {
		ok, err := tryLock(f)
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("lock the sign-in: %w", err)
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
