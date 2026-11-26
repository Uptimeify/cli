//go:build windows

package auth

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// tryLock locks the first byte of f exclusively without blocking. false, nil means another handle
// holds it.
func tryLock(f *os.File) (bool, error) {
	err := windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, new(windows.Overlapped))
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func unlockFile(f *os.File) error {
	return windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, new(windows.Overlapped))
}

// openLockFile opens (or creates) the lock file. Windows has no O_NOFOLLOW; the caller compares
// the opened file with the one at the path after locking.
func openLockFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
}
