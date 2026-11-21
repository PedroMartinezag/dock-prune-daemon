//go:build unix

// Package daemon coordinates the autonomous storage control plane lifecycle,
// kernel PID file locking, SIGHUP hot-reloads, debounced Docker event streams,
// and cryptographic audit persistence.
package daemon

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// ErrPIDLocked is returned when another daemon process holds the exclusive kernel lock.
var ErrPIDLocked = errors.New("exclusive daemon PID lock is already held by another process")

// PIDLock holds an open file descriptor locked via kernel syscall.Flock(LOCK_EX | LOCK_NB).
type PIDLock struct {
	path string
	file *os.File
}

// AcquirePIDLock acquires a non-blocking exclusive kernel flock on path and writes
// the current process PID into the lockfile.
func AcquirePIDLock(path string) (*PIDLock, error) {
	cleanPath := strings.TrimSpace(path)
	if cleanPath == "" {
		return nil, errors.New("pid_file path cannot be empty")
	}
	if err := os.MkdirAll(filepath.Dir(cleanPath), 0o750); err != nil {
		return nil, fmt.Errorf("create pid directory: %w", err)
	}

	f, err := os.OpenFile(cleanPath, os.O_CREATE|os.O_RDWR, 0o640)
	if err != nil {
		return nil, fmt.Errorf("open pid file %q: %w", cleanPath, err)
	}

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		holder := readExistingHolderPID(f)
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			if holder != "" {
				return nil, fmt.Errorf("%w (path=%s, holder_pid=%s)", ErrPIDLocked, cleanPath, holder)
			}
			return nil, fmt.Errorf("%w (path=%s)", ErrPIDLocked, cleanPath)
		}
		return nil, fmt.Errorf("flock %q: %w", cleanPath, err)
	}

	if err := f.Truncate(0); err == nil {
		_, _ = f.Seek(0, 0)
		_, _ = f.WriteString(strconv.Itoa(os.Getpid()) + "\n")
		_ = f.Sync()
	}

	return &PIDLock{
		path: cleanPath,
		file: f,
	}, nil
}

// Release removes the PID file while still holding LOCK_EX (preventing deletion races
// against successor processes), unlocks the descriptor, and closes it.
func (l *PIDLock) Release() error {
	if l == nil || l.file == nil {
		return nil
	}
	f := l.file
	l.file = nil

	_ = os.Remove(l.path)
	unlockErr := syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	closeErr := f.Close()
	return errors.Join(unlockErr, closeErr)
}

func readExistingHolderPID(f *os.File) string {
	buf := make([]byte, 32)
	n, err := f.ReadAt(buf, 0)
	if err != nil && n == 0 {
		return ""
	}
	return strings.TrimSpace(string(buf[:n]))
}

// ReloadSignals returns OS signals that trigger zero-downtime configuration hot-reload.
func ReloadSignals() []os.Signal {
	return []os.Signal{syscall.SIGHUP}
}

// TriggerSignals returns OS signals that trigger an immediate forced reclamation cycle.
func TriggerSignals() []os.Signal {
	return []os.Signal{syscall.SIGUSR1}
}
