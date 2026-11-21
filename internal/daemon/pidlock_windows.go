//go:build windows

package daemon

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

// ErrPIDLocked is returned when another daemon process holds the exclusive Win32 file lock.
var ErrPIDLocked = errors.New("exclusive daemon PID lock is already held by another process")

const (
	lockfileFailImmediately = 0x00000001
	lockfileExclusiveLock   = 0x00000002
)

var (
	modKernel32Lock  = syscall.NewLazyDLL("kernel32.dll")
	procLockFileEx   = modKernel32Lock.NewProc("LockFileEx")
	procUnlockFileEx = modKernel32Lock.NewProc("UnlockFileEx")
)

// PIDLock holds an open file handle locked via Win32 LockFileEx.
type PIDLock struct {
	path string
	file *os.File
}

// AcquirePIDLock acquires a non-blocking exclusive Win32 byte-range lock on path.
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

	var overlapped syscall.Overlapped
	r1, _, callErr := procLockFileEx.Call(
		f.Fd(),
		uintptr(lockfileExclusiveLock|lockfileFailImmediately),
		0,
		1,
		0,
		uintptr(unsafe.Pointer(&overlapped)),
	)
	if r1 == 0 {
		_ = f.Close()
		if callErr != nil {
			return nil, fmt.Errorf("%w (path=%s): %v", ErrPIDLocked, cleanPath, callErr)
		}
		return nil, fmt.Errorf("%w (path=%s)", ErrPIDLocked, cleanPath)
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

// Release unlocks the Win32 file handle, closes it, and removes the lockfile.
func (l *PIDLock) Release() error {
	if l == nil || l.file == nil {
		return nil
	}
	f := l.file
	l.file = nil

	var overlapped syscall.Overlapped
	_, _, _ = procUnlockFileEx.Call(
		f.Fd(),
		0,
		1,
		0,
		uintptr(unsafe.Pointer(&overlapped)),
	)
	closeErr := f.Close()
	_ = os.Remove(l.path)
	return closeErr
}

// ReloadSignals returns OS signals that trigger configuration reload on Windows.
func ReloadSignals() []os.Signal {
	return []os.Signal{syscall.SIGHUP}
}

// TriggerSignals returns nil on Windows (use POST /v1/trigger on Windows hosts).
func TriggerSignals() []os.Signal {
	return nil
}
