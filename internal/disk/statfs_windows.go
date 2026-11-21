//go:build windows

package disk

import (
	"path/filepath"
	"syscall"
	"unsafe"
)

var (
	modKernel32             = syscall.NewLazyDLL("kernel32.dll")
	procGetDiskFreeSpaceExW = modKernel32.NewProc("GetDiskFreeSpaceExW")
)

func statFS(path string) (rawStatFS, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return rawStatFS{}, err
	}
	pathPtr, err := syscall.UTF16PtrFromString(absPath)
	if err != nil {
		return rawStatFS{}, err
	}

	var freeBytesAvail uint64
	var totalBytes uint64
	var totalFreeBytes uint64

	r1, _, callErr := procGetDiskFreeSpaceExW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(unsafe.Pointer(&freeBytesAvail)),
		uintptr(unsafe.Pointer(&totalBytes)),
		uintptr(unsafe.Pointer(&totalFreeBytes)),
	)
	if r1 == 0 {
		if callErr != nil && callErr != syscall.Errno(0) {
			return rawStatFS{}, callErr
		}
		return rawStatFS{}, syscall.EINVAL
	}

	return rawStatFS{
		totalBytes:   totalBytes,
		freeAvail:    freeBytesAvail,
		rawFreeBytes: totalFreeBytes,
		totalInodes:  0,
		freeInodes:   0,
	}, nil
}
