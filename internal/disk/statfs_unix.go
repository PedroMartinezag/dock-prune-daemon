//go:build unix

package disk

import (
	"fmt"
	"math"
	"syscall"
)

func statFS(path string) (rawStatFS, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return rawStatFS{}, err
	}

	blockSize := toSafeUint64(st.Bsize)
	if blockSize == 0 {
		return rawStatFS{}, fmt.Errorf("kernel returned invalid zero block size for %q", path)
	}

	blocks := toSafeUint64(st.Blocks)
	bfree := toSafeUint64(st.Bfree)
	bavail := toSafeUint64(st.Bavail)

	return rawStatFS{
		totalBytes:   mulSaturatingUint64(blocks, blockSize),
		freeAvail:    mulSaturatingUint64(bavail, blockSize),
		rawFreeBytes: mulSaturatingUint64(bfree, blockSize),
		totalInodes:  toSafeUint64(st.Files),
		freeInodes:   toSafeUint64(st.Ffree),
	}, nil
}

// toSafeUint64 converts platform-dependent Statfs integer fields (which vary
// between signed int64 and unsigned uint64/uint32 across Linux, macOS, and BSDs)
// without wrapping negative reserved-block counts into huge uint64 values.
func toSafeUint64[T ~int | ~int32 | ~int64 | ~uint | ~uint32 | ~uint64](v T) uint64 {
	if v <= 0 {
		return 0
	}
	return uint64(v)
}

func mulSaturatingUint64(a, b uint64) uint64 {
	if a == 0 || b == 0 {
		return 0
	}
	if a > math.MaxUint64/b {
		return math.MaxUint64
	}
	return a * b
}
