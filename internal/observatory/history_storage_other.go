//go:build !linux

package observatory

import (
	"errors"
	"io/fs"
	"time"
)

var errSecureHistoryLinuxRequired = errors.New("secure Observatory history requires a Linux control host")

type secureHistoryRoot struct{}

func prepareSecureHistoryRoot(string) error { return errSecureHistoryLinuxRequired }

func openSecureHistoryRoot(string) (*secureHistoryRoot, error) {
	return nil, errSecureHistoryLinuxRequired
}

func (*secureHistoryRoot) close() error { return nil }

func (*secureHistoryRoot) ensureDirectory(string, fs.FileMode) error {
	return errSecureHistoryLinuxRequired
}

func (*secureHistoryRoot) readRegularFile(string, int, fs.FileMode) ([]byte, error) {
	return nil, errSecureHistoryLinuxRequired
}

func (*secureHistoryRoot) writeRegularFileExclusive(string, []byte, fs.FileMode) (bool, error) {
	return false, errSecureHistoryLinuxRequired
}

func (*secureHistoryRoot) syncRegularFile(string, fs.FileMode) error {
	return errSecureHistoryLinuxRequired
}

func (*secureHistoryRoot) acquireWriterLock(time.Duration) (func() error, error) {
	return nil, errSecureHistoryLinuxRequired
}

func (*secureHistoryRoot) writeIndexAtomic([]byte) error {
	return errSecureHistoryLinuxRequired
}
