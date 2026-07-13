//go:build linux

package observatory

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const historyIndexTemporaryPrefix = ".index.json.tmp-"

type secureHistoryRoot struct {
	dir *os.File
	uid uint32
}

func prepareSecureHistoryRoot(path string) error {
	parent := filepath.Dir(path)
	parentFD, err := openDirectoryPathNoSymlinks(parent, true)
	if err != nil {
		return fmt.Errorf("open artifacts directory without following links: %w", err)
	}
	defer unix.Close(parentFD)
	if err := unix.Mkdirat(parentFD, filepath.Base(path), uint32(historyDirectoryMode.Perm())); err != nil && !errors.Is(err, syscall.EEXIST) {
		return err
	} else if err == nil {
		if err := unix.Fsync(parentFD); err != nil {
			return fmt.Errorf("sync artifacts directory after creating history root: %w", err)
		}
	}
	root, err := openSecureHistoryRoot(path)
	if err != nil {
		return err
	}
	return root.close()
}

func openSecureHistoryRoot(path string) (*secureHistoryRoot, error) {
	fd, err := openDirectoryPathNoSymlinks(path, false)
	if err != nil {
		return nil, fmt.Errorf("unsafe history root: open without following links: %w", err)
	}
	root := &secureHistoryRoot{dir: os.NewFile(uintptr(fd), path), uid: uint32(os.Geteuid())}
	if err := validateHistoryDescriptor(fd, root.uid, unix.S_IFDIR, historyDirectoryMode, "history root"); err != nil {
		root.close()
		return nil, err
	}
	return root, nil
}

func openDirectoryPathNoSymlinks(path string, create bool) (int, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return -1, err
	}
	fd, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if err != nil {
		return -1, err
	}
	parts := strings.Split(strings.TrimPrefix(filepath.Clean(absolute), string(filepath.Separator)), string(filepath.Separator))
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		next, openErr := unix.Openat(fd, part, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
		if errors.Is(openErr, syscall.ENOENT) && create {
			mkdirErr := unix.Mkdirat(fd, part, uint32(historyDirectoryMode.Perm()))
			if mkdirErr != nil && !errors.Is(mkdirErr, syscall.EEXIST) {
				unix.Close(fd)
				return -1, mkdirErr
			}
			if mkdirErr == nil {
				if syncErr := unix.Fsync(fd); syncErr != nil {
					unix.Close(fd)
					return -1, syncErr
				}
			}
			next, openErr = unix.Openat(fd, part, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
		}
		unix.Close(fd)
		if openErr != nil {
			return -1, openErr
		}
		fd = next
	}
	return fd, nil
}

func (root *secureHistoryRoot) close() error {
	if root == nil || root.dir == nil {
		return nil
	}
	return root.dir.Close()
}

func validateHistoryDescriptor(fd int, uid uint32, kind uint32, mode fs.FileMode, label string) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fmt.Errorf("unsafe %s: stat: %w", label, err)
	}
	if stat.Mode&unix.S_IFMT != kind {
		return fmt.Errorf("unsafe %s: unexpected file type", label)
	}
	if stat.Uid != uid {
		return fmt.Errorf("unsafe %s: owned by uid %d, expected uid %d", label, stat.Uid, uid)
	}
	if fs.FileMode(stat.Mode&0o7777) != mode.Perm() {
		return fmt.Errorf("unsafe %s: mode is %04o, expected %04o", label, stat.Mode&0o7777, mode.Perm())
	}
	return nil
}

func validateHistoryRelativePath(rel string) ([]string, error) {
	clean := filepath.Clean(rel)
	if clean == "." {
		return nil, nil
	}
	if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("unsafe history path %q escapes the store", rel)
	}
	parts := strings.Split(clean, string(filepath.Separator))
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return nil, fmt.Errorf("unsafe history path %q", rel)
		}
	}
	return parts, nil
}

func (root *secureHistoryRoot) openDirectory(rel string, create bool, mode fs.FileMode) (*os.File, error) {
	parts, err := validateHistoryRelativePath(rel)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Openat(int(root.dir.Fd()), ".", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	for _, part := range parts {
		if create {
			mkdirErr := unix.Mkdirat(fd, part, uint32(mode.Perm()))
			if mkdirErr != nil && !errors.Is(mkdirErr, syscall.EEXIST) {
				unix.Close(fd)
				return nil, fmt.Errorf("create secure history directory %q: %w", rel, mkdirErr)
			}
			if mkdirErr == nil {
				if err := unix.Fsync(fd); err != nil {
					unix.Close(fd)
					return nil, fmt.Errorf("sync secure history directory parent %q: %w", rel, err)
				}
			}
		}
		next, openErr := unix.Openat(fd, part, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
		unix.Close(fd)
		if openErr != nil {
			return nil, fmt.Errorf("open secure history directory %q without following links: %w", rel, openErr)
		}
		fd = next
		if err := validateHistoryDescriptor(fd, root.uid, unix.S_IFDIR, mode, "history directory "+rel); err != nil {
			unix.Close(fd)
			return nil, err
		}
	}
	return os.NewFile(uintptr(fd), filepath.Join(root.dir.Name(), rel)), nil
}

func (root *secureHistoryRoot) ensureDirectory(rel string, mode fs.FileMode) error {
	dir, err := root.openDirectory(rel, true, mode)
	if err != nil {
		return err
	}
	return dir.Close()
}

func (root *secureHistoryRoot) openRegular(rel string, flags int, mode fs.FileMode, exclusive bool) (*os.File, error) {
	parts, err := validateHistoryRelativePath(rel)
	if err != nil {
		return nil, err
	}
	if len(parts) == 0 {
		return nil, errors.New("unsafe history file path refers to the root")
	}
	parentRel := filepath.Join(parts[:len(parts)-1]...)
	if len(parts) == 1 {
		parentRel = "."
	}
	parent, err := root.openDirectory(parentRel, false, historyDirectoryMode)
	if err != nil {
		if errors.Is(err, syscall.ENOENT) {
			return nil, errHistoryPathNotExist
		}
		return nil, err
	}
	defer parent.Close()
	openFlags := flags | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
	if exclusive {
		openFlags |= unix.O_CREAT | unix.O_EXCL
	}
	fd, err := unix.Openat(int(parent.Fd()), parts[len(parts)-1], openFlags, uint32(mode.Perm()))
	if err != nil {
		if errors.Is(err, syscall.EEXIST) {
			return nil, errHistoryPathExist
		}
		if errors.Is(err, syscall.ENOENT) {
			return nil, errHistoryPathNotExist
		}
		return nil, fmt.Errorf("open secure history file %q without following links: %w", rel, err)
	}
	if err := validateHistoryDescriptor(fd, root.uid, unix.S_IFREG, mode, "history file "+rel); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), filepath.Join(root.dir.Name(), rel)), nil
}

func (root *secureHistoryRoot) readRegularFile(rel string, maxBytes int, mode fs.FileMode) ([]byte, error) {
	file, err := root.openRegular(rel, unix.O_RDONLY, mode, false)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > int64(maxBytes) {
		return nil, fmt.Errorf("history file %q exceeds size bound", rel)
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(maxBytes)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxBytes {
		return nil, fmt.Errorf("history file %q exceeds size bound", rel)
	}
	return data, nil
}

func (root *secureHistoryRoot) writeRegularFileExclusive(rel string, payload []byte, mode fs.FileMode) (bool, error) {
	file, err := root.openRegular(rel, unix.O_WRONLY, mode, true)
	if err != nil {
		return false, err
	}
	if err := writeAndSyncHistoryFile(file, payload); err != nil {
		return true, err
	}
	if err := root.syncParent(rel); err != nil {
		return true, err
	}
	return true, nil
}

func writeAndSyncHistoryFile(file *os.File, payload []byte) error {
	for len(payload) > 0 {
		written, err := file.Write(payload)
		if err != nil {
			file.Close()
			return err
		}
		if written == 0 {
			file.Close()
			return io.ErrShortWrite
		}
		payload = payload[written:]
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

func (root *secureHistoryRoot) syncParent(rel string) error {
	parentRel := filepath.Dir(rel)
	parent, err := root.openDirectory(parentRel, false, historyDirectoryMode)
	if err != nil {
		return err
	}
	defer parent.Close()
	return unix.Fsync(int(parent.Fd()))
}

func (root *secureHistoryRoot) syncRegularFile(rel string, mode fs.FileMode) error {
	file, err := root.openRegular(rel, unix.O_RDONLY, mode, false)
	if err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return fmt.Errorf("sync existing history file %q: %w", rel, err)
	}
	if err := file.Close(); err != nil {
		return err
	}
	return root.syncParent(rel)
}

func (root *secureHistoryRoot) acquireWriterLock(timeout time.Duration) (func() error, error) {
	lock, err := root.openRegular(".writer.lock", unix.O_RDWR, historyFileMode, true)
	if errors.Is(err, errHistoryPathExist) {
		lock, err = root.openRegular(".writer.lock", unix.O_RDWR, historyFileMode, false)
	}
	if err != nil {
		return nil, err
	}
	if timeout <= 0 {
		timeout = historyWriterLockTimeout
	}
	deadline := time.Now().Add(timeout)
	for {
		err = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return func() error {
				unlockErr := unix.Flock(int(lock.Fd()), unix.LOCK_UN)
				closeErr := lock.Close()
				if unlockErr != nil {
					return unlockErr
				}
				return closeErr
			}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			lock.Close()
			return nil, fmt.Errorf("lock history writer: %w", err)
		}
		if !time.Now().Before(deadline) {
			lock.Close()
			return nil, fmt.Errorf("history: timed out after %s waiting for writer lock", timeout)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (root *secureHistoryRoot) writeIndexAtomic(payload []byte) error {
	tempName, err := newHistoryIndexTemporaryName()
	if err != nil {
		return err
	}
	return root.writeIndexAtomicNamed(payload, tempName)
}

func newHistoryIndexTemporaryName() (string, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", fmt.Errorf("generate temporary history index name: %w", err)
	}
	return historyIndexTemporaryPrefix + hex.EncodeToString(nonce[:]), nil
}

func (root *secureHistoryRoot) writeIndexAtomicNamed(payload []byte, tempName string) error {
	if !strings.HasPrefix(tempName, historyIndexTemporaryPrefix) {
		return errors.New("unsafe temporary history index name")
	}
	if current, err := root.openRegular("index.json", unix.O_RDONLY, historyFileMode, false); err == nil {
		current.Close()
	} else if !errors.Is(err, errHistoryPathNotExist) {
		return fmt.Errorf("validate history index before replacement: %w", err)
	}
	temp, err := root.openRegular(tempName, unix.O_WRONLY, historyFileMode, true)
	if err != nil {
		return fmt.Errorf("create secure temporary history index: %w", err)
	}
	if err := writeAndSyncHistoryFile(temp, payload); err != nil {
		return fmt.Errorf("write temporary history index: %w", err)
	}
	if current, err := root.openRegular("index.json", unix.O_RDONLY, historyFileMode, false); err == nil {
		current.Close()
	} else if !errors.Is(err, errHistoryPathNotExist) {
		return fmt.Errorf("validate history index before atomic replacement: %w", err)
	}
	if err := unix.Renameat(int(root.dir.Fd()), tempName, int(root.dir.Fd()), "index.json"); err != nil {
		return fmt.Errorf("atomically replace history index: %w", err)
	}
	if err := unix.Fsync(int(root.dir.Fd())); err != nil {
		return fmt.Errorf("sync history directory after index replacement: %w", err)
	}
	return nil
}
