//go:build linux

package observatory

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func openRenderOutputDirectory(path string, mode os.FileMode) (*os.File, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve render output directory: %w", err)
	}
	absolute = filepath.Clean(absolute)
	if absolute == string(filepath.Separator) {
		return nil, errors.New("render output directory must not be the filesystem root")
	}
	flags := syscall.O_RDONLY | syscall.O_CLOEXEC | syscall.O_NOFOLLOW | syscall.O_NONBLOCK | syscall.O_DIRECTORY
	fd, err := syscall.Open(string(filepath.Separator), flags, 0)
	if err != nil {
		return nil, fmt.Errorf("pin render filesystem root: %w", err)
	}
	for _, component := range strings.Split(strings.TrimPrefix(absolute, string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" || component == "." {
			continue
		}
		next, openErr := syscall.Openat(fd, component, flags, 0)
		if errors.Is(openErr, syscall.ENOENT) {
			if mkdirErr := syscall.Mkdirat(fd, component, uint32(mode.Perm())); mkdirErr != nil && !errors.Is(mkdirErr, syscall.EEXIST) {
				syscall.Close(fd)
				return nil, fmt.Errorf("create render output path component %q: %w", component, mkdirErr)
			}
			next, openErr = syscall.Openat(fd, component, flags, 0)
		}
		if openErr != nil {
			syscall.Close(fd)
			return nil, fmt.Errorf("render output path contains an unsafe component %q: %w", component, openErr)
		}
		if closeErr := syscall.Close(fd); closeErr != nil {
			syscall.Close(next)
			return nil, fmt.Errorf("close pinned render output ancestor: %w", closeErr)
		}
		fd = next
	}
	return os.NewFile(uintptr(fd), absolute), nil
}

func openRenderOutputFile(directory *os.File, name string, mode os.FileMode) (*os.File, error) {
	if name == "" || filepath.Base(name) != name {
		return nil, errors.New("render output filename is unsafe")
	}
	flags := syscall.O_WRONLY | syscall.O_CREAT | syscall.O_CLOEXEC | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
	fd, err := syscall.Openat(int(directory.Fd()), name, flags, uint32(mode.Perm()))
	if err != nil {
		return nil, fmt.Errorf("securely open render output %q: %w", name, err)
	}
	file := os.NewFile(uintptr(fd), name)
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("inspect render output %q: %w", name, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || !ok || stat.Nlink != 1 {
		file.Close()
		return nil, fmt.Errorf("render output %q must be a single-link regular file", name)
	}
	if err := syscall.Ftruncate(fd, 0); err != nil {
		file.Close()
		return nil, fmt.Errorf("truncate render output %q: %w", name, err)
	}
	return file, nil
}
