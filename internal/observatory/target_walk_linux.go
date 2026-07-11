//go:build linux

package observatory

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	pathpkg "path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const targetOpenFlags = syscall.O_RDONLY | syscall.O_CLOEXEC | syscall.O_NOFOLLOW | syscall.O_NONBLOCK

func walkTargetTree(root string, maxEntries int, visit targetWalkFunc) error {
	directory, err := openTargetDirectoryPath(root)
	if err != nil {
		return err
	}
	defer directory.Close()

	info, err := directory.Stat()
	if err != nil {
		return fmt.Errorf("inspect pinned target root: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("behavior target root is not a directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("inspect pinned target root device")
	}
	descend, err := visit(".", info, directory)
	if err != nil || !descend {
		return err
	}
	seen := 1
	return walkPinnedTargetDirectory(directory, ".", uint64(stat.Dev), maxEntries, &seen, visit)
}

func openTargetDirectoryPath(root string) (*os.File, error) {
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve behavior target root: %w", err)
	}
	absolute = filepath.Clean(absolute)
	if !filepath.IsAbs(absolute) {
		return nil, fmt.Errorf("behavior target root must be absolute")
	}

	fd, err := syscall.Open(string(filepath.Separator), targetOpenFlags|syscall.O_DIRECTORY, 0)
	if err != nil {
		return nil, fmt.Errorf("pin filesystem root: %w", err)
	}
	components := strings.Split(strings.TrimPrefix(absolute, string(filepath.Separator)), string(filepath.Separator))
	for _, component := range components {
		if component == "" || component == "." {
			continue
		}
		next, openErr := syscall.Openat(fd, component, targetOpenFlags|syscall.O_DIRECTORY, 0)
		closeErr := syscall.Close(fd)
		if openErr != nil {
			if errors.Is(openErr, syscall.ELOOP) || errors.Is(openErr, syscall.ENOTDIR) {
				return nil, fmt.Errorf("behavior target path contains an unsupported symlink or non-directory component at %s", component)
			}
			return nil, fmt.Errorf("securely open behavior target path component %s: %w", component, openErr)
		}
		if closeErr != nil {
			syscall.Close(next)
			return nil, fmt.Errorf("close pinned behavior target ancestor: %w", closeErr)
		}
		fd = next
	}
	return os.NewFile(uintptr(fd), absolute), nil
}

func walkPinnedTargetDirectory(directory *os.File, rel string, rootDevice uint64, maxEntries int, seen *int, visit targetWalkFunc) error {
	const directoryBatchSize = 128
	for {
		readSize := directoryBatchSize
		if remaining := maxEntries - *seen; remaining < readSize {
			// Read one beyond the remaining budget so an oversized tree is
			// rejected without materializing the rest of an untrusted directory.
			readSize = remaining + 1
		}
		if readSize < 1 {
			readSize = 1
		}
		entries, readErr := directory.ReadDir(readSize)
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return fmt.Errorf("read target directory %s: %w", rel, readErr)
		}
		if len(entries) == 0 {
			return nil
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

		for _, entry := range entries {
			if *seen >= maxEntries {
				return fmt.Errorf("target exceeds maxFiles entries (%d)", maxEntries)
			}
			*seen++
			childRel := entry.Name()
			if rel != "." {
				childRel = pathpkg.Join(rel, entry.Name())
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return fmt.Errorf("target contains unsupported symlink: %s", childRel)
			}

			pathFD, openErr := unix.Openat(int(directory.Fd()), entry.Name(), unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
			if openErr != nil {
				if errors.Is(openErr, unix.ELOOP) {
					return fmt.Errorf("target contains unsupported symlink: %s", childRel)
				}
				return fmt.Errorf("securely pin target entry %s: %w", childRel, openErr)
			}
			pinned := os.NewFile(uintptr(pathFD), childRel)
			info, statErr := pinned.Stat()
			if statErr != nil {
				pinned.Close()
				return fmt.Errorf("inspect pinned target entry %s: %w", childRel, statErr)
			}
			if !info.Mode().IsRegular() && !info.IsDir() {
				pinned.Close()
				return fmt.Errorf("target contains unsupported non-regular file: %s", childRel)
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				pinned.Close()
				return fmt.Errorf("inspect pinned target entry device: %s", childRel)
			}
			if uint64(stat.Dev) != rootDevice {
				pinned.Close()
				return fmt.Errorf("target entry crosses a filesystem boundary: %s", childRel)
			}
			if info.Mode().IsRegular() && stat.Nlink != 1 {
				pinned.Close()
				return fmt.Errorf("target contains unsupported hard-linked file: %s", childRel)
			}
			reopenFlags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NONBLOCK
			if info.IsDir() {
				reopenFlags |= unix.O_DIRECTORY
			}
			fdPath := "/proc/self/fd/" + strconv.Itoa(pathFD)
			fd, reopenErr := unix.Open(fdPath, reopenFlags, 0)
			if reopenErr != nil {
				pinned.Close()
				return fmt.Errorf("open pinned target entry %s: %w", childRel, reopenErr)
			}
			child := os.NewFile(uintptr(fd), childRel)
			reopenedInfo, reopenStatErr := child.Stat()
			if reopenStatErr != nil || !os.SameFile(info, reopenedInfo) || reopenedInfo.Mode() != info.Mode() {
				child.Close()
				pinned.Close()
				return fmt.Errorf("target entry changed while opening: %s", childRel)
			}
			if closeErr := pinned.Close(); closeErr != nil {
				child.Close()
				return fmt.Errorf("close pinned target entry handle %s: %w", childRel, closeErr)
			}
			info = reopenedInfo

			descend, visitErr := visit(childRel, info, child)
			if visitErr == nil && info.IsDir() && descend {
				visitErr = walkPinnedTargetDirectory(child, childRel, rootDevice, maxEntries, seen, visit)
			}
			closeErr := child.Close()
			if visitErr != nil {
				return visitErr
			}
			if closeErr != nil {
				return fmt.Errorf("close pinned target entry %s: %w", childRel, closeErr)
			}
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
	}
}

func sameTargetFileSnapshot(before fs.FileInfo, after fs.FileInfo) bool {
	if before == nil || after == nil || !before.Mode().IsRegular() || !after.Mode().IsRegular() ||
		!os.SameFile(before, after) || before.Size() != after.Size() || before.Mode() != after.Mode() ||
		!before.ModTime().Equal(after.ModTime()) {
		return false
	}
	beforeStat, beforeOK := before.Sys().(*syscall.Stat_t)
	afterStat, afterOK := after.Sys().(*syscall.Stat_t)
	return beforeOK && afterOK && beforeStat.Dev == afterStat.Dev && beforeStat.Ino == afterStat.Ino &&
		beforeStat.Nlink == afterStat.Nlink && beforeStat.Mtim == afterStat.Mtim && beforeStat.Ctim == afterStat.Ctim
}
