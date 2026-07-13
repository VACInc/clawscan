//go:build linux

package observatory

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// WriteGradeFile securely creates a new standalone grade artifact. It is
// intentionally create-only: existing files, symlinks, hardlinks, FIFOs, and
// symlinked ancestors are refused rather than followed or clobbered.
func WriteGradeFile(path string, grade Grade) error {
	return writeGradeFile(path, grade, true)
}

// CheckGradeOutputAvailable performs the same pinned, no-follow destination
// walk as WriteGradeFile and rejects an existing final component. Callers that
// publish evidence and a separate grade use this before changing the evidence
// file, so a known grade collision cannot leave a stale pair.
func CheckGradeOutputAvailable(path string) error {
	if path == "" || strings.HasSuffix(path, string(filepath.Separator)) || filepath.Base(path) == "." || filepath.Base(path) == string(filepath.Separator) {
		return errors.New("grade output path is invalid")
	}
	directory, err := openRenderOutputDirectory(filepath.Dir(path), 0o700)
	if err != nil {
		return fmt.Errorf("secure grade output directory: %w", err)
	}
	defer directory.Close()
	name := filepath.Base(path)
	var existing unix.Stat_t
	if err := unix.Fstatat(int(directory.Fd()), name, &existing, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		return fmt.Errorf("securely create grade output %q: %w", name, unix.EEXIST)
	} else if !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("inspect grade output destination %q: %w", name, err)
	}
	return nil
}

func writeGradeFile(path string, grade Grade, preferAnonymous bool) error {
	if err := ValidateGrade(grade); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(grade, "", "  ")
	if err != nil {
		return fmt.Errorf("encode grade: %w", err)
	}
	encoded = append(encoded, '\n')
	if len(encoded) > MaxGradeBytes {
		return fmt.Errorf("grade exceeds maximum encoded size (%d bytes)", MaxGradeBytes)
	}
	if path == "" || strings.HasSuffix(path, string(filepath.Separator)) || filepath.Base(path) == "." || filepath.Base(path) == string(filepath.Separator) {
		return errors.New("grade output path is invalid")
	}
	directory, err := openRenderOutputDirectory(filepath.Dir(path), 0o700)
	if err != nil {
		return fmt.Errorf("secure grade output directory: %w", err)
	}
	defer directory.Close()
	name := filepath.Base(path)
	file, stagingName, err := openGradeOutputStagingFile(directory, name, preferAnonymous)
	if err != nil {
		return gradeStagingError(filepath.Dir(path), stagingName, "prepare grade output", err)
	}
	published := false
	defer func() {
		if !published {
			file.Close()
		}
	}()
	if _, err := io.Copy(file, bytesReader(encoded)); err != nil {
		return gradeStagingError(filepath.Dir(path), stagingName, "write grade output", err)
	}
	if err := file.Sync(); err != nil {
		return gradeStagingError(filepath.Dir(path), stagingName, "sync grade output", err)
	}
	// Publish only after the complete artifact is durable. Until Linkat succeeds,
	// the inode has no filesystem name, so write or sync failure cannot strand a
	// partial artifact that blocks a safe retry.
	// The /proc descriptor path preserves atomic no-replace publication without
	// requiring CAP_DAC_READ_SEARCH, which AT_EMPTY_PATH requires.
	if err := publishGradeOutput(directory, file, stagingName, name); err != nil {
		return gradeStagingError(filepath.Dir(path), stagingName, fmt.Sprintf("securely publish grade output %q", name), err)
	}
	published = true
	if err := directory.Sync(); err != nil {
		file.Close()
		return fmt.Errorf("sync grade output directory: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close grade output: %w", err)
	}
	return nil
}

func gradeStagingError(directory string, stagingName string, action string, err error) error {
	if stagingName == "" {
		return fmt.Errorf("%s: %w", action, err)
	}
	// The repository's no-deletion contract applies even to failed staging
	// files. Retain the owner-only file and report it for explicit operator
	// recovery rather than silently unlinking data.
	return fmt.Errorf("%s (owner-only staging file retained at %q): %w", action, filepath.Join(directory, stagingName), err)
}

func publishGradeOutput(directory *os.File, file *os.File, stagingName string, name string) error {
	if stagingName != "" {
		return unix.Renameat2(int(directory.Fd()), stagingName, int(directory.Fd()), name, unix.RENAME_NOREPLACE)
	}
	source := fmt.Sprintf("/proc/self/fd/%d", file.Fd())
	return unix.Linkat(unix.AT_FDCWD, source, int(directory.Fd()), name, unix.AT_SYMLINK_FOLLOW)
}

func openGradeOutputStagingFile(directory *os.File, name string, preferAnonymous bool) (*os.File, string, error) {
	if preferAnonymous {
		file, err := openUnlinkedGradeOutputFile(directory, name)
		if err == nil {
			return file, "", nil
		}
		if !errors.Is(err, unix.EOPNOTSUPP) && !errors.Is(err, unix.EINVAL) && !errors.Is(err, unix.ENOSYS) {
			return nil, "", err
		}
	}
	return openNamedGradeOutputFile(directory, name)
}

func openUnlinkedGradeOutputFile(directory *os.File, name string) (*os.File, error) {
	if name == "" || filepath.Base(name) != name {
		return nil, errors.New("grade output filename is unsafe")
	}
	flags := unix.O_WRONLY | unix.O_TMPFILE | unix.O_CLOEXEC
	fd, err := unix.Openat(int(directory.Fd()), ".", flags, 0o600)
	if err != nil {
		return nil, fmt.Errorf("securely create unlinked grade output %q: %w", name, err)
	}
	file := os.NewFile(uintptr(fd), name)
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("inspect grade output %q: %w", name, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || !ok || stat.Nlink != 0 {
		file.Close()
		return nil, fmt.Errorf("grade output %q must begin as an unlinked regular file", name)
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return nil, fmt.Errorf("set grade output permissions: %w", err)
	}
	return file, nil
}

func openNamedGradeOutputFile(directory *os.File, name string) (*os.File, string, error) {
	if name == "" || filepath.Base(name) != name {
		return nil, "", errors.New("grade output filename is unsafe")
	}
	info, err := directory.Stat()
	if err != nil {
		return nil, "", fmt.Errorf("inspect fallback grade output directory: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	owner := ^uint32(0)
	if ok {
		owner = stat.Uid
	}
	if !info.IsDir() || !ok || stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0o022 != 0 {
		return nil, "", fmt.Errorf("named grade staging requires an owner-controlled, non-group/world-writable output directory (mode %s, owner %d, effective user %d)", info.Mode(), owner, os.Geteuid())
	}
	var existing unix.Stat_t
	if err := unix.Fstatat(int(directory.Fd()), name, &existing, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		return nil, "", fmt.Errorf("securely create grade output %q: %w", name, unix.EEXIST)
	} else if !errors.Is(err, unix.ENOENT) {
		return nil, "", fmt.Errorf("inspect grade output destination %q: %w", name, err)
	}
	for attempt := 0; attempt < 16; attempt++ {
		random := make([]byte, 16)
		if _, err := rand.Read(random); err != nil {
			return nil, "", fmt.Errorf("generate grade staging name: %w", err)
		}
		stagingName := ".observatory-grade-" + hex.EncodeToString(random) + ".tmp"
		flags := unix.O_WRONLY | unix.O_CREAT | unix.O_EXCL | unix.O_CLOEXEC | unix.O_NOFOLLOW
		fd, err := unix.Openat(int(directory.Fd()), stagingName, flags, 0o600)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return nil, "", fmt.Errorf("securely create named grade staging file: %w", err)
		}
		file := os.NewFile(uintptr(fd), stagingName)
		fileInfo, err := file.Stat()
		if err != nil {
			file.Close()
			return nil, stagingName, fmt.Errorf("inspect named grade staging file: %w", err)
		}
		fileStat, ok := fileInfo.Sys().(*syscall.Stat_t)
		if !fileInfo.Mode().IsRegular() || !ok || fileStat.Nlink != 1 || fileStat.Uid != uint32(os.Geteuid()) {
			file.Close()
			return nil, stagingName, errors.New("named grade staging file must be an owner-controlled single-link regular file")
		}
		if err := file.Chmod(0o600); err != nil {
			file.Close()
			return nil, stagingName, fmt.Errorf("set named grade staging permissions: %w", err)
		}
		return file, stagingName, nil
	}
	return nil, "", errors.New("could not allocate a unique grade staging filename")
}

// bytesReader keeps the secure writer independent of command-layer encoders.
func bytesReader(data []byte) *bytes.Reader { return bytes.NewReader(data) }
