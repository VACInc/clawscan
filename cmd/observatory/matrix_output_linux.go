//go:build linux

package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/openclaw/clawscan/internal/observatory"
	"golang.org/x/sys/unix"
)

const (
	matrixOutputDirectoryMode fs.FileMode = 0o700
	matrixOutputFileMode      fs.FileMode = 0o600
	matrixOutputTempPrefix                = ".observatory-matrix-tmp-"
)

var matrixOutputVariantIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

type matrixOutputFile struct {
	name  string
	value any
}

func writeMatrixOutput(path string, result observatory.MatrixResult) error {
	files := []matrixOutputFile{{name: "comparison.json", value: result.Comparison}}
	seen := map[string]struct{}{"comparison.json": {}}
	for _, run := range result.Runs {
		if run.Evidence == nil {
			continue
		}
		if !matrixOutputVariantIDPattern.MatchString(run.ID) {
			return fmt.Errorf("matrix output variant id is unsafe: %q", run.ID)
		}
		name := "variant-" + run.ID + ".json"
		if _, ok := seen[name]; ok {
			return fmt.Errorf("matrix output filename is duplicated: %q", name)
		}
		seen[name] = struct{}{}
		files = append(files, matrixOutputFile{name: name, value: *run.Evidence})
	}
	return publishMatrixOutputDirectory(path, files)
}

func publishMatrixOutputDirectory(path string, files []matrixOutputFile) error {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return errors.New("matrix output path is required")
	}
	absolute, err := filepath.Abs(trimmed)
	if err != nil {
		return fmt.Errorf("resolve matrix output path: %w", err)
	}
	absolute = filepath.Clean(absolute)
	if absolute == string(filepath.Separator) || filepath.Base(absolute) == "." {
		return errors.New("matrix output path must name a new directory below the filesystem root")
	}
	parentFD, err := openMatrixOutputParent(filepath.Dir(absolute))
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)
	name := filepath.Base(absolute)
	if err := rejectExistingMatrixOutput(parentFD, name); err != nil {
		return err
	}

	stageName, stageFD, err := createMatrixOutputStage(parentFD)
	if err != nil {
		return err
	}
	stage := os.NewFile(uintptr(stageFD), filepath.Join(filepath.Dir(absolute), stageName))
	for _, output := range files {
		if err := writeMatrixStageJSON(stage, output.name, output.value); err != nil {
			stage.Close()
			return err
		}
	}
	if err := stage.Sync(); err != nil {
		stage.Close()
		return fmt.Errorf("sync matrix output staging directory: %w", err)
	}
	if err := stage.Close(); err != nil {
		return fmt.Errorf("close matrix output staging directory: %w", err)
	}
	if err := rejectExistingMatrixOutput(parentFD, name); err != nil {
		return err
	}
	if err := unix.Renameat2(parentFD, stageName, parentFD, name, unix.RENAME_NOREPLACE); err != nil {
		if errors.Is(err, syscall.EEXIST) {
			return fmt.Errorf("matrix output path %q already exists; refusing to clobber it", absolute)
		}
		return fmt.Errorf("atomically publish matrix output: %w", err)
	}
	if err := unix.Fsync(parentFD); err != nil {
		return fmt.Errorf("sync matrix output parent directory: %w", err)
	}
	return nil
}

func openMatrixOutputParent(path string) (int, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return -1, err
	}
	flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_DIRECTORY
	fd, err := unix.Open(string(filepath.Separator), flags, 0)
	if err != nil {
		return -1, fmt.Errorf("pin matrix output filesystem root: %w", err)
	}
	components := strings.Split(strings.TrimPrefix(filepath.Clean(absolute), string(filepath.Separator)), string(filepath.Separator))
	for _, component := range components {
		if component == "" || component == "." {
			continue
		}
		next, openErr := unix.Openat(fd, component, flags, 0)
		if errors.Is(openErr, syscall.ENOENT) {
			mkdirErr := unix.Mkdirat(fd, component, uint32(matrixOutputDirectoryMode.Perm()))
			if mkdirErr != nil && !errors.Is(mkdirErr, syscall.EEXIST) {
				unix.Close(fd)
				return -1, fmt.Errorf("create matrix output ancestor %q: %w", component, mkdirErr)
			}
			if mkdirErr == nil {
				if syncErr := unix.Fsync(fd); syncErr != nil {
					unix.Close(fd)
					return -1, fmt.Errorf("sync matrix output ancestor %q: %w", component, syncErr)
				}
			}
			next, openErr = unix.Openat(fd, component, flags, 0)
		}
		unix.Close(fd)
		if openErr != nil {
			return -1, fmt.Errorf("matrix output path contains unsafe ancestor %q: %w", component, openErr)
		}
		fd = next
	}
	return fd, nil
}

func rejectExistingMatrixOutput(parentFD int, name string) error {
	var stat unix.Stat_t
	err := unix.Fstatat(parentFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, syscall.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect matrix output path: %w", err)
	}
	kind := stat.Mode & unix.S_IFMT
	switch {
	case kind == unix.S_IFLNK:
		return fmt.Errorf("matrix output path %q is an unsafe symbolic link", name)
	case kind == unix.S_IFREG && stat.Nlink > 1:
		return fmt.Errorf("matrix output path %q is an unsafe hard-linked file", name)
	default:
		return fmt.Errorf("matrix output path %q already exists; refusing to clobber it", name)
	}
}

func createMatrixOutputStage(parentFD int) (string, int, error) {
	for range 4 {
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return "", -1, fmt.Errorf("generate matrix output staging name: %w", err)
		}
		name := matrixOutputTempPrefix + hex.EncodeToString(nonce[:])
		if err := unix.Mkdirat(parentFD, name, uint32(matrixOutputDirectoryMode.Perm())); errors.Is(err, syscall.EEXIST) {
			continue
		} else if err != nil {
			return "", -1, fmt.Errorf("create matrix output staging directory: %w", err)
		}
		fd, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
		if err != nil {
			return "", -1, fmt.Errorf("open matrix output staging directory: %w", err)
		}
		if err := validateMatrixOutputDescriptor(fd, unix.S_IFDIR, matrixOutputDirectoryMode, "staging directory"); err != nil {
			unix.Close(fd)
			return "", -1, err
		}
		return name, fd, nil
	}
	return "", -1, errors.New("create matrix output staging directory: repeated name collision")
}

func writeMatrixStageJSON(directory *os.File, name string, value any) error {
	if name == "" || filepath.Base(name) != name {
		return fmt.Errorf("unsafe matrix output filename %q", name)
	}
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, uint32(matrixOutputFileMode.Perm()))
	if err != nil {
		return fmt.Errorf("create matrix output file %q without following links: %w", name, err)
	}
	if err := validateMatrixOutputDescriptor(fd, unix.S_IFREG, matrixOutputFileMode, "file "+name); err != nil {
		unix.Close(fd)
		return err
	}
	file := os.NewFile(uintptr(fd), name)
	if err := encodeJSON(file, value); err != nil {
		file.Close()
		return fmt.Errorf("encode matrix output file %q: %w", name, err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return fmt.Errorf("sync matrix output file %q: %w", name, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close matrix output file %q: %w", name, err)
	}
	return nil
}

func validateMatrixOutputDescriptor(fd int, kind uint32, mode fs.FileMode, label string) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fmt.Errorf("inspect matrix output %s: %w", label, err)
	}
	if stat.Mode&unix.S_IFMT != kind {
		return fmt.Errorf("matrix output %s has an unsafe file type", label)
	}
	if stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("matrix output %s is not owned by the current user", label)
	}
	if fs.FileMode(stat.Mode&0o7777) != mode.Perm() {
		return fmt.Errorf("matrix output %s has mode %04o, expected %04o", label, stat.Mode&0o7777, mode.Perm())
	}
	if kind == unix.S_IFREG && stat.Nlink != 1 {
		return fmt.Errorf("matrix output %s must have exactly one hard link", label)
	}
	return nil
}
