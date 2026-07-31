package observatory

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type orderedBundleEntry struct {
	name     string
	body     string
	typeflag byte
}

func writeOrderedTestBundle(path string, entries []orderedBundleEntry) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	gzipWriter := gzip.NewWriter(file)
	tarWriter := tar.NewWriter(gzipWriter)
	for _, entry := range entries {
		typeflag := entry.typeflag
		if typeflag == 0 {
			typeflag = tar.TypeReg
		}
		data := []byte(entry.body)
		header := &tar.Header{Name: entry.name, Mode: 0o600, Typeflag: typeflag}
		if typeflag == tar.TypeReg {
			header.Size = int64(len(data))
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			return err
		}
		if typeflag == tar.TypeReg {
			if _, err := tarWriter.Write(data); err != nil {
				return err
			}
		}
	}
	if err := tarWriter.Close(); err != nil {
		return err
	}
	if err := gzipWriter.Close(); err != nil {
		return err
	}
	return file.Close()
}

// TestReadCaptureBundleRejectsDuplicateMembers covers the release-gate item for
// capture ambiguity: a second member with the same normalized name must fail
// closed instead of silently replacing the first.
func TestReadCaptureBundleRejectsDuplicateMembers(t *testing.T) {
	cases := []struct {
		name    string
		entries []orderedBundleEntry
	}{
		{
			name: "identical names",
			entries: []orderedBundleEntry{
				{name: "baseline/trace", body: "first"},
				{name: "baseline/trace", body: "second"},
			},
		},
		{
			name: "normalized collision",
			entries: []orderedBundleEntry{
				{name: "baseline/trace", body: "first"},
				{name: "./baseline/trace", body: "second"},
			},
		},
		{
			name: "dot segment collision",
			entries: []orderedBundleEntry{
				{name: "baseline/trace", body: "first"},
				{name: "baseline/./trace", body: "second"},
			},
		},
		{
			name: "non-regular shadow of a regular member",
			entries: []orderedBundleEntry{
				{name: "baseline/trace", body: "first"},
				{name: "baseline/trace", typeflag: tar.TypeSymlink},
			},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			bundlePath := filepath.Join(t.TempDir(), "duplicate.tar.gz")
			if err := writeOrderedTestBundle(bundlePath, testCase.entries); err != nil {
				t.Fatal(err)
			}
			_, err := ReadCaptureBundle(bundlePath, 1<<20)
			if err == nil || !strings.Contains(err.Error(), "duplicate member") {
				t.Fatalf("err = %v, want duplicate member rejection", err)
			}
		})
	}
}

func TestReadCaptureBundleAllowsDistinctMembers(t *testing.T) {
	bundlePath := filepath.Join(t.TempDir(), "distinct.tar.gz")
	entries := []orderedBundleEntry{
		{name: "baseline/trace", body: "first"},
		{name: "baseline/trace.1", body: "second"},
		{name: "exercise/trace", body: "third"},
	}
	if err := writeOrderedTestBundle(bundlePath, entries); err != nil {
		t.Fatal(err)
	}
	_, err := ReadCaptureBundle(bundlePath, 1<<20)
	if err != nil && strings.Contains(err.Error(), "duplicate member") {
		t.Fatalf("distinct members must not be rejected as duplicates: %v", err)
	}
}
