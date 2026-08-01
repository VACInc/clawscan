package runner

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFetchSkillTrustBenchRowsPinsDatasetRevision(t *testing.T) {
	var revision string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		revision = request.URL.Query().Get("revision")
		writer.Header().Set("Content-Type", "application/json")
		fmt.Fprint(writer, `{"rows":[{"row":{"id":"case_00001","judgment":"normal","skill_path":"benchmark_full_v1.0/case_00001"}}]}`)
	}))
	defer server.Close()

	client := &HuggingFaceBenchmarkClient{Endpoint: server.URL}
	rows, err := client.FetchSkillTrustBenchRows(skillTrustBenchID, defaultSkillTrustBenchSplit, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	if revision != skillTrustBenchRevision {
		t.Fatalf("revision = %q, want %q", revision, skillTrustBenchRevision)
	}
}

func TestSkillTrustBenchArchiveRejectsDigestMismatch(t *testing.T) {
	archivePath := filepath.Join(t.TempDir(), "benchmark.zip")
	if err := os.WriteFile(archivePath, []byte("poisoned cache"), 0o600); err != nil {
		t.Fatal(err)
	}
	client := &HuggingFaceBenchmarkClient{
		SkillTrustBenchArchivePath:   archivePath,
		SkillTrustBenchArchiveSHA256: sha256String("expected archive"),
	}
	_, err := client.skillTrustBenchArchivePath()
	if err == nil || !strings.Contains(err.Error(), "SHA-256 mismatch") {
		t.Fatalf("error = %v, want digest mismatch", err)
	}
}

func TestSkillTrustBenchArchiveReplacesInvalidCacheOnlyAfterVerifiedDownload(t *testing.T) {
	cacheRoot := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", cacheRoot)
	cachePath := filepath.Join(cacheRoot, "clawscan", "benchmarks", "skilltrustbench", skillTrustBenchArchiveName)
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cachePath, []byte("poisoned cache"), 0o600); err != nil {
		t.Fatal(err)
	}

	wanted := []byte("verified archive payload")
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Write(wanted)
	}))
	defer server.Close()
	client := &HuggingFaceBenchmarkClient{
		SkillTrustBenchArchiveURL:    server.URL,
		SkillTrustBenchArchiveSHA256: sha256String(string(wanted)),
	}
	path, err := client.skillTrustBenchArchivePath()
	if err != nil {
		t.Fatal(err)
	}
	if path != cachePath {
		t.Fatalf("path = %q, want %q", path, cachePath)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(wanted) {
		t.Fatalf("cache = %q, want %q", got, wanted)
	}
}

func TestSkillTrustBenchArchiveDoesNotCacheBadDownload(t *testing.T) {
	cacheRoot := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", cacheRoot)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(writer, "wrong archive")
	}))
	defer server.Close()
	client := &HuggingFaceBenchmarkClient{
		SkillTrustBenchArchiveURL:    server.URL,
		SkillTrustBenchArchiveSHA256: sha256String("expected archive"),
	}
	_, err := client.skillTrustBenchArchivePath()
	if err == nil || !strings.Contains(err.Error(), "SHA-256 mismatch") {
		t.Fatalf("error = %v, want digest mismatch", err)
	}
	cachePath := filepath.Join(cacheRoot, "clawscan", "benchmarks", "skilltrustbench", skillTrustBenchArchiveName)
	if _, statErr := os.Stat(cachePath); !os.IsNotExist(statErr) {
		t.Fatalf("invalid download was cached: %v", statErr)
	}
}

func sha256String(value string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(value)))
}
