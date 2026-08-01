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

func TestSkillTrustBenchJSONLRowsAreAuthoritative(t *testing.T) {
	dir := t.TempDir()
	idsPath := filepath.Join(dir, "subset.jsonl")
	if err := os.WriteFile(idsPath, []byte(`{"id":"case_00001","judgment":"normal","risk_labels":[],"source":"pinned-subset","base_category":"safe","skill_path":"benchmark_full_v1.0/case_00001"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	benchmark, err := NewBenchmarkOptions("SkillTrustBench", "", 0, 0, "", idsPath)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := RunBenchmark(Options{
		Benchmark:          benchmark,
		Scanners:           []string{"clawscan-static"},
		ScannerResultPaths: map[string]string{},
	}, RunContext{
		Env: map[string]string{},
		BenchmarkClient: staticBenchmarkClient{
			skillTrustBenchRows: []SkillTrustBenchRow{{
				ID: "case_00001", Judgment: "malicious", SkillPath: "benchmark_full_v1.0/case_00001",
			}},
			materializedSkillTrustBench: map[string]map[string]string{
				"case_00001": {"SKILL.md": "# Safe fixture\n"},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := artifact.Cases[0].Expected.Verdict; got != "clean" {
		t.Fatalf("expected verdict = %q, want pinned JSONL verdict clean", got)
	}
	if got := string(artifact.Cases[0].Expected.Context); !strings.Contains(got, `"source":"pinned-subset"`) {
		t.Fatalf("expected context = %s, want pinned JSONL metadata", got)
	}
}

func TestSkillTrustBenchJSONLRowsFailBeforeScannerOnInvalidLabel(t *testing.T) {
	dir := t.TempDir()
	idsPath := filepath.Join(dir, "subset.jsonl")
	if err := os.WriteFile(idsPath, []byte(`{"id":"case_00001","judgment":"changed-upstream","skill_path":"benchmark_full_v1.0/case_00001"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	benchmark, err := NewBenchmarkOptions("SkillTrustBench", "", 0, 0, "", idsPath)
	if err != nil {
		t.Fatal(err)
	}
	recorder := &recordingScannerRunner{}
	_, err = RunBenchmark(Options{
		Benchmark:          benchmark,
		Scanners:           []string{"clawscan-static"},
		ScannerResultPaths: map[string]string{},
	}, RunContext{
		Env:             map[string]string{},
		ScannerRunner:   recorder,
		BenchmarkClient: staticBenchmarkClient{},
	})
	if err == nil || !strings.Contains(err.Error(), `unsupported judgment "changed-upstream"`) {
		t.Fatalf("error = %v, want unsupported judgment", err)
	}
	if len(recorder.targets) != 0 {
		t.Fatalf("scanner executed for invalid label source: %v", recorder.targets)
	}
}

func TestFetchSkillTrustBenchRowsVerifiesPinnedJSONL(t *testing.T) {
	rowsJSONL := strings.Join([]string{
		`{"id":"case_00001","judgment":"normal","skill_path":"benchmark_full_v1.0/case_00001"}`,
		`{"id":"case_00002","judgment":"malicious","skill_path":"benchmark_full_v1.0/case_00002"}`,
	}, "\n") + "\n"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(writer, rowsJSONL)
	}))
	defer server.Close()
	client := &HuggingFaceBenchmarkClient{
		SkillTrustBenchRowsURL:    server.URL,
		SkillTrustBenchRowsSHA256: sha256String(rowsJSONL),
	}
	rows, err := client.FetchSkillTrustBenchRows(skillTrustBenchID, defaultSkillTrustBenchSplit, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].ID != "case_00002" || rows[0].Judgment != "malicious" {
		t.Fatalf("rows = %#v", rows)
	}
}

func TestFetchSkillTrustBenchRowsRejectsDigestMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(writer, `{"id":"case_00001","judgment":"malicious"}`)
	}))
	defer server.Close()
	client := &HuggingFaceBenchmarkClient{
		SkillTrustBenchRowsURL:    server.URL,
		SkillTrustBenchRowsSHA256: sha256String("different pinned rows"),
	}
	_, err := client.FetchSkillTrustBenchRows(skillTrustBenchID, defaultSkillTrustBenchSplit, 0, 0)
	if err == nil || !strings.Contains(err.Error(), "SkillTrustBench rows SHA-256 mismatch") {
		t.Fatalf("error = %v, want rows digest mismatch", err)
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
	t.Setenv("HOME", cacheRoot)
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
	t.Setenv("HOME", cacheRoot)
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
