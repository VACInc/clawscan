//go:build !linux

package observatory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNonLinuxControlHostFailsClosed(t *testing.T) {
	config := validTestConfig(t, t.TempDir())
	if err := config.ValidateLive(); err == nil || !strings.Contains(err.Error(), "Linux control host") {
		t.Fatalf("live execution did not fail closed: %v", err)
	}

	target := filepath.Join(t.TempDir(), "skill")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "SKILL.md"), []byte("---\nname: platform-probe\n---\n"), 0600); err != nil {
		t.Fatal(err)
	}
	limits := LimitsConfig{MaxFiles: 10, MaxFileBytes: 1 << 20, MaxTotalBytes: 1 << 20, MaxBundleBytes: 1 << 20}
	if _, err := InspectTarget(target, limits); err == nil || !strings.Contains(err.Error(), "Linux control host") {
		t.Fatalf("secure staging did not fail closed: %v", err)
	}
	if err := RenderSite(filepath.Join(t.TempDir(), "site"), fixtureEvidence(), nil); err == nil || !strings.Contains(err.Error(), "Linux control host") {
		t.Fatalf("secure rendering did not fail closed: %v", err)
	}
}
