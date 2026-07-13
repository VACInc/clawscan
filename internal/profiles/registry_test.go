package profiles

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProfileRegistryReturnsSortedIDs(t *testing.T) {
	registry, err := NewProfileRegistry(map[string]resolvedProfile{
		"review":  {profile: Profile{Scanners: []string{"snyk"}}},
		"clawhub": {profile: Profile{Scanners: []string{"skillspector"}}},
	})
	if err != nil {
		t.Fatal(err)
	}

	if got := strings.Join(registry.IDs(), ","); got != "clawhub,review" {
		t.Fatalf("ids = %q", got)
	}
}

func TestDefaultProfileRegistryContainsEmbeddedBuiltIns(t *testing.T) {
	registry := DefaultProfileRegistry()

	clawhub, ok := registry.Profile("clawhub")
	if !ok {
		t.Fatal("missing clawhub profile")
	}
	if got := strings.Join(clawhub.profile.Scanners, ","); got != "skillspector,virustotal,clawscan-static" {
		t.Fatalf("clawhub scanners = %q", got)
	}
	if clawhub.configDir != "clawhub" {
		t.Fatalf("clawhub config dir = %q", clawhub.configDir)
	}
	if clawhub.source != "built-in" {
		t.Fatalf("clawhub source = %q", clawhub.source)
	}
	if string(clawhub.files["clawhub/prompt.md"]) == "" {
		t.Fatal("missing clawhub embedded prompt")
	}
	if string(clawhub.files["clawhub/output.schema.json"]) == "" {
		t.Fatal("missing clawhub embedded output schema")
	}

	oauth, ok := registry.Profile("clawhub-oauth")
	if !ok {
		t.Fatal("missing clawhub-oauth profile")
	}
	if oauth.profile.Judge == nil || oauth.profile.Judge.Execution != "host" {
		t.Fatalf("clawhub-oauth judge = %#v", oauth.profile.Judge)
	}
	if got := strings.Join(oauth.profile.Scanners, ","); got != "virustotal,skillspector,clawscan-static" {
		t.Fatalf("clawhub-oauth scanners = %q", got)
	}
	if got := strings.Join(oauth.profile.Judge.WaitForScanners, ","); got != "virustotal" {
		t.Fatalf("clawhub-oauth wait scanners = %q", got)
	}
	if timeout, err := time.ParseDuration(oauth.profile.Judge.WaitTimeout); err != nil || timeout != 10*time.Minute {
		t.Fatalf("clawhub-oauth wait timeout = %q, %v", oauth.profile.Judge.WaitTimeout, err)
	}
}

func TestProfileRegistryRejectsUnknownScannerReferences(t *testing.T) {
	_, err := NewProfileRegistry(map[string]resolvedProfile{
		"bad": {profile: Profile{Scanners: []string{"missing-scanner"}}},
	})
	if err == nil || err.Error() != "Profile bad references unknown scanner: missing-scanner" {
		t.Fatalf("err = %v", err)
	}
}

func TestInspectProfilesDiscoversNearestConfigAndShadowsBuiltIns(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".clawscan.yml"), `version: 1
profiles:
  clawhub:
    scanners:
      - clawscan-static
  local:
    scanners:
      - socket
`)
	nested := filepath.Join(dir, "nested")
	if err := os.Mkdir(nested, 0o755); err != nil {
		t.Fatal(err)
	}

	catalog, err := InspectProfiles(nested)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(catalog.IDs(), ","); got != "clawhub,clawhub-oauth,local" {
		t.Fatalf("profile ids = %q", got)
	}

	clawhub, ok := catalog.Profile("clawhub")
	if !ok {
		t.Fatal("missing clawhub profile")
	}
	if got := strings.Join(clawhub.Profile.Scanners, ","); got != "clawscan-static" {
		t.Fatalf("clawhub scanners = %q", got)
	}
	if !strings.HasSuffix(clawhub.Source, ".clawscan.yml") {
		t.Fatalf("clawhub source = %q", clawhub.Source)
	}

}
