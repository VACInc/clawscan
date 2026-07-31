package profiles

import (
	"strings"
	"testing"
)

func TestValidateConfigBytesRejectsTrailingDocuments(t *testing.T) {
	body := "version: 1\nprofiles:\n  clawhub:\n    scanners:\n      - clawscan-static\n---\nversion: 1\nprofiles:\n  shadow:\n    scanners:\n      - skillspector\n"
	if _, err := ValidateConfigBytes("candidate.yml", []byte(body)); err == nil ||
		!strings.Contains(err.Error(), "exactly one YAML document") {
		t.Fatalf("expected trailing-document rejection, got %v", err)
	}
}

func TestValidateConfigBytesAcceptsSingleDocument(t *testing.T) {
	body := "version: 1\nprofiles:\n  clawhub:\n    scanners:\n      - clawscan-static\n"
	config, err := ValidateConfigBytes("candidate.yml", []byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(config.Profiles) != 1 {
		t.Fatalf("expected one profile, got %d", len(config.Profiles))
	}
}

func TestValidateConfigBytesRequiresProfiles(t *testing.T) {
	if _, err := ValidateConfigBytes("candidate.yml", []byte("version: 1\n")); err == nil ||
		!strings.Contains(err.Error(), "defines no profiles") {
		t.Fatalf("expected empty-profile rejection, got %v", err)
	}
}

func TestValidateConfigBytesRejectsInvalidProfile(t *testing.T) {
	body := "version: 1\nprofiles:\n  clawhub:\n    scanners:\n      - clawscan-static\n      - clawscan-static\n"
	if _, err := ValidateConfigBytes("candidate.yml", []byte(body)); err == nil {
		t.Fatal("expected duplicate scanner rejection")
	}
}

func TestBuiltinProfilesStillLoadWithSingleDocumentRule(t *testing.T) {
	if _, err := loadBuiltinProfiles(); err != nil {
		t.Fatalf("builtin profiles must still load: %v", err)
	}
}
