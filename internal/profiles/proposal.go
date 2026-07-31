package profiles

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

// ValidateConfigBytes parses and semantically validates a ClawScan config
// document without resolving paths, reading referenced files, or executing any
// profile field. It is the trusted-side entry point for treating an untrusted
// profile proposal as data.
func ValidateConfigBytes(label string, data []byte) (Config, error) {
	config, err := readConfigBytes(label, func() ([]byte, error) {
		return data, nil
	})
	if err != nil {
		return Config{}, err
	}
	if len(config.Profiles) == 0 {
		return Config{}, fmt.Errorf("ClawScan config %s defines no profiles", label)
	}
	for name, profile := range config.Profiles {
		if err := validateProfile(name, profile); err != nil {
			return Config{}, err
		}
	}
	return config, nil
}

// rejectTrailingDocuments fails when a YAML stream carries more than one
// document. A single-document contract keeps every reader of the same bytes in
// agreement about which profile definition is authoritative.
func rejectTrailingDocuments(label string, data []byte) error {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	documents := 0
	for {
		var node yaml.Node
		err := decoder.Decode(&node)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			// Shape errors are reported by the typed decode path.
			return nil
		}
		documents++
		if documents > 1 {
			return fmt.Errorf("ClawScan config %s must contain exactly one YAML document", label)
		}
	}
	return nil
}
