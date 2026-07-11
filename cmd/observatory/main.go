package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/openclaw/clawscan/internal/observatory"
)

var version = "dev"

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) error {
	if len(args) == 0 || (len(args) == 1 && (args[0] == "--help" || args[0] == "-h")) {
		fmt.Fprint(stdout, helpText)
		return nil
	}
	if len(args) == 1 && args[0] == "--version" {
		fmt.Fprintln(stdout, version)
		return nil
	}
	switch args[0] {
	case "scan":
		return runScan(ctx, args[1:], stdout, stderr)
	case "analyze":
		return runAnalyze(args[1:], stdout)
	case "render":
		return runRender(args[1:], stdout)
	case "validate-config":
		return runValidateConfig(args[1:], stdout)
	default:
		return fmt.Errorf("unknown command: %s", args[0])
	}
}

func runScan(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) error {
	flags := flag.NewFlagSet("scan", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", defaultConfigPath(), "Observatory YAML config")
	output := flags.String("output", "", "write evidence JSON to a file")
	jsonOutput := flags.Bool("json", false, "write evidence JSON to stdout")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return errors.New("usage: observatory scan [--config path] [--json] <target>")
	}
	config, err := observatory.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	result, err := observatory.Scan(ctx, flags.Arg(0), config, nil)
	hasEvidence := result.Evidence.SchemaVersion != ""
	if hasEvidence && *output != "" {
		if err := writeEvidence(*output, result.Evidence); err != nil {
			return err
		}
	}
	if hasEvidence && (*jsonOutput || *output == "") {
		if err := encodeJSON(stdout, result.Evidence); err != nil {
			return err
		}
	}
	if result.RunDirectory != "" {
		fmt.Fprintf(stderr, "run_directory: %s\n", result.RunDirectory)
	}
	return err
}

func runAnalyze(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("analyze", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", defaultConfigPath(), "Observatory YAML config")
	bundle := flags.String("bundle", "", "captured raw.tar.gz")
	output := flags.String("output", "", "write evidence JSON to a file")
	jsonOutput := flags.Bool("json", false, "write evidence JSON to stdout")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 1 || strings.TrimSpace(*bundle) == "" {
		return errors.New("usage: observatory analyze --config path --bundle raw.tar.gz [--json] <target>")
	}
	config, err := observatory.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	evidence, err := observatory.AnalyzeBundle(flags.Arg(0), config, *bundle)
	if err != nil {
		return err
	}
	if *output != "" {
		if err := writeEvidence(*output, evidence); err != nil {
			return err
		}
	}
	if *jsonOutput || *output == "" {
		return encodeJSON(stdout, evidence)
	}
	return nil
}

func runRender(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("render", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	input := flags.String("input", "", "Observatory or Clawscan evidence JSON")
	previousPath := flags.String("previous", "", "optional previous evidence JSON")
	output := flags.String("output", "", "static site output directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *input == "" || *output == "" {
		return errors.New("usage: observatory render --input evidence.json --output site [--previous evidence.json]")
	}
	evidence, err := observatory.LoadEvidence(*input)
	if err != nil {
		return err
	}
	var previous *observatory.Evidence
	if *previousPath != "" {
		loaded, err := observatory.LoadEvidence(*previousPath)
		if err != nil {
			return err
		}
		previous = &loaded
	}
	if err := observatory.RenderSite(*output, evidence, previous); err != nil {
		return err
	}
	fmt.Fprintln(stdout, filepath.Join(*output, "index.html"))
	return nil
}

func runValidateConfig(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("validate-config", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	live := flags.Bool("live", false, "also require live-execution safety controls")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return errors.New("usage: observatory validate-config [--live] <config>")
	}
	config, err := observatory.LoadConfig(flags.Arg(0))
	if err != nil {
		return err
	}
	if *live {
		if err := config.ValidateLive(); err != nil {
			return err
		}
	}
	fmt.Fprintln(stdout, "valid")
	return nil
}

func defaultConfigPath() string {
	if value := strings.TrimSpace(os.Getenv("CLAWSCAN_BEHAVIOR_CONFIG")); value != "" {
		return value
	}
	if value := strings.TrimSpace(os.Getenv("OBSERVATORY_CONFIG")); value != "" {
		return value
	}
	return ".observatory.yml"
}

func writeEvidence(path string, evidence observatory.Evidence) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	encodeErr := encodeJSON(file, evidence)
	closeErr := file.Close()
	if encodeErr != nil {
		return encodeErr
	}
	return closeErr
}

func encodeJSON(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

const helpText = `ClawHub Observatory — paired behavioral evidence for OpenClaw targets

Usage:
  observatory scan [--config path] [--json] <target>
  observatory analyze --config path --bundle raw.tar.gz [--json] <target>
  observatory render --input evidence.json --output site [--previous evidence.json]
  observatory validate-config [--live] <config>

The output is evidence, never a safety verdict. Live scans fail closed until the
config attests a disposable Proxmox VM and an isolated deny/sinkhole network.
`
