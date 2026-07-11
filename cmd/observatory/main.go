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
		return runRender(args[1:], stdout, stderr)
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
	site := flags.String("site", "", "render a self-contained site, auto-including the latest comparable predecessor delta")
	deltaOutput := flags.String("delta", "", "write a structured version delta JSON when a comparable predecessor exists")
	noHistory := flags.Bool("no-history", false, "do not record this scan in local history or compute a version delta")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return errors.New("usage: observatory scan [--config path] [--json] [--site dir] [--delta path] [--no-history] <target>")
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
	if hasEvidence {
		if diffErr := recordAndDiff(config, result.Evidence, *site, *deltaOutput, *noHistory, stderr); diffErr != nil {
			return errors.Join(err, diffErr)
		}
	}
	return err
}

// recordAndDiff runs the hands-off local-history workflow as a side channel: it
// records the completed capture, selects the latest strictly comparable
// predecessor, and renders or emits the version delta. It never writes to stdout
// so the evidence JSON contract with the Clawscan adapter is preserved.
// Corrupt or incomparable history fails closed by omitting the delta; only an
// explicitly requested --site or --delta write can return an error.
func recordAndDiff(config observatory.Config, evidence observatory.Evidence, sitePath string, deltaPath string, noHistory bool, stderr io.Writer) error {
	if noHistory || !config.HistoryEnabled() {
		return renderCurrentOnly(sitePath, evidence, stderr)
	}
	store, err := observatory.OpenHistoryStore(config.ArtifactsDir)
	if err != nil {
		fmt.Fprintf(stderr, "history unavailable: %v\n", err)
		return renderCurrentOnly(sitePath, evidence, stderr)
	}
	// Select before recording so the current run is never its own predecessor.
	previous, selErr := store.LatestComparable(evidence)
	if selErr != nil {
		fmt.Fprintf(stderr, "version delta unavailable: %v\n", selErr)
		previous = nil
	}
	if recErr := store.Record(evidence, config.HistoryRetain()); recErr != nil {
		switch {
		case errors.Is(recErr, observatory.ErrHistoryNoStableIdentity):
			fmt.Fprintln(stderr, "history: target has no stable lineage/plugin ID; version diffs disabled")
		case errors.Is(recErr, observatory.ErrHistoryIncompleteCapture):
			fmt.Fprintln(stderr, "history: incomplete capture not recorded")
		default:
			fmt.Fprintf(stderr, "history record failed: %v\n", recErr)
		}
	}
	if previous != nil {
		delta, err := observatory.ComputeVersionDelta(*previous, evidence)
		if err != nil {
			fmt.Fprintf(stderr, "version delta unavailable: %v\n", err)
			previous = nil
		} else {
			if deltaPath != "" {
				if err := writeVersionDelta(deltaPath, delta); err != nil {
					return err
				}
				fmt.Fprintf(stderr, "version delta written: %s\n", deltaPath)
			}
			fmt.Fprintf(stderr, "version delta: %d change(s) vs prior run %s\n", len(delta.Changes), previous.Run.ID)
		}
	} else {
		fmt.Fprintln(stderr, "version delta: no comparable predecessor in local history")
	}
	if sitePath != "" {
		if err := observatory.RenderSite(sitePath, evidence, previous); err != nil {
			return err
		}
		fmt.Fprintf(stderr, "site: %s\n", filepath.Join(sitePath, "index.html"))
	}
	return nil
}

func renderCurrentOnly(sitePath string, evidence observatory.Evidence, stderr io.Writer) error {
	if sitePath == "" {
		return nil
	}
	if err := observatory.RenderSite(sitePath, evidence, nil); err != nil {
		return err
	}
	fmt.Fprintf(stderr, "site: %s\n", filepath.Join(sitePath, "index.html"))
	return nil
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

func runRender(args []string, stdout io.Writer, stderr io.Writer) error {
	flags := flag.NewFlagSet("render", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	input := flags.String("input", "", "Observatory or Clawscan evidence JSON")
	previousPath := flags.String("previous", "", "optional previous evidence JSON")
	autoPrevious := flags.Bool("auto-previous", false, "select the latest comparable predecessor from local history")
	configPath := flags.String("config", "", "Observatory config used to locate local history for --auto-previous")
	output := flags.String("output", "", "static site output directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *input == "" || *output == "" {
		return errors.New("usage: observatory render --input evidence.json --output site [--previous evidence.json | --auto-previous --config path]")
	}
	if *autoPrevious && *previousPath != "" {
		return errors.New("--previous and --auto-previous are mutually exclusive")
	}
	evidence, err := observatory.LoadEvidence(*input)
	if err != nil {
		return err
	}
	var previous *observatory.Evidence
	switch {
	case *autoPrevious:
		selected, err := selectHistoryPredecessor(*configPath, evidence, stderr)
		if err != nil {
			return err
		}
		previous = selected
	case *previousPath != "":
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

// selectHistoryPredecessor resolves the latest strictly comparable predecessor
// for evidence from the configured local history. It fails closed loudly on
// corrupt history because the operator asked for the diff explicitly.
func selectHistoryPredecessor(configPath string, evidence observatory.Evidence, stderr io.Writer) (*observatory.Evidence, error) {
	path := strings.TrimSpace(configPath)
	if path == "" {
		path = defaultConfigPath()
	}
	config, err := observatory.LoadConfig(path)
	if err != nil {
		return nil, err
	}
	if !config.HistoryEnabled() {
		return nil, errors.New("--auto-previous requires history.enabled in the config")
	}
	store, err := observatory.OpenHistoryStore(config.ArtifactsDir)
	if err != nil {
		return nil, err
	}
	previous, err := store.LatestComparable(evidence)
	if err != nil {
		return nil, err
	}
	if previous == nil {
		fmt.Fprintln(stderr, "no comparable predecessor in local history; rendering current evidence only")
	}
	return previous, nil
}

func writeVersionDelta(path string, delta observatory.VersionDelta) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	encodeErr := encodeJSON(file, delta)
	closeErr := file.Close()
	if encodeErr != nil {
		return encodeErr
	}
	return closeErr
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
  observatory scan [--config path] [--json] [--site dir] [--delta path] [--no-history] <target>
  observatory analyze --config path --bundle raw.tar.gz [--json] <target>
  observatory render --input evidence.json --output site [--previous evidence.json | --auto-previous --config path]
  observatory validate-config [--live] <config>

A normal scan records its completed evidence in a bounded local history and,
when a strictly comparable prior release exists, renders (--site) or emits
(--delta) an evidence-based version delta. History is never fetched from the
network; incomparable or corrupt history fails closed by omitting the delta.

The output is evidence, never a safety verdict. Live scans fail closed until the
config attests a disposable Proxmox VM and an isolated deny/sinkhole network.
`
