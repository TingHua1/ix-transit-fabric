package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
)

// nodeNetworkCLIArgs adapts the established --mode interface to the same
// helper as the node-network subcommand. Keeping parsing and execution apart
// makes this path testable without os.Exit or a subprocess.
func nodeNetworkCLIArgs(action, config, artifact, sha256 string, asJSON bool) []string {
	args := []string{action}
	if config != "" {
		args = append(args, "--config", config)
	}
	if artifact != "" {
		args = append(args, "--artifact", artifact)
	}
	if sha256 != "" {
		args = append(args, "--sha256", sha256)
	}
	if asJSON {
		args = append(args, "--json")
	}
	return args
}

// runNodeNetworkCLI implements local-only node network administration. It
// neither starts a process nor contacts a service. The install action is the
// intentional exception to dry-run plans: it invokes the reviewed local
// artifact installer for an already present, hash-verified file.
func runNodeNetworkCLI(args []string, stdout io.Writer) error {
	if len(args) == 0 || args[0] == "" {
		return errors.New("node-network action is required")
	}
	action := args[0]
	fs := flag.NewFlagSet("node-network "+action, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	configPath := fs.String("config", "", "local node-network configuration")
	configPathCompat := fs.String("node-network-config", "", "local node-network configuration")
	artifact := fs.String("artifact", "", "local EasyTier artifact")
	sha256 := fs.String("sha256", "", "expected artifact SHA-256")
	_ = fs.Bool("json", false, "machine-readable output") // Output is safe JSON where structured data is emitted.
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("node-network accepts exactly one action")
	}
	if *configPath == "" {
		*configPath = *configPathCompat
	}
	if action == "validate" || action == "render-systemd" || action == "install-local" || action == "apply-local" {
		if err := requireNodeNetworkSupported(); err != nil {
			return err
		}
	}
	if action != "stop" && action != "uninstall" && *configPath != "" && *configPath != NodeNetworkConfigFile {
		return fmt.Errorf("--config must be %s", NodeNetworkConfigFile)
	}

	switch action {
	case "validate":
		if err := requireNodeNetworkSupported(); err != nil {
			return err
		}
		cfg, err := loadRequiredLocalNodeNetworkConfig(*configPath)
		if err != nil {
			return err
		}
		return writeNodeNetworkJSON(stdout, struct {
			Action string                    `json:"action"`
			Valid  bool                      `json:"valid"`
			Config RedactedNodeNetworkConfig `json:"config"`
		}{"validate", true, redactedNodeNetworkConfig(cfg)})
	case "render-systemd":
		if err := requireNodeNetworkSupported(); err != nil {
			return err
		}
		cfg, err := loadRequiredLocalNodeNetworkConfig(*configPath)
		if err != nil {
			return err
		}
		unit, err := RenderNodeNetworkSystemdUnit(cfg)
		if err != nil {
			return err
		}
		_, err = fmt.Fprint(stdout, unit)
		return err
	case "install-local":
		if err := requireNodeNetworkSupported(); err != nil {
			return err
		}
		if *artifact == "" || *sha256 == "" {
			return errors.New("install-local requires --artifact and --sha256")
		}
		cfg, err := loadRequiredLocalNodeNetworkConfigForInstall(*configPath)
		if err != nil {
			return err
		}
		metadata, err := InstallNodeNetworkArtifact(cfg, *artifact, *sha256)
		if err != nil {
			return err
		}
		return writeNodeNetworkJSON(stdout, metadata)
	case "apply-local":
		if err := requireNodeNetworkSupported(); err != nil {
			return err
		}
		cfg, err := loadRequiredLocalNodeNetworkConfig(*configPath)
		if err != nil {
			return err
		}
		plan, err := BuildLocalOperationPlan(LocalOperationApply, &cfg)
		if err != nil {
			return err
		}
		return writeNodeNetworkJSON(stdout, plan)
	case "stop":
		plan, err := BuildLocalOperationPlan(LocalOperationStop, nil)
		if err != nil {
			return err
		}
		return writeNodeNetworkJSON(stdout, plan)
	case "uninstall":
		plan, err := BuildLocalOperationPlan(LocalOperationUninstall, nil)
		if err != nil {
			return err
		}
		return writeNodeNetworkJSON(stdout, plan)
	case "status":
		return writeNodeNetworkStatus(stdout, *configPath)
	default:
		return errors.New("node-network action must be validate, render-systemd, install-local, apply-local, status, stop, or uninstall")
	}
}

func localNodeNetworkConfigOwner() string {
	if runtime.GOOS == "windows" {
		return ""
	}
	return "0"
}

// loadLocalNodeNetworkConfig validates the real config file before reading its
// declaration. DecodeNodeNetworkConfig is syntax-only; subsequent local
// validation checks the EnvironmentFile contract without exposing its value.
// No URI in the declaration is resolved or contacted.
func loadLocalNodeNetworkConfig(path string) (NodeNetworkConfig, error) {
	if err := ValidateNodeNetworkConfigFile(path, localNodeNetworkConfigOwner(), OSNodeNetworkFileInspector{}); err != nil {
		return NodeNetworkConfig{}, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return NodeNetworkConfig{}, fmt.Errorf("read node network config: %w", err)
	}
	cfg, err := DecodeNodeNetworkConfig(raw)
	if err != nil {
		return NodeNetworkConfig{}, fmt.Errorf("parse node network config: %w", err)
	}
	if err := validateNodeNetworkConfig(cfg); err != nil {
		return NodeNetworkConfig{}, fmt.Errorf("validate node network config: %w", err)
	}
	return cfg, nil
}

func loadLocalNodeNetworkConfigForInstall(path string) (NodeNetworkConfig, error) {
	if err := ValidateNodeNetworkConfigFile(path, localNodeNetworkConfigOwner(), OSNodeNetworkFileInspector{}); err != nil {
		return NodeNetworkConfig{}, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return NodeNetworkConfig{}, fmt.Errorf("read node network config: %w", err)
	}
	cfg, err := DecodeNodeNetworkConfig(raw)
	if err != nil {
		return NodeNetworkConfig{}, fmt.Errorf("parse node network config: %w", err)
	}
	if err := validateNodeNetworkConfigForInstall(cfg); err != nil {
		return NodeNetworkConfig{}, fmt.Errorf("validate node network install config: %w", err)
	}
	return cfg, nil
}

func loadRequiredLocalNodeNetworkConfig(path string) (NodeNetworkConfig, error) {
	if path != NodeNetworkConfigFile {
		return NodeNetworkConfig{}, fmt.Errorf("--config must be %s", NodeNetworkConfigFile)
	}
	return loadLocalNodeNetworkConfig(path)
}

func loadRequiredLocalNodeNetworkConfigForInstall(path string) (NodeNetworkConfig, error) {
	if path != NodeNetworkConfigFile {
		return NodeNetworkConfig{}, fmt.Errorf("--config must be %s", NodeNetworkConfigFile)
	}
	return loadLocalNodeNetworkConfigForInstall(path)
}

func redactedNodeNetworkConfig(cfg NodeNetworkConfig) RedactedNodeNetworkConfig {
	return RedactedNodeNetworkConfig{
		ConfigurationPresent: true, NoListener: cfg.NoListener,
	}
}

type nodeNetworkCLIStatus struct {
	ConfigState string             `json:"config_state"`
	EasyTier    EasyTierStatus     `json:"easytier"`
	Tun0        TunStatus          `json:"tun0"`
	Peers       PeerSummary        `json:"peers"`
	Error       StatusErrorSummary `json:"error"`
}

func writeNodeNetworkStatus(stdout io.Writer, configPath string) error {
	state := "unknown"
	summary := LocalNetworkSummary{ServiceState: "unknown", ReasonCode: "not_collected"}
	if configPath != "" {
		if _, err := loadLocalNodeNetworkConfig(configPath); err != nil {
			// Do not surface the parsing error: file names, endpoint declarations,
			// and secret paths are not status telemetry.
			state = "config_rejected"
			summary = LocalNetworkSummary{ServiceState: "error", ReasonCode: "local_state_error"}
		}
	}
	easy, tun, peers, statusErr := MapLocalNetworkSummary(summary)
	return writeNodeNetworkJSON(stdout, nodeNetworkCLIStatus{state, easy, tun, peers, statusErr})
}

func writeNodeNetworkJSON(stdout io.Writer, value any) error {
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}
