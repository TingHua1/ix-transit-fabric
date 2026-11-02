package main

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// NodeNetworkUnit is the only unit this local planning package knows about.
// It deliberately does not derive a unit name from configuration input.
const NodeNetworkUnit = "ix-control-easytier.service"

var nodeNetworkPlanServiceNameRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,14}$`)

const (
	// NodeNetworkConfigFile is the separately managed, strict JSON declaration.
	// The binary, state directory, and EnvironmentFile are configuration fields
	// and are validated before inclusion in a unit.
	NodeNetworkConfigFile = "/etc/ix-control/node-network.json"
)

const (
	LocalOperationInstall   = "install"
	LocalOperationApply     = "apply"
	LocalOperationStop      = "stop"
	LocalOperationUninstall = "uninstall"
)

const (
	LocalActionWriteUnit   = "write_unit"
	LocalActionEnableUnit  = "enable_unit"
	LocalActionStartUnit   = "start_unit"
	LocalActionReloadUnit  = "reload_unit"
	LocalActionRestartUnit = "restart_unit"
	LocalActionStopUnit    = "stop_unit"
	LocalActionDisableUnit = "disable_unit"
	LocalActionRemoveUnit  = "remove_unit"
)

// LocalOperationAction is declarative.  Name is intentionally constrained to
// the constants above, while Unit is always NodeNetworkUnit; it is never a
// command line and must be interpreted by a separately reviewed local runner.
type LocalOperationAction struct {
	Name string `json:"name"`
	Unit string `json:"unit"`
}

// RedactedNodeNetworkConfig is safe to show in a local plan.  In particular,
// it contains no addresses, peers, configuration path, environment path, or
// environment values.
type RedactedNodeNetworkConfig struct {
	ConfigurationPresent bool `json:"configuration_present"`
	NoListener           bool `json:"no_listener"`
}

// LocalOperationPlan describes a prospective local change.  It is always a
// dry run: this package has no file-writing, process, network, or service
// management code.
type LocalOperationPlan struct {
	Operation string                    `json:"operation"`
	DryRun    bool                      `json:"dry_run"`
	Unit      string                    `json:"unit"`
	UnitText  string                    `json:"unit_text,omitempty"`
	Actions   []LocalOperationAction    `json:"actions"`
	Config    RedactedNodeNetworkConfig `json:"config"`
}

type nodeNetworkUnitInput struct {
	binaryPath      string
	networkName     string
	hostname        string
	ipv4            string
	listeners       []string
	peers           []string
	noListener      bool
	stateDir        string
	environmentFile string
	serviceName     string
}

// RenderNodeNetworkUnit renders the complete unit to stdout-compatible text.
func RenderNodeNetworkUnit(cfg NodeNetworkConfig) (string, error) {
	if err := requireNodeNetworkSupported(); err != nil {
		return "", err
	}
	if err := validateNodeNetworkConfig(cfg); err != nil {
		return "", err
	}
	in, err := nodeNetworkInputFromConfig(cfg)
	if err != nil {
		return "", err
	}
	return renderNodeNetworkUnit(in), nil
}

// RenderNodeNetworkSystemdUnit is an explicit alias for callers that want to
// make the output format clear at the call site.
func RenderNodeNetworkSystemdUnit(cfg NodeNetworkConfig) (string, error) {
	return RenderNodeNetworkUnit(cfg)
}

func renderNodeNetworkUnit(in nodeNetworkUnitInput) string {
	args := []string{
		in.binaryPath,
		"--network-name", in.networkName,
		"--hostname", in.hostname,
		"--ipv4", in.ipv4,
	}
	for _, listener := range in.listeners {
		args = append(args, "--listeners", listener)
	}
	for _, peer := range in.peers {
		args = append(args, "--peers", peer)
	}
	if in.noListener {
		args = append(args, "--no-listener")
	}
	args = append(args, "--state-dir", in.stateDir)

	return fmt.Sprintf(`[Unit]
Description=ix-control EasyTier local network (%s)
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
EnvironmentFile=%s
ExecStart=%s
Restart=on-failure
RestartSec=5s
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=%s
CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
`, in.serviceName, in.environmentFile, strings.Join(args, " "), in.stateDir)
}

// BuildLocalOperationPlan creates a non-executing plan for the supported
// lifecycle operations.  It never embeds unit text because a rendered unit
// includes the EnvironmentFile location.  Call RenderNodeNetworkUnit when the
// explicitly requested stdout unit text is needed.
func BuildLocalOperationPlan(operation string, cfg *NodeNetworkConfig) (LocalOperationPlan, error) {
	if err := requireNodeNetworkSupported(); err != nil {
		return LocalOperationPlan{}, err
	}
	operation = strings.ToLower(strings.TrimSpace(operation))
	if !oneOf(operation, LocalOperationInstall, LocalOperationApply, LocalOperationStop, LocalOperationUninstall) {
		return LocalOperationPlan{}, errors.New("unsupported local operation")
	}

	plan := LocalOperationPlan{
		Operation: operation,
		DryRun:    true,
		Unit:      NodeNetworkUnit,
		Actions:   nodeNetworkActions(operation),
	}
	if cfg == nil {
		if operation == LocalOperationStop || operation == LocalOperationUninstall {
			return plan, nil
		}
		return LocalOperationPlan{}, errors.New("node network configuration is required")
	}
	_, err := nodeNetworkInputFromConfig(*cfg)
	if err != nil {
		return LocalOperationPlan{}, err
	}
	if operation == LocalOperationApply {
		if err := validateNodeNetworkConfig(*cfg); err != nil {
			return LocalOperationPlan{}, err
		}
	}
	plan.Config = RedactedNodeNetworkConfig{
		ConfigurationPresent: true,
		NoListener:           cfg.NoListener,
	}
	return plan, nil
}

// PlanLocalOperation and NewLocalOperationPlan keep the public API readable
// for both procedural and constructor-style callers.
func PlanLocalOperation(operation string, cfg *NodeNetworkConfig) (LocalOperationPlan, error) {
	return BuildLocalOperationPlan(operation, cfg)
}

func NewLocalOperationPlan(operation string, cfg *NodeNetworkConfig) (LocalOperationPlan, error) {
	return BuildLocalOperationPlan(operation, cfg)
}

func nodeNetworkActions(operation string) []LocalOperationAction {
	names := map[string][]string{
		LocalOperationInstall:   {LocalActionWriteUnit, LocalActionEnableUnit, LocalActionStartUnit},
		LocalOperationApply:     {LocalActionWriteUnit, LocalActionReloadUnit, LocalActionRestartUnit},
		LocalOperationStop:      {LocalActionStopUnit},
		LocalOperationUninstall: {LocalActionStopUnit, LocalActionDisableUnit, LocalActionRemoveUnit},
	}[operation]
	actions := make([]LocalOperationAction, len(names))
	for i, name := range names {
		actions[i] = LocalOperationAction{Name: name, Unit: NodeNetworkUnit}
	}
	return actions
}

func nodeNetworkInputFromConfig(cfg NodeNetworkConfig) (nodeNetworkUnitInput, error) {
	in := nodeNetworkUnitInput{
		binaryPath:      cfg.BinaryPath,
		networkName:     cfg.NetworkName,
		hostname:        cfg.Hostname,
		ipv4:            cfg.IPv4,
		listeners:       append([]string(nil), cfg.Listeners...),
		peers:           append([]string(nil), cfg.Peers...),
		noListener:      cfg.NoListener,
		stateDir:        cfg.StateDir,
		environmentFile: cfg.NetworkSecretFile,
		serviceName:     cfg.ServiceName,
	}
	if err := validateNodeNetworkInput(in); err != nil {
		return nodeNetworkUnitInput{}, err
	}
	return in, nil
}

func validateNodeNetworkInput(in nodeNetworkUnitInput) error {
	for _, item := range []struct {
		name  string
		value string
	}{
		{"binary path", in.binaryPath},
		{"state directory", in.stateDir},
		{"environment file", in.environmentFile},
	} {
		if err := validateNodeNetworkPath(item.name, item.value); err != nil {
			return err
		}
	}
	if !nodeNetworkPlanServiceNameRE.MatchString(in.serviceName) || nodeNetworkReservedWord(in.serviceName) {
		return errors.New("invalid service name")
	}
	return nil
}

// LocalOperationActionNames returns the fixed action vocabulary.  It is useful
// to UIs and tests that must reject arbitrary operation text.
func LocalOperationActionNames() []string {
	names := []string{
		LocalActionWriteUnit, LocalActionEnableUnit, LocalActionStartUnit,
		LocalActionReloadUnit, LocalActionRestartUnit, LocalActionStopUnit,
		LocalActionDisableUnit, LocalActionRemoveUnit,
	}
	sort.Strings(names)
	return names
}
