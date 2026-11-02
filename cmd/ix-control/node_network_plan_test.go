package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const nodeNetworkTestSecretValue = "local-test-secret-should-not-render"

func installedNodeNetworkConfig(t *testing.T) NodeNetworkConfig {
	t.Helper()
	if runtime.GOOS == "windows" || os.Geteuid() != 0 {
		t.Skip("strict runtime binary verification requires a root-owned Unix test file")
	}
	if os.Getenv("IX_CONTROL_TEST_FIXED_PATHS") != "1" {
		t.Skip("requires explicit isolated fixed-path fixture setup; never writes production paths by default")
	}
	dir := t.TempDir()
	secret := filepath.Join(dir, "network.secret")
	binary := filepath.Join(dir, "easytier-core")
	state := filepath.Join(dir, "state")
	if err := os.WriteFile(secret, []byte("ET_NETWORK_SECRET="+nodeNetworkTestSecretValue), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binary, []byte("binary"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(state, 0755); err != nil {
		t.Fatal(err)
	}
	cfg := validNodeNetworkConfig()
	cfg.NetworkSecretFile, cfg.BinaryPath, cfg.StateDir = secret, binary, state
	return cfg
}

func TestRenderNodeNetworkUnitRejectsInjection(t *testing.T) {
	for _, edit := range []func(*NodeNetworkConfig){
		func(c *NodeNetworkConfig) { c.NetworkSecretFile = "/etc/ix-control/x\nExecStart=/bad" },
		func(c *NodeNetworkConfig) { c.ServiceName = "ixet0;bad" },
		func(c *NodeNetworkConfig) { c.StateDir = "/var/lib/a b" },
		func(c *NodeNetworkConfig) { c.BinaryPath = "/usr/local/bin/easy%t" },
		func(c *NodeNetworkConfig) { c.NetworkSecretFile = "/etc/ix-control/%E" },
		func(c *NodeNetworkConfig) { c.StateDir = "/var/lib/%S" },
	} {
		cfg := validNodeNetworkConfig()
		edit(&cfg)
		if _, err := RenderNodeNetworkUnit(cfg); err == nil {
			t.Fatal("unsafe input unexpectedly rendered")
		}
	}
}

func TestLocalOperationPlanIsRedactedAndDeclarative(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("node-network planning is unsupported on Windows")
	}
	cfg := validNodeNetworkConfig()
	cfg.NetworkSecretFile = "/etc/ix-control/must-not-appear"
	plan, err := BuildLocalOperationPlan(LocalOperationInstall, &cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.DryRun || plan.Unit != NodeNetworkUnit {
		t.Fatalf("unexpected plan: %#v", plan)
	}
	encoded, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"must-not-appear", cfg.BinaryPath, cfg.StateDir, cfg.IPv4, cfg.Listeners[0], cfg.Peers[0], "sh -c", "eval", "systemctl", "--token"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Errorf("plan contains forbidden %q: %s", forbidden, encoded)
		}
	}
}

func TestLocalOperationPlanUsesFixedActions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("node-network planning is unsupported on Windows")
	}
	want := map[string][]string{
		LocalOperationInstall:   {LocalActionWriteUnit, LocalActionEnableUnit, LocalActionStartUnit},
		LocalOperationApply:     {LocalActionWriteUnit, LocalActionReloadUnit, LocalActionRestartUnit},
		LocalOperationStop:      {LocalActionStopUnit},
		LocalOperationUninstall: {LocalActionStopUnit, LocalActionDisableUnit, LocalActionRemoveUnit},
	}
	for operation, names := range want {
		cfg := installedNodeNetworkConfig(t)
		plan, err := BuildLocalOperationPlan(operation, &cfg)
		if err != nil {
			t.Fatalf("%s: %v", operation, err)
		}
		if len(plan.Actions) != len(names) {
			t.Fatalf("%s actions: %#v", operation, plan.Actions)
		}
		for i, name := range names {
			if plan.Actions[i].Name != name || plan.Actions[i].Unit != NodeNetworkUnit {
				t.Fatalf("%s action %d: %#v", operation, i, plan.Actions[i])
			}
		}
	}
}

func TestRenderNodeNetworkUnitUsesConfiguredPaths(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("node-network rendering is unsupported on Windows")
	}
	config := installedNodeNetworkConfig(t)
	unit, err := RenderNodeNetworkUnit(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"EnvironmentFile=/etc/ix-control/network.secret",
		"ExecStart=/usr/local/libexec/ix-control/easytier-core --network-name network-a --hostname node-a.example --ipv4 10.44.0.0/24 --listeners tcp://*:11010 --peers tcp://198.51.100.2:11010 --state-dir /var/lib/ix-control/easytier",
		"After=network-online.target", "Restart=on-failure", "CAP_NET_ADMIN", "ix-easytier",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("unit missing %q:\n%s", want, unit)
		}
	}
	for _, forbidden := range []string{"--config-file", NodeNetworkConfigFile, "--daemon", "sh -c", "eval", "systemctl", "--token", "ET_NETWORK_SECRET", nodeNetworkTestSecretValue} {
		if strings.Contains(unit, forbidden) {
			t.Errorf("unit contains forbidden %q", forbidden)
		}
	}
}

func TestRenderNodeNetworkUnitConsumesDeclarationWithoutSecretOrJSONConfig(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("node-network rendering is unsupported on Windows")
	}
	cfg := installedNodeNetworkConfig(t)
	cfg.Listeners = []string{"tcp://*:11010", "tcp://127.0.0.1:11011"}
	cfg.Peers = []string{"tcp://198.51.100.2:11010", "tcp://198.51.100.3:11010"}
	cfg.NoListener = false
	unit, err := RenderNodeNetworkUnit(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Description=ix-control EasyTier local network (ix-easytier)",
		"--network-name network-a", "--hostname node-a.example", "--ipv4 10.44.0.0/24",
		"--listeners tcp://*:11010", "--listeners tcp://127.0.0.1:11011",
		"--peers tcp://198.51.100.2:11010", "--peers tcp://198.51.100.3:11010",
		"--state-dir /var/lib/ix-control/easytier", "EnvironmentFile=/etc/ix-control/network.secret",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("unit omitted declaration mapping %q:\n%s", want, unit)
		}
	}
	for _, forbidden := range []string{"--config-file", NodeNetworkConfigFile, "ET_NETWORK_SECRET=", "NETWORK_SECRET=test"} {
		if strings.Contains(unit, forbidden) {
			t.Errorf("unit leaked or invented %q:\n%s", forbidden, unit)
		}
	}

	cfg.NoListener, cfg.Listeners = true, nil
	unit, err = RenderNodeNetworkUnit(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(unit, "--no-listener") || strings.Contains(unit, "--listeners") {
		t.Fatalf("no_listener was not rendered safely:\n%s", unit)
	}
}
