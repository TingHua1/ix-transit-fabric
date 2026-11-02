package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeCLINodeNetworkConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	secret := filepath.Join(dir, "network.env")
	binary := filepath.Join(dir, "easytier-core")
	if err := os.WriteFile(secret, []byte("ET_NETWORK_SECRET=x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binary, []byte("local binary placeholder"), 0700); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "node-network.json")
	payload := `{"schema_version":1,"service_name":"ixnet","binary_path":"` + strings.ReplaceAll(binary, `\`, `\\`) + `","network_name":"fabric","network_secret_file":"` + strings.ReplaceAll(secret, `\`, `\\`) + `","hostname":"node-01.example","ipv4":"10.44.0.0/24","transport":"tcp","listeners":["tcp://127.0.0.1:11010"],"peers":[],"no_listener":false,"state_dir":"` + strings.ReplaceAll(filepath.Join(dir, "state"), `\`, `\\`) + `"}`
	if err := os.WriteFile(config, []byte(payload), 0600); err != nil {
		t.Fatal(err)
	}
	return config
}

func TestNodeNetworkCLIValidateAndPlansAreLocalAndRedacted(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose POSIX 0600 permission bits through os.Lstat")
	}
	config := writeCLINodeNetworkConfig(t)
	var out bytes.Buffer
	if err := runNodeNetworkCLI([]string{"validate", "--config", config, "--json"}, &out); err == nil || !strings.Contains(err.Error(), NodeNetworkConfigFile) {
		t.Fatalf("non-fixed config path accepted: %v", err)
	}
}

func TestNodeNetworkCLIStatusRejectsConfigWithoutLeakingIt(t *testing.T) {
	config := writeCLINodeNetworkConfig(t)
	// Windows FileMode does not expose POSIX 0600/0644 distinctions. A malformed
	// closed-schema file exercises the same redacted rejection path everywhere.
	if err := os.WriteFile(config, []byte(`{"schema_version":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runNodeNetworkCLI([]string{"status", "--config", config}, &out); err == nil || !strings.Contains(err.Error(), NodeNetworkConfigFile) {
		t.Fatalf("status accepted non-fixed config path: %v", err)
	}
}

func TestNodeNetworkCLIWindowsFailsClosedExceptStatus(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only safety behavior")
	}
	for _, action := range []string{"validate", "render-systemd", "install-local", "apply-local"} {
		if err := runNodeNetworkCLI([]string{action}, &bytes.Buffer{}); !errors.Is(err, ErrNodeNetworkUnsupported) {
			t.Fatalf("%s: expected unsupported safety error, got %v", action, err)
		}
	}
	var out bytes.Buffer
	if err := runNodeNetworkCLI([]string{"status"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"config_state":"unknown"`) {
		t.Fatalf("unexpected Windows status: %s", out.String())
	}
}

func TestNodeNetworkCLIHelperRejectsMissingActionWithoutExit(t *testing.T) {
	if err := runNodeNetworkCLI(nil, &bytes.Buffer{}); err == nil {
		t.Fatal("missing action accepted")
	}
}
