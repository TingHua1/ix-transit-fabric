package main

import (
	"encoding/json"
	"errors"
	"io/fs"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type fakeNodeNetworkInspector struct {
	files map[string]NodeNetworkFileInfo
	err   error
}

type fakeNodeNetworkSecretReader struct {
	contents []byte
	err      error
}

func (f fakeNodeNetworkSecretReader) ReadNodeNetworkSecret(string) ([]byte, error) {
	return f.contents, f.err
}

func (f fakeNodeNetworkInspector) InspectNodeNetworkFile(path string) (NodeNetworkFileInfo, error) {
	if f.err != nil {
		return NodeNetworkFileInfo{}, f.err
	}
	return f.files[path], nil
}

func validNodeNetworkConfig() NodeNetworkConfig {
	return NodeNetworkConfig{
		SchemaVersion: 1, ServiceName: "ix-easytier", BinaryPath: "/usr/local/libexec/ix-control/easytier-core",
		NetworkName: "network-a", NetworkSecretFile: "/etc/ix-control/network.secret", Hostname: "node-a.example",
		IPv4: "10.44.0.0/24", Transport: "tcp", Listeners: []string{"tcp://*:11010"},
		Peers: []string{"tcp://198.51.100.2:11010"}, StateDir: "/var/lib/ix-control/easytier",
	}
}

func validNodeNetworkSecretReader() fakeNodeNetworkSecretReader {
	return fakeNodeNetworkSecretReader{contents: []byte("ET_NETWORK_SECRET=x")}
}

func validNodeNetworkInspector() fakeNodeNetworkInspector {
	files := map[string]NodeNetworkFileInfo{
		"/":                              {Exists: true, Directory: true, Mode: 0755, Owner: "0"},
		"/etc":                           {Exists: true, Directory: true, Mode: 0755, Owner: "0"},
		"/etc/ix-control":                {Exists: true, Directory: true, Mode: 0755, Owner: "0"},
		"/usr":                           {Exists: true, Directory: true, Mode: 0755, Owner: "0"},
		"/usr/local":                     {Exists: true, Directory: true, Mode: 0755, Owner: "0"},
		"/usr/local/libexec":             {Exists: true, Directory: true, Mode: 0755, Owner: "0"},
		"/usr/local/libexec/ix-control":  {Exists: true, Directory: true, Mode: 0755, Owner: "0"},
		"/var":                           {Exists: true, Directory: true, Mode: 0755, Owner: "0"},
		"/var/lib":                       {Exists: true, Directory: true, Mode: 0755, Owner: "0"},
		"/var/lib/ix-control":            {Exists: true, Directory: true, Mode: 0755, Owner: "0"},
		"/var/lib/ix-control/easytier":   {Exists: true, Directory: true, Mode: 0755, Owner: "0"},
		"/etc/ix-control/network.secret": {Exists: true, Regular: true, Mode: 0600},
		"/usr/local/libexec/ix-control/easytier-core": {Exists: true, Regular: true, Mode: 0755, Owner: "0"},
	}
	files["/etc/ix-control/network.secret"] = NodeNetworkFileInfo{Exists: true, Regular: true, Mode: 0600, Owner: "0"}
	return fakeNodeNetworkInspector{files: files}
}

func TestNodeNetworkConfigClosedSchemaAndSecretExclusion(t *testing.T) {
	config := validNodeNetworkConfig()
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, extra := range []string{`"unexpected":true`, `"network_secret":"do-not-log-me"`, `"node_id":"legacy"`} {
		payload := append(append([]byte{}, raw[:len(raw)-1]...), append([]byte(","), append([]byte(extra), '}')...)...)
		if _, err := decodeNodeNetworkConfig(payload); err == nil {
			t.Fatalf("accepted forbidden field %s", extra)
		}
	}
}

func TestNodeNetworkConfigRejectsNullAndNonArrayCollections(t *testing.T) {
	cfg := validNodeNetworkConfig()
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, replacement := range [][2]string{{`"hostname":"node-a.example"`, `"hostname":null`}, {`"listeners":["tcp://*:11010"]`, `"listeners":null`}, {`"peers":["tcp://198.51.100.2:11010"]`, `"peers":"not-an-array"`}} {
		payload := strings.Replace(string(raw), replacement[0], replacement[1], 1)
		if _, err := decodeNodeNetworkConfig([]byte(payload)); err == nil {
			t.Fatalf("accepted invalid JSON shape: %s", replacement[1])
		}
	}
}

func TestNodeNetworkConfigValidationRejectsUnsafeInputs(t *testing.T) {
	cases := []struct {
		name   string
		change func(*NodeNetworkConfig)
	}{
		{"schema", func(c *NodeNetworkConfig) { c.SchemaVersion = 2 }},
		{"cidr", func(c *NodeNetworkConfig) { c.IPv4 = "10.44.1.1/24" }},
		{"transport", func(c *NodeNetworkConfig) { c.Transport = "proxy" }},
		{"listener scheme", func(c *NodeNetworkConfig) { c.Listeners = []string{"udp://*:1"} }},
		{"peer wildcard", func(c *NodeNetworkConfig) { c.Peers = []string{"tcp://*:1"} }},
		{"peer any", func(c *NodeNetworkConfig) { c.Peers = []string{"tcp://any:1"} }},
		{"service exit", func(c *NodeNetworkConfig) { c.ServiceName = "exit" }},
		{"path newline", func(c *NodeNetworkConfig) { c.NetworkSecretFile = "/etc/ix-control/x\nrun" }},
		{"no listener mismatch", func(c *NodeNetworkConfig) { c.NoListener = true }},
		{"no listener peers", func(c *NodeNetworkConfig) { c.NoListener = true; c.Listeners = nil; c.Peers = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := validNodeNetworkConfig()
			tc.change(&config)
			if err := validateNodeNetworkConfigWithSecretReader(config, validNodeNetworkInspector(), validNodeNetworkSecretReader()); err == nil {
				t.Fatal("unsafe config accepted")
			}
		})
	}
}

func TestNodeNetworkSupportsEveryDeclaredTransport(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("node-network runtime validation is unsupported on Windows")
	}
	for _, transport := range []string{"wg", "udp", "tcp", "ws", "wss", "quic"} {
		t.Run(transport, func(t *testing.T) {
			cfg := validNodeNetworkConfig()
			cfg.Transport = transport
			cfg.Listeners = []string{transport + "://*:11010"}
			cfg.Peers = []string{transport + "://198.51.100.2:11010"}
			if err := validateNodeNetworkConfigWithSecretReader(cfg, validNodeNetworkInspector(), validNodeNetworkSecretReader()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNodeNetworkSecretBinaryAndConfigFileInspector(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("node-network file validation is unsupported on Windows")
	}
	config := validNodeNetworkConfig()
	for _, info := range []NodeNetworkFileInfo{
		{}, {Exists: true, Regular: false}, {Exists: true, Regular: true, Symlink: true}, {Exists: true, Regular: true, Mode: 0640},
	} {
		inspector := validNodeNetworkInspector()
		inspector.files[config.NetworkSecretFile] = info
		if err := validateNodeNetworkConfigWithSecretReader(config, inspector, validNodeNetworkSecretReader()); err == nil {
			t.Fatal("unsafe secret accepted")
		}
	}
	inspector := validNodeNetworkInspector()
	inspector.files[config.BinaryPath] = NodeNetworkFileInfo{Exists: true, Regular: true, Mode: 0777, Owner: "0"}
	if err := validateNodeNetworkConfigWithSecretReader(config, inspector, validNodeNetworkSecretReader()); err == nil {
		t.Fatal("world-writable binary accepted")
	}
	file := NodeNetworkConfigFile
	good := validNodeNetworkInspector()
	good.files[file] = NodeNetworkFileInfo{Exists: true, Regular: true, Mode: fs.FileMode(0600), Owner: "0"}
	if err := validateNodeNetworkConfigFile(file, "0", good); err != nil {
		t.Fatalf("good inspected config %q rejected: %v", file, err)
	}
	badMode := good
	badMode.files[file] = NodeNetworkFileInfo{Exists: true, Regular: true, Mode: 0644, Owner: "0"}
	if err := validateNodeNetworkConfigFile(file, "0", badMode); err == nil {
		t.Fatal("world-readable config accepted")
	}
}

func TestNodeNetworkSecretEnvironmentFileContractDoesNotExposeSecret(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("node-network file validation is unsupported on Windows")
	}
	if !validNodeNetworkSecretEnvironmentFile([]byte("ET_NETWORK_SECRET=x")) {
		t.Fatal("minimal valid EnvironmentFile rejected")
	}
	for _, contents := range [][]byte{
		nil,
		[]byte("ET_NETWORK_SECRET="),
		[]byte("NETWORK_SECRET=x"),
		[]byte("ET_NETWORK_SECRET=x\nOTHER_VARIABLE=y"),
		[]byte("ET_NETWORK_SECRET=x\n"),
		[]byte("ET_NETWORK_SECRET=x y"),
		[]byte("ET_NETWORK_SECRET=x\x00"),
	} {
		if validNodeNetworkSecretEnvironmentFile(contents) {
			t.Fatalf("invalid EnvironmentFile accepted: %q", contents)
		}
	}

	const secret = "not-to-be-exposed"
	cfg := validNodeNetworkConfig()
	err := validateNodeNetworkConfigWithSecretReader(cfg, validNodeNetworkInspector(), fakeNodeNetworkSecretReader{
		contents: []byte("ET_NETWORK_SECRET=" + secret + "\nOTHER_VARIABLE=x"),
	})
	if err == nil || err.Error() != nodeNetworkSecretFormatError || strings.Contains(err.Error(), secret) {
		t.Fatalf("secret validator error was not fixed and redacted: %v", err)
	}
	err = validateNodeNetworkConfigWithSecretReader(cfg, validNodeNetworkInspector(), fakeNodeNetworkSecretReader{err: errors.New(secret)})
	if err == nil || err.Error() != nodeNetworkSecretFormatError || strings.Contains(err.Error(), secret) {
		t.Fatalf("secret reader error was not fixed and redacted: %v", err)
	}
}

func TestNodeNetworkInstallValidationAllowsMissingBinaryButRequiresSafeParent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("node-network file validation is unsupported on Windows")
	}
	cfg := validNodeNetworkConfig()
	inspector := validNodeNetworkInspector()
	inspector.files[filepath.Dir(cfg.BinaryPath)] = NodeNetworkFileInfo{Exists: true, Directory: true, Mode: 0755, Owner: "0"}
	delete(inspector.files, cfg.BinaryPath)
	if err := validateNodeNetworkConfigForInstallWithSecretReader(cfg, inspector, validNodeNetworkSecretReader()); err != nil {
		t.Fatalf("first install target rejected: %v", err)
	}
	if err := validateNodeNetworkConfigWithSecretReader(cfg, inspector, validNodeNetworkSecretReader()); err == nil {
		t.Fatal("runtime validation accepted missing binary")
	}
	for _, binary := range []NodeNetworkFileInfo{
		{Exists: true, Regular: true, Mode: 0644, Owner: "0"},
		{Exists: true, Regular: true, Mode: 0755, Owner: "1000"},
		{Exists: true, Regular: true, Mode: 0775, Owner: "0"},
	} {
		inspector.files[cfg.BinaryPath] = binary
		if err := validateNodeNetworkConfigWithSecretReader(cfg, inspector, validNodeNetworkSecretReader()); err == nil {
			t.Fatalf("weak binary accepted: %+v", binary)
		}
	}
	inspector.files[filepath.Dir(cfg.BinaryPath)] = NodeNetworkFileInfo{Exists: true, Directory: true, Mode: 0775, Owner: "0"}
	delete(inspector.files, cfg.BinaryPath)
	if err := validateNodeNetworkConfigForInstallWithSecretReader(cfg, inspector, validNodeNetworkSecretReader()); err == nil {
		t.Fatal("unsafe binary parent accepted")
	}
}

func TestNodeNetworkManagedPrefixesAndParentTrustChain(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("node-network file validation is unsupported on Windows")
	}
	for _, edit := range []func(*NodeNetworkConfig){
		func(c *NodeNetworkConfig) { c.BinaryPath = "/usr/local/bin/easytier-core" },
		func(c *NodeNetworkConfig) { c.NetworkSecretFile = "/etc/network.secret" },
		func(c *NodeNetworkConfig) { c.StateDir = "/var/lib/ix-control/other" },
	} {
		cfg := validNodeNetworkConfig()
		edit(&cfg)
		if err := validateNodeNetworkConfigWithSecretReader(cfg, validNodeNetworkInspector(), validNodeNetworkSecretReader()); err == nil {
			t.Fatal("unmanaged path accepted")
		}
	}
	inspector := validNodeNetworkInspector()
	inspector.files["/usr/local"] = NodeNetworkFileInfo{Exists: true, Directory: true, Mode: 0775, Owner: "0"}
	if err := validateNodeNetworkConfigWithSecretReader(validNodeNetworkConfig(), inspector, validNodeNetworkSecretReader()); err == nil {
		t.Fatal("group-writable parent accepted")
	}
	inspector = validNodeNetworkInspector()
	inspector.files["/etc/ix-control"] = NodeNetworkFileInfo{Exists: true, Directory: true, Symlink: true, Mode: 0755, Owner: "0"}
	if err := validateNodeNetworkConfigWithSecretReader(validNodeNetworkConfig(), inspector, validNodeNetworkSecretReader()); err == nil {
		t.Fatal("symlink parent accepted")
	}
}

func TestNodeNetworkSummaryDoesNotLeakSensitiveLocationData(t *testing.T) {
	config := validNodeNetworkConfig()
	config.NetworkSecretFile = "/etc/ix-control/private-super-secret"
	b, err := json.Marshal(config.Summary())
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"secret", config.NetworkSecretFile, config.BinaryPath, config.StateDir, config.IPv4, config.Listeners[0], config.Peers[0]} {
		if strings.Contains(string(b), forbidden) {
			t.Fatalf("summary leaked sensitive data: %s", b)
		}
	}
}
