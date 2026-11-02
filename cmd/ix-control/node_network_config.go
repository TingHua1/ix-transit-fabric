package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const nodeNetworkSchemaVersion = 1

// ErrNodeNetworkUnsupported is returned rather than attempting to approximate
// Unix ownership and permission checks on Windows.
var ErrNodeNetworkUnsupported = errors.New("node-network local operations are unsupported on Windows for safety")

// NodeNetworkConfig is the closed, declarative node-network schema. It never
// contains a network secret; NetworkSecretFile names the local EnvironmentFile
// from which the service obtains that value.
type NodeNetworkConfig struct {
	SchemaVersion     int      `json:"schema_version"`
	ServiceName       string   `json:"service_name"`
	BinaryPath        string   `json:"binary_path"`
	NetworkName       string   `json:"network_name"`
	NetworkSecretFile string   `json:"network_secret_file"`
	Hostname          string   `json:"hostname"`
	IPv4              string   `json:"ipv4"`
	Transport         string   `json:"transport"`
	Listeners         []string `json:"listeners"`
	Peers             []string `json:"peers"`
	NoListener        bool     `json:"no_listener"`
	StateDir          string   `json:"state_dir"`
}

// NodeNetworkFileInfo is deliberately independent of os.FileInfo so callers
// can test ownership and file type policy without depending on a host OS.
type NodeNetworkFileInfo struct {
	Exists    bool
	Regular   bool
	Directory bool
	Symlink   bool
	Mode      fs.FileMode
	Owner     string
}

// NodeNetworkFileInspector provides local file checks without following
// symlinks. It makes security decisions testable on every supported OS.
type NodeNetworkFileInspector interface {
	InspectNodeNetworkFile(path string) (NodeNetworkFileInfo, error)
}

type OSNodeNetworkFileInspector struct{}

// NodeNetworkSecretReader is intentionally separate from file inspection:
// validation must inspect the EnvironmentFile bytes, while callers must never
// retain or expose those bytes.  Test readers can provide only validity cases
// without requiring a real root-owned file.
type NodeNetworkSecretReader interface {
	ReadNodeNetworkSecret(path string) ([]byte, error)
}

// osRead is a narrow seam for the production reader.  Its output is consumed
// immediately by the local validator and is never stored in configuration,
// plans, status, or errors.
var osRead = os.ReadFile

type OSNodeNetworkSecretReader struct{}

func (OSNodeNetworkSecretReader) ReadNodeNetworkSecret(name string) ([]byte, error) {
	return osRead(name)
}

func (OSNodeNetworkFileInspector) InspectNodeNetworkFile(name string) (NodeNetworkFileInfo, error) {
	info, err := os.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return NodeNetworkFileInfo{}, nil
	}
	if err != nil {
		return NodeNetworkFileInfo{}, err
	}
	mode := info.Mode()
	return NodeNetworkFileInfo{
		Exists: true, Regular: mode.IsRegular(), Directory: mode.IsDir(),
		Symlink: mode&fs.ModeSymlink != 0, Mode: mode, Owner: nodeNetworkOwner(info),
	}, nil
}

// nodeNetworkOwner uses reflection so this source remains buildable on Unix
// and Windows. Windows has no portable numeric owner and reports an empty one.
func nodeNetworkOwner(info fs.FileInfo) string {
	v := reflect.ValueOf(info.Sys())
	if !v.IsValid() {
		return ""
	}
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return ""
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return ""
	}
	uid := v.FieldByName("Uid")
	if !uid.IsValid() || !uid.CanUint() {
		return ""
	}
	return fmt.Sprintf("%d", uid.Uint())
}

var nodeNetworkIdentifierRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$`)
var nodeNetworkHostnameRE = regexp.MustCompile(`(?i)^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$`)

// DecodeNodeNetworkConfig performs a strict closed-schema decode. Legacy
// names (including network_secret) are intentionally not accepted.
func DecodeNodeNetworkConfig(raw json.RawMessage) (NodeNetworkConfig, error) {
	return decodeNodeNetworkConfig(raw)
}

func decodeNodeNetworkConfig(raw json.RawMessage) (NodeNetworkConfig, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return NodeNetworkConfig{}, err
	}
	required := []string{"schema_version", "service_name", "binary_path", "network_name", "network_secret_file", "hostname", "ipv4", "transport", "listeners", "peers", "no_listener", "state_dir"}
	if len(fields) != len(required) {
		return NodeNetworkConfig{}, errors.New("node network config has unknown or missing fields")
	}
	for _, name := range required {
		value, ok := fields[name]
		if !ok {
			return NodeNetworkConfig{}, fmt.Errorf("node network config missing %s", name)
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return NodeNetworkConfig{}, fmt.Errorf("node network config %s cannot be null", name)
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var config NodeNetworkConfig
	if err := decoder.Decode(&config); err != nil {
		return NodeNetworkConfig{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return NodeNetworkConfig{}, errors.New("node network config has trailing data")
	}
	if err := validateNodeNetworkConfigSyntax(config); err != nil {
		return NodeNetworkConfig{}, err
	}
	return config, nil
}

func ValidateNodeNetworkConfig(config NodeNetworkConfig, inspectors ...NodeNetworkFileInspector) error {
	return validateNodeNetworkConfig(config, inspectors...)
}

func validateNodeNetworkConfig(config NodeNetworkConfig, inspectors ...NodeNetworkFileInspector) error {
	return validateNodeNetworkConfigWithSecretReader(config, nodeNetworkInspector(inspectors...), OSNodeNetworkSecretReader{})
}

func validateNodeNetworkConfigWithSecretReader(config NodeNetworkConfig, inspector NodeNetworkFileInspector, reader NodeNetworkSecretReader) error {
	if err := requireNodeNetworkSupported(); err != nil {
		return err
	}
	if err := validateNodeNetworkConfigSyntax(config); err != nil {
		return err
	}
	if err := requireNodeNetworkSecret(inspector, reader, config.NetworkSecretFile); err != nil {
		return err
	}
	if err := requireNodeNetworkStateDirectory(inspector, config.StateDir); err != nil {
		return fmt.Errorf("state_dir: %w", err)
	}
	return requireNodeNetworkBinary(inspector, config.BinaryPath)
}

// validateNodeNetworkConfigForInstall permits a missing binary only for the
// first local install. The secret remains subject to the normal strict policy,
// while the binary destination directory is checked before staging files into
// it.
func validateNodeNetworkConfigForInstall(config NodeNetworkConfig, inspectors ...NodeNetworkFileInspector) error {
	return validateNodeNetworkConfigForInstallWithSecretReader(config, nodeNetworkInspector(inspectors...), OSNodeNetworkSecretReader{})
}

func validateNodeNetworkConfigForInstallWithSecretReader(config NodeNetworkConfig, inspector NodeNetworkFileInspector, reader NodeNetworkSecretReader) error {
	if err := requireNodeNetworkSupported(); err != nil {
		return err
	}
	if err := validateNodeNetworkConfigSyntax(config); err != nil {
		return err
	}
	if err := requireNodeNetworkSecret(inspector, reader, config.NetworkSecretFile); err != nil {
		return err
	}
	if err := requireNodeNetworkStateDirectory(inspector, config.StateDir); err != nil {
		return fmt.Errorf("state_dir: %w", err)
	}
	return requireNodeNetworkBinaryParent(inspector, filepath.Dir(config.BinaryPath))
}

func nodeNetworkInspector(inspectors ...NodeNetworkFileInspector) NodeNetworkFileInspector {
	inspector := NodeNetworkFileInspector(OSNodeNetworkFileInspector{})
	if len(inspectors) > 0 && inspectors[0] != nil {
		inspector = inspectors[0]
	}
	return inspector
}

func validateNodeNetworkConfigSyntax(config NodeNetworkConfig) error {
	if config.SchemaVersion != nodeNetworkSchemaVersion {
		return fmt.Errorf("schema_version must be %d", nodeNetworkSchemaVersion)
	}
	for _, item := range []struct{ name, value string }{
		{"service_name", config.ServiceName}, {"network_name", config.NetworkName},
	} {
		if !nodeNetworkIdentifierRE.MatchString(item.value) || nodeNetworkReservedWord(item.value) {
			return fmt.Errorf("%s must be a non-reserved identifier", item.name)
		}
	}
	if !validNodeNetworkHostname(config.Hostname) {
		return errors.New("hostname must be a non-reserved hostname")
	}
	if err := validateNodeNetworkPath("binary_path", config.BinaryPath); err != nil {
		return err
	}
	if err := validateNodeNetworkPath("network_secret_file", config.NetworkSecretFile); err != nil {
		return err
	}
	if err := validateNodeNetworkPath("state_dir", config.StateDir); err != nil {
		return err
	}
	if err := requireNodeNetworkManagedPaths(config); err != nil {
		return err
	}
	prefix, err := netip.ParsePrefix(config.IPv4)
	if err != nil || !prefix.Addr().Is4() || prefix.Bits() == 0 || prefix != prefix.Masked() {
		return errors.New("ipv4 must be a masked non-default IPv4 CIDR")
	}
	if !nodeNetworkTransport(config.Transport) {
		return errors.New("transport must be wg, udp, tcp, ws, wss, or quic")
	}
	if config.Listeners == nil || config.Peers == nil {
		return errors.New("listeners and peers must be JSON arrays")
	}
	if config.NoListener {
		if len(config.Listeners) != 0 {
			return errors.New("no_listener cannot be used with listeners")
		}
	} else if len(config.Listeners) == 0 {
		return errors.New("a listener is required unless no_listener is true")
	}
	if len(config.Peers) == 0 && config.NoListener {
		return errors.New("no_listener requires at least one peer")
	}
	if err := validateNodeNetworkURIs("listener", config.Listeners, config.Transport, true); err != nil {
		return err
	}
	if err := validateNodeNetworkURIs("peer", config.Peers, config.Transport, false); err != nil {
		return err
	}

	return nil
}

func nodeNetworkTransport(value string) bool {
	switch value {
	case "wg", "udp", "tcp", "ws", "wss", "quic":
		return true
	default:
		return false
	}
}

func nodeNetworkReservedWord(value string) bool {
	switch strings.ToLower(value) {
	case "tun0", "exit", "default", "proxy":
		return true
	default:
		return false
	}
}

func validNodeNetworkHostname(value string) bool {
	return len(value) <= 253 && nodeNetworkHostnameRE.MatchString(value) && !nodeNetworkReservedWord(value)
}

func validateNodeNetworkURIs(label string, values []string, transport string, listener bool) error {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			return fmt.Errorf("duplicate %s", label)
		}
		seen[value] = struct{}{}
		if err := validateNodeNetworkURI(label, value, transport, listener); err != nil {
			return err
		}
	}
	return nil
}

func validateNodeNetworkURI(label, value, transport string, listener bool) error {
	if value == "" || strings.ContainsAny(value, " \t\r\n;|&$`'\"\\<>?!(){}[]%") {
		return fmt.Errorf("%s contains unsafe characters", label)
	}
	u, err := url.Parse(value)
	if err != nil || u.Scheme != transport || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return fmt.Errorf("%s must be a credential-free %s URI", label, transport)
	}
	port, err := strconv.ParseUint(u.Port(), 10, 16)
	if err != nil || port == 0 {
		return fmt.Errorf("%s must include a valid port", label)
	}
	host := u.Hostname()
	if host == "" || !validNodeNetworkURIHost(host, listener) {
		return fmt.Errorf("%s must include a valid host", label)
	}
	return nil
}

func validNodeNetworkURIHost(host string, listener bool) bool {
	if listener && (host == "*" || host == "0.0.0.0" || host == "::") {
		return true
	}
	if !listener && (host == "*" || host == "0.0.0.0" || host == "::" || strings.EqualFold(host, "any")) {
		return false
	}
	if nodeNetworkReservedWord(host) {
		return false
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return !addr.IsUnspecified()
	}
	return validNodeNetworkHostname(host) && net.ParseIP(host) == nil
}

func validateNodeNetworkPath(label, value string) error {
	posixPath := strings.HasPrefix(value, "/")
	clean := filepath.Clean(value) == value
	if posixPath {
		clean = path.Clean(value) == value
	}
	if value == "" || (!filepath.IsAbs(value) && !posixPath) || !clean || filepath.Base(value) == "." {
		return fmt.Errorf("%s must be an absolute clean path", label)
	}
	if strings.ContainsAny(value, "\r\n\t ;|&$`'\"<>*?!(){}[]@%") {
		return fmt.Errorf("%s contains unsafe characters", label)
	}
	return nil
}

const (
	maxNodeNetworkSecretEnvironmentFileSize = 4096
	nodeNetworkSecretFormatError            = "network_secret_file has invalid EnvironmentFile format"
)

func requireNodeNetworkSecret(inspector NodeNetworkFileInspector, reader NodeNetworkSecretReader, name string) error {
	if err := requireNodeNetworkTrustedDirectoryChain(inspector, filepath.Dir(name)); err != nil {
		return fmt.Errorf("network_secret_file parent: %w", err)
	}
	info, err := inspector.InspectNodeNetworkFile(name)
	if err != nil {
		return fmt.Errorf("inspect network secret: %w", err)
	}
	if !info.Exists || !info.Regular || info.Symlink || info.Mode.Perm() != 0600 || info.Owner != "0" {
		return errors.New("network_secret_file must be an existing root-owned regular non-symlink file with mode 0600")
	}
	if reader == nil {
		reader = OSNodeNetworkSecretReader{}
	}
	contents, err := reader.ReadNodeNetworkSecret(name)
	defer clear(contents)
	if err != nil || !validNodeNetworkSecretEnvironmentFile(contents) {
		return errors.New(nodeNetworkSecretFormatError)
	}
	return nil
}

// validNodeNetworkSecretEnvironmentFile accepts exactly one EnvironmentFile
// assignment, ET_NETWORK_SECRET=<nonempty value>.  It intentionally reports
// only a boolean so no secret bytes can become part of an error or result.
func validNodeNetworkSecretEnvironmentFile(contents []byte) bool {
	if len(contents) == 0 || len(contents) > maxNodeNetworkSecretEnvironmentFileSize || !utf8.Valid(contents) {
		return false
	}
	const prefix = "ET_NETWORK_SECRET="
	if !bytes.HasPrefix(contents, []byte(prefix)) || len(contents) == len(prefix) {
		return false
	}
	for value := contents; len(value) > 0; {
		r, size := utf8.DecodeRune(value)
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
		value = value[size:]
	}
	return true
}

func requireNodeNetworkBinary(inspector NodeNetworkFileInspector, name string) error {
	if err := requireNodeNetworkTrustedDirectoryChain(inspector, filepath.Dir(name)); err != nil {
		return fmt.Errorf("binary_path parent: %w", err)
	}
	info, err := inspector.InspectNodeNetworkFile(name)
	if err != nil {
		return fmt.Errorf("inspect node network binary: %w", err)
	}
	if !info.Exists || !info.Regular || info.Symlink || info.Mode.Perm()&0022 != 0 || info.Mode.Perm()&0111 == 0 || info.Owner != "0" {
		return errors.New("binary_path must be an existing root-owned regular non-symlink executable that is not group- or world-writable")
	}
	return nil
}

func requireNodeNetworkBinaryParent(inspector NodeNetworkFileInspector, name string) error {
	return requireNodeNetworkTrustedDirectoryChain(inspector, name)
}

// ValidateNodeNetworkConfigFile checks the separately stored strict JSON file
// before it is read. Ownership can be skipped on Windows with an empty owner.
func ValidateNodeNetworkConfigFile(path, expectedOwner string, inspector NodeNetworkFileInspector) error {
	return validateNodeNetworkConfigFile(path, expectedOwner, inspector)
}

func validateNodeNetworkConfigFile(path, expectedOwner string, inspector NodeNetworkFileInspector) error {
	if err := requireNodeNetworkSupported(); err != nil {
		return err
	}
	if err := validateNodeNetworkPath("node network config path", path); err != nil {
		return err
	}
	if path != NodeNetworkConfigFile {
		return fmt.Errorf("node network config path must be %s", NodeNetworkConfigFile)
	}
	if inspector == nil {
		inspector = OSNodeNetworkFileInspector{}
	}
	info, err := inspector.InspectNodeNetworkFile(path)
	if err != nil {
		return fmt.Errorf("inspect node network config: %w", err)
	}
	if err := requireNodeNetworkTrustedDirectoryChain(inspector, filepath.Dir(path)); err != nil {
		return fmt.Errorf("node network config parent: %w", err)
	}
	if !info.Exists || !info.Regular || info.Symlink || info.Mode.Perm() != 0600 {
		return errors.New("node network config must be an existing regular non-symlink file with mode 0600")
	}
	if expectedOwner != "" && info.Owner != expectedOwner {
		return fmt.Errorf("node network config owner must be %s", expectedOwner)
	}
	return nil
}

const (
	nodeNetworkSecretPrefix = "/etc/ix-control/"
	nodeNetworkBinaryPrefix = "/usr/local/libexec/ix-control/"
	nodeNetworkStatePrefix  = "/var/lib/ix-control/easytier/"
)

// requireNodeNetworkManagedPaths fixes the trust boundary to administrator
// managed roots.  Arbitrary absolute paths are not a substitute for a trust
// chain: each accepted path is subsequently checked component by component.
func requireNodeNetworkManagedPaths(config NodeNetworkConfig) error {
	if !strings.HasPrefix(config.NetworkSecretFile, nodeNetworkSecretPrefix) || config.NetworkSecretFile == nodeNetworkSecretPrefix {
		return fmt.Errorf("network_secret_file must be below %s", nodeNetworkSecretPrefix)
	}
	if !strings.HasPrefix(config.BinaryPath, nodeNetworkBinaryPrefix) || config.BinaryPath == nodeNetworkBinaryPrefix {
		return fmt.Errorf("binary_path must be below %s", nodeNetworkBinaryPrefix)
	}
	if config.StateDir != strings.TrimSuffix(nodeNetworkStatePrefix, "/") && !strings.HasPrefix(config.StateDir, nodeNetworkStatePrefix) {
		return fmt.Errorf("state_dir must be below %s", nodeNetworkStatePrefix)
	}
	return nil
}

func requireNodeNetworkStateDirectory(inspector NodeNetworkFileInspector, name string) error {
	return requireNodeNetworkTrustedDirectoryChain(inspector, name)
}

// requireNodeNetworkTrustedDirectoryChain refuses every untrusted component
// from / through directory.  InspectNodeNetworkFile is deliberately Lstat
// based, so a symlink is never accepted as an intermediate component.
func requireNodeNetworkTrustedDirectoryChain(inspector NodeNetworkFileInspector, directory string) error {
	clean := filepath.Clean(directory)
	if !filepath.IsAbs(clean) {
		return errors.New("directory chain must be absolute")
	}
	parts := strings.Split(strings.TrimPrefix(filepath.ToSlash(clean), "/"), "/")
	current := string(os.PathSeparator)
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		info, err := inspector.InspectNodeNetworkFile(current)
		if err != nil {
			return fmt.Errorf("inspect %s: %w", current, err)
		}
		if !info.Exists || !info.Directory || info.Symlink || info.Owner != "0" || info.Mode.Perm()&0022 != 0 {
			return fmt.Errorf("%s must be an existing root-owned non-symlink directory that is not group- or world-writable", current)
		}
	}
	return nil
}

func requireNodeNetworkSupported() error {
	if runtime.GOOS == "windows" {
		return ErrNodeNetworkUnsupported
	}
	return nil
}

// NodeNetworkConfigSummary deliberately contains no address, URI, path, or
// secret-bearing data and is therefore safe for plans and logs.
type NodeNetworkConfigSummary struct {
	SchemaVersion bool `json:"schema_version_present"`
	Configured    bool `json:"configured"`
	NoListener    bool `json:"no_listener"`
}

func (config NodeNetworkConfig) Summary() NodeNetworkConfigSummary {
	return nodeNetworkConfigSummary(config)
}

func nodeNetworkConfigSummary(config NodeNetworkConfig) NodeNetworkConfigSummary {
	return NodeNetworkConfigSummary{SchemaVersion: config.SchemaVersion == nodeNetworkSchemaVersion, Configured: true, NoListener: config.NoListener}
}

type NodeNetworkPlan = NodeNetworkConfigSummary

func (config NodeNetworkConfig) Plan() NodeNetworkPlan { return nodeNetworkConfigSummary(config) }
