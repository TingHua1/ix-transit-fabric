package main

import (
	"embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	// SystemdStateDir is deliberately fixed: all generated units keep mutable
	// ix-control state in one private, reviewable location.
	SystemdStateDir = "/var/lib/ix-control"
	// RequiredTokenFileMode is the mode an integrator must establish before
	// rendering an agent unit. Rendering never reads the token file.
	RequiredTokenFileMode fs.FileMode = 0600
)

// SystemdRole selects the unit set for a node or for the controller host.
type SystemdRole string

const (
	SystemdNode       SystemdRole = "node"
	SystemdController SystemdRole = "controller"
)

const (
	restoreUnit        = "ix-control-restore.service"
	agentUnit          = "ix-control-agent.service"
	collectorUnit      = "ix-control-collector.service"
	collectorTimerUnit = "ix-control-collector.timer"
	serverUnit         = "ix-control-server.service"
	reconcileUnit      = "ix-control-reconcile.service"
	reconcileTimerUnit = "ix-control-reconcile.timer"
	templatesDirectory = "systemd_templates"
)

var (
	placeholderRE = regexp.MustCompile(`@[A-Z_]+@`)
	nodeIDRE      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$`)
)

// SystemdRenderInput contains declarative values for local unit text. Values
// are validated and interpolated only into complete systemd arguments; this
// package neither writes units nor starts services.
type SystemdRenderInput struct {
	BinaryPath    string
	NodeID        string
	ServerURL     string
	TokenFile     string
	TokenFileMode fs.FileMode
	StateDir      string
	DatabaseDSN   string
}

//go:embed systemd_templates/*
var systemdTemplateFS embed.FS

var roleTemplates = map[SystemdRole][]string{
	SystemdNode:       {restoreUnit, agentUnit, collectorUnit, collectorTimerUnit},
	SystemdController: {serverUnit, reconcileUnit, reconcileTimerUnit},
}

// SystemdTemplateNames returns a sorted copy of the unit names rendered for a
// role. The names also are the intended local filenames.
func SystemdTemplateNames(role SystemdRole) ([]string, error) {
	names, ok := roleTemplates[role]
	if !ok {
		return nil, fmt.Errorf("unknown systemd role %q", role)
	}
	out := append([]string(nil), names...)
	sort.Strings(out)
	return out, nil
}

// RenderSystemdTemplate renders one embedded unit file. It is intentionally a
// pure operation: callers decide whether and where to write the returned text.
func RenderSystemdTemplate(name string, in SystemdRenderInput) (string, error) {
	if !knownTemplate(name) {
		return "", fmt.Errorf("unknown systemd template %q", name)
	}
	if err := validateSystemdInput(name, in); err != nil {
		return "", err
	}
	b, err := systemdTemplateFS.ReadFile(templatesDirectory + "/" + name)
	if err != nil {
		return "", err
	}
	return substituteSystemdPlaceholders(string(b), systemdValues(in))
}

// RenderSystemdTemplates renders every unit for a role. It only returns text;
// it never invokes systemctl, makes a network connection, or touches the host.
func RenderSystemdTemplates(role SystemdRole, in SystemdRenderInput) (map[string]string, error) {
	names, err := SystemdTemplateNames(role)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(names))
	for _, name := range names {
		rendered, err := RenderSystemdTemplate(name, in)
		if err != nil {
			return nil, err
		}
		out[name] = rendered
	}
	return out, nil
}

func knownTemplate(name string) bool {
	for _, names := range roleTemplates {
		for _, known := range names {
			if name == known {
				return true
			}
		}
	}
	return false
}

func systemdValues(in SystemdRenderInput) map[string]string {
	return map[string]string{
		"@IX_CONTROL_BIN@": in.BinaryPath,
		"@NODE_ID@":        in.NodeID,
		"@SERVER_URL@":     in.ServerURL,
		"@TOKEN_FILE@":     in.TokenFile,
		"@STATE_DIR@":      in.StateDir,
		"@DB_DSN@":         in.DatabaseDSN,
	}
}

func substituteSystemdPlaceholders(source string, values map[string]string) (string, error) {
	unknown := placeholderRE.FindAllString(source, -1)
	for _, key := range unknown {
		if _, ok := values[key]; !ok {
			return "", fmt.Errorf("unrecognized placeholder %s", key)
		}
	}
	for key, value := range values {
		source = strings.ReplaceAll(source, key, value)
	}
	if unresolved := placeholderRE.FindString(source); unresolved != "" {
		return "", fmt.Errorf("unresolved placeholder %s", unresolved)
	}
	if err := validateRenderedUnit(source); err != nil {
		return "", err
	}
	return source, nil
}

func validateSystemdInput(name string, in SystemdRenderInput) error {
	if err := validateSystemdPath("binary path", in.BinaryPath); err != nil {
		return err
	}
	if in.StateDir != SystemdStateDir {
		return fmt.Errorf("state directory must be %s", SystemdStateDir)
	}
	if usesNodeValues(name) {
		if !nodeIDRE.MatchString(in.NodeID) {
			return errors.New("invalid node id")
		}
		if err := validateSystemdURL(in.ServerURL); err != nil {
			return err
		}
		if err := validateSystemdPath("token file", in.TokenFile); err != nil {
			return err
		}
		if !strings.HasPrefix(in.TokenFile, "/etc/ix-control/") {
			return errors.New("token file must be below /etc/ix-control")
		}
		if in.TokenFileMode.Perm() != RequiredTokenFileMode {
			return fmt.Errorf("token file mode must be %04o", RequiredTokenFileMode)
		}
	}
	if usesDatabase(name) {
		if err := validateDatabaseDSN(in.DatabaseDSN); err != nil {
			return err
		}
	}
	return nil
}

func usesNodeValues(name string) bool {
	return name == agentUnit || name == collectorUnit || name == restoreUnit || name == collectorTimerUnit
}

func usesDatabase(name string) bool {
	return name == serverUnit || name == reconcileUnit || name == reconcileTimerUnit
}

func validateSystemdPath(label, value string) error {
	if value == "" || !strings.HasPrefix(value, "/") || path.Clean(value) != value {
		return fmt.Errorf("%s must be a clean absolute path", label)
	}
	if strings.ContainsAny(value, " \t\r\n@'\"\\") {
		return fmt.Errorf("%s contains unsafe characters", label)
	}
	return nil
}

func validateSystemdURL(value string) error {
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "wss" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("server URL must be a credential-free wss URL without query or fragment")
	}
	if strings.ContainsAny(value, " \t\r\n@'\"") {
		return errors.New("server URL contains unsafe characters")
	}
	return nil
}

func validateDatabaseDSN(value string) error {
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "file" || !strings.HasPrefix(u.Path, SystemdStateDir+"/") {
		return fmt.Errorf("database DSN must be a file URL below %s", SystemdStateDir)
	}
	q := u.Query()
	if q.Get("_journal_mode") != "WAL" {
		return errors.New("database DSN must set _journal_mode=WAL")
	}
	busy, err := strconv.Atoi(q.Get("_busy_timeout"))
	if err != nil || busy <= 0 {
		return errors.New("database DSN must set a positive _busy_timeout")
	}
	if strings.ContainsAny(value, " \t\r\n@'\"\\") {
		return errors.New("database DSN contains unsafe characters")
	}
	return nil
}

func validateRenderedUnit(unit string) error {
	for _, forbidden := range []string{"--apply-hook", "sh -c", "eval", "--token ", "--token="} {
		if strings.Contains(unit, forbidden) {
			return fmt.Errorf("rendered unit contains forbidden fragment %q", forbidden)
		}
	}
	return nil
}

// ParseSystemdTokenFileMode accepts only the explicitly required 0600 mode.
// The rendering command does not inspect the token file itself.
func ParseSystemdTokenFileMode(value string) (fs.FileMode, error) {
	if value != "0600" {
		return 0, fmt.Errorf("systemd token file mode must be %04o", RequiredTokenFileMode)
	}
	mode, err := strconv.ParseUint(value, 8, 32)
	if err != nil || mode != uint64(RequiredTokenFileMode) {
		return 0, fmt.Errorf("systemd token file mode must be %04o", RequiredTokenFileMode)
	}
	return fs.FileMode(mode), nil
}

// GenerateSystemdTemplates renders units to stdout for local review. A nonempty
// outputDir is rejected: this command never creates unit files. It never invokes
// systemctl or contacts a server.
func GenerateSystemdTemplates(role SystemdRole, in SystemdRenderInput, outputDir string, stdout io.Writer) error {
	if outputDir != "" {
		return errors.New("systemd output directories are not supported; templates are stdout-only")
	}
	units, err := RenderSystemdTemplates(role, in)
	if err != nil {
		return err
	}
	names, err := SystemdTemplateNames(role)
	if err != nil {
		return err
	}
	for i, name := range names {
		if _, err := fmt.Fprintf(stdout, "### %s\n%s", name, units[name]); err != nil {
			return err
		}
		if i < len(names)-1 {
			if _, err := fmt.Fprintln(stdout); err != nil {
				return err
			}
		}
	}
	return nil
}
