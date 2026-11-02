package main

import (
	"bytes"
	"strings"
	"testing"
)

func validNodeSystemdInput() SystemdRenderInput {
	return SystemdRenderInput{
		BinaryPath:    "/usr/local/bin/ix-control",
		NodeID:        "node-01",
		ServerURL:     "wss://control.invalid/v1/ws",
		TokenFile:     "/etc/ix-control/node-01.token",
		TokenFileMode: RequiredTokenFileMode,
		StateDir:      SystemdStateDir,
		DatabaseDSN:   "file:/var/lib/ix-control/ix-control.db?_busy_timeout=5000&_journal_mode=WAL",
	}
}

func TestRenderSystemdNodeTemplates(t *testing.T) {
	units, err := RenderSystemdTemplates(SystemdNode, validNodeSystemdInput())
	if err != nil {
		t.Fatal(err)
	}
	if len(units) != 4 {
		t.Fatalf("got units %#v", units)
	}
	restore := units[restoreUnit]
	for _, want := range []string{
		"Before=ix-control-agent.service",
		"--mode restore --ruleset-state /var/lib/ix-control/ruleset.json",
		"StateDirectory=ix-control",
		"StateDirectoryMode=0700",
		"UMask=0077",
		"NoNewPrivileges=true",
		"ProtectSystem=strict",
	} {
		if !strings.Contains(restore, want) {
			t.Errorf("restore unit missing %q:\n%s", want, restore)
		}
	}
	agent := units[agentUnit]
	for _, want := range []string{
		"Requires=ix-control-restore.service",
		"After=network-online.target ix-control-restore.service",
		"--server wss://control.invalid/v1/ws",
		"--node-id node-01",
		"--token-file /etc/ix-control/node-01.token",
		"--usage-file /var/lib/ix-control/usage.ndjson",
		"ReadWritePaths=/var/lib/ix-control",
	} {
		if !strings.Contains(agent, want) {
			t.Errorf("agent unit missing %q:\n%s", want, agent)
		}
	}
	collector := units[collectorUnit]
	for _, want := range []string{
		"--mode nft --collector-state /var/lib/ix-control/collector-state.json",
		"--usage-file /var/lib/ix-control/usage.ndjson",
		"--node-id node-01",
	} {
		if !strings.Contains(collector, want) {
			t.Errorf("collector unit missing %q:\n%s", want, collector)
		}
	}
	timer := units[collectorTimerUnit]
	for _, want := range []string{"OnUnitActiveSec=1min", "Persistent=true", "Unit=ix-control-collector.service"} {
		if !strings.Contains(timer, want) {
			t.Errorf("collector timer missing %q:\n%s", want, timer)
		}
	}
	assertSafeRenderedUnits(t, units)
}

func TestRenderSystemdControllerTemplates(t *testing.T) {
	units, err := RenderSystemdTemplates(SystemdController, validNodeSystemdInput())
	if err != nil {
		t.Fatal(err)
	}
	if len(units) != 3 {
		t.Fatalf("got units %#v", units)
	}
	server := units[serverUnit]
	for _, want := range []string{
		"--mode server --listen 127.0.0.1:8787",
		"--db file:/var/lib/ix-control/ix-control.db?_busy_timeout=5000&_journal_mode=WAL",
		"StateDirectory=ix-control",
		"StateDirectoryMode=0700",
		"UMask=0077",
		"NoNewPrivileges=true",
		"ProtectSystem=strict",
	} {
		if !strings.Contains(server, want) {
			t.Errorf("server unit missing %q:\n%s", want, server)
		}
	}
	reconcile := units[reconcileUnit]
	if !strings.Contains(reconcile, "--mode reconcile --db file:/var/lib/ix-control/ix-control.db?_busy_timeout=5000&_journal_mode=WAL") {
		t.Errorf("reconcile unit has unexpected content:\n%s", reconcile)
	}
	timer := units[reconcileTimerUnit]
	for _, want := range []string{"OnUnitActiveSec=1min", "Persistent=true", "Unit=ix-control-reconcile.service"} {
		if !strings.Contains(timer, want) {
			t.Errorf("reconcile timer missing %q:\n%s", want, timer)
		}
	}
	assertSafeRenderedUnits(t, units)
}

func assertSafeRenderedUnits(t *testing.T, units map[string]string) {
	t.Helper()
	for name, unit := range units {
		if strings.Contains(unit, "@") {
			t.Errorf("%s retains placeholder: %s", name, unit)
		}
		for _, forbidden := range []string{"--apply-hook", "sh -c", "eval", "--token ", "--token="} {
			if strings.Contains(unit, forbidden) {
				t.Errorf("%s contains forbidden %q", name, forbidden)
			}
		}
	}
}

func TestRenderSystemdRejectsUnsafeInput(t *testing.T) {
	cases := []struct {
		name string
		unit string
		edit func(*SystemdRenderInput)
	}{
		{"unknown unit", "unknown.service", func(*SystemdRenderInput) {}},
		{"bad binary", serverUnit, func(in *SystemdRenderInput) { in.BinaryPath = "relative/ix-control" }},
		{"bad state", serverUnit, func(in *SystemdRenderInput) { in.StateDir = "/tmp/ix-control" }},
		{"bad db path", serverUnit, func(in *SystemdRenderInput) {
			in.DatabaseDSN = "file:/tmp/control.db?_busy_timeout=5000&_journal_mode=WAL"
		}},
		{"db lacks WAL", serverUnit, func(in *SystemdRenderInput) {
			in.DatabaseDSN = "file:/var/lib/ix-control/control.db?_busy_timeout=5000"
		}},
		{"db lacks timeout", serverUnit, func(in *SystemdRenderInput) { in.DatabaseDSN = "file:/var/lib/ix-control/control.db?_journal_mode=WAL" }},
		{"bad node", agentUnit, func(in *SystemdRenderInput) { in.NodeID = "node name" }},
		{"not wss", agentUnit, func(in *SystemdRenderInput) { in.ServerURL = "https://control.invalid/v1/ws" }},
		{"url query", agentUnit, func(in *SystemdRenderInput) { in.ServerURL = "wss://control.invalid/v1/ws?token=x" }},
		{"bad token path", agentUnit, func(in *SystemdRenderInput) { in.TokenFile = "/tmp/token" }},
		{"bad token mode", agentUnit, func(in *SystemdRenderInput) { in.TokenFileMode = 0644 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := validNodeSystemdInput()
			tc.edit(&in)
			if _, err := RenderSystemdTemplate(tc.unit, in); err == nil {
				t.Fatal("expected input validation error")
			}
		})
	}
}

func TestSystemdPlaceholderValidation(t *testing.T) {
	values := systemdValues(validNodeSystemdInput())
	if _, err := substituteSystemdPlaceholders("ExecStart=@UNRECOGNIZED@", values); err == nil {
		t.Fatal("expected unrecognized placeholder error")
	}
	if _, err := substituteSystemdPlaceholders("ExecStart=@IX_CONTROL_BIN@ --apply-hook x", values); err == nil {
		t.Fatal("expected forbidden rendered content error")
	}
}

func TestGenerateSystemdTemplatesStdoutIsStable(t *testing.T) {
	var output bytes.Buffer
	if err := GenerateSystemdTemplates(SystemdNode, validNodeSystemdInput(), "", &output); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	wantOrder := []string{
		"### ix-control-agent.service\n",
		"### ix-control-collector.service\n",
		"### ix-control-collector.timer\n",
		"### ix-control-restore.service\n",
	}
	last := -1
	for _, marker := range wantOrder {
		index := strings.Index(got, marker)
		if index < 0 {
			t.Errorf("stdout missing filename marker %q:\n%s", marker, got)
		}
		if index <= last {
			t.Errorf("stdout template order is unstable around %q:\n%s", marker, got)
		}
		last = index
	}
}

func TestGenerateSystemdTemplatesRejectsExplicitOutputDirectory(t *testing.T) {
	if err := GenerateSystemdTemplates(SystemdController, validNodeSystemdInput(), "./local-unit-review", &bytes.Buffer{}); err == nil {
		t.Fatal("explicit output directory unexpectedly accepted")
	}
}

func TestParseSystemdTokenFileMode(t *testing.T) {
	if mode, err := ParseSystemdTokenFileMode("0600"); err != nil || mode != RequiredTokenFileMode {
		t.Fatalf("valid mode = %#o, %v", mode, err)
	}
	for _, value := range []string{"600", "0644", "invalid"} {
		if _, err := ParseSystemdTokenFileMode(value); err == nil {
			t.Errorf("expected %q rejection", value)
		}
	}
}
