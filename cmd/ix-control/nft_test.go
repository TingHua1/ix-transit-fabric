package main

import (
	"strings"
	"testing"
)

func TestRenderNFTTransitCounters(t *testing.T) {
	rs := Ruleset{Role: "transit", NATETIP: "10.67.98.2", Rules: []RuleSpec{{ID: "r-video", Protocol: "both", ListenPort: 38175, TargetIP: "10.0.0.9", TargetPort: 443}}}
	s, err := renderNFT(rs)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"table ip ix_control_plane_v1", "ip daddr 10.67.98.2 tcp dport 38175 dnat to 10.0.0.9:443", "ip daddr 10.67.98.2 udp dport 38175 dnat to 10.0.0.9:443",
		`comment "ixcp:r-video:tcp:up"`, `comment "ixcp:r-video:tcp:down"`, `comment "ixcp:r-video:udp:up"`, `comment "ixcp:r-video:udp:down"`,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in:\n%s", want, s)
		}
	}
}
func TestRenderRejectsUnsafeOrDuplicateSelectors(t *testing.T) {
	for _, rs := range []Ruleset{
		{Role: "transit", NATETIP: "10.0.0.1", Rules: []RuleSpec{{ID: "bad id", Protocol: "tcp", ListenPort: 1, TargetIP: "1.1.1.1", TargetPort: 1}}},
		{Role: "ingress", Rules: []RuleSpec{{ID: "one", Protocol: "both", ListenPort: 443, TargetIP: "1.1.1.1", TargetPort: 443}, {ID: "two", Protocol: "tcp", ListenPort: 443, TargetIP: "2.2.2.2", TargetPort: 443}}},
	} {
		if _, err := renderNFT(rs); err == nil {
			t.Fatalf("expected invalid ruleset rejection: %#v", rs)
		}
	}
}
func TestLegacyConflict(t *testing.T) {
	rs := Ruleset{Role: "ingress", Rules: []RuleSpec{{ID: "one", Protocol: "tcp", ListenPort: 30000, TargetIP: "1.1.1.1", TargetPort: 443}}}
	if err := legacyConflicts("tcp dport 30000 dnat to 1.1.1.1:443", rs); err == nil {
		t.Fatal("expected overlap rejection")
	}
	if err := legacyConflicts("udp dport 30000 dnat to 1.1.1.1:443", rs); err != nil {
		t.Fatal(err)
	}
}
func TestParseCounterJSON(t *testing.T) {
	in := []byte(`{"nftables":[{"rule":{"comment":"ixcp:r1:tcp:up","expr":[{"counter":{"packets":2,"bytes":123}}]}},{"rule":{"comment":"other","expr":[{"counter":{"bytes":999}}]}}]}`)
	got, err := parseCounterJSON(in)
	if err != nil {
		t.Fatal(err)
	}
	if got["ixcp:r1:tcp:up"] != 123 {
		t.Fatalf("got %#v", got)
	}
	if len(got) != 1 {
		t.Fatalf("unexpected counters %#v", got)
	}
}
