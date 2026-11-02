package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestMapLocalNetworkSummaryRedactsAndPreservesUnknownInactiveDifference(t *testing.T) {
	unknown, _, unknownPeers, unknownError := MapLocalNetworkSummary(LocalNetworkSummary{
		ServiceState: "unknown",
		ReasonCode:   "peer.example.invalid:11010 password=not-safe",
	})
	if unknown.State != "unknown" || unknown.Detail != "not_collected" || unknownPeers.State != "unknown" || unknownError.Code != "none" {
		t.Fatalf("unknown status leaked or changed: %#v %#v %#v", unknown, unknownPeers, unknownError)
	}
	inactive, inactiveTun, inactivePeers, inactiveError := MapLocalNetworkSummary(LocalNetworkSummary{
		ServiceState: "inactive",
		InterfaceUp:  true,
		InterfaceIP:  "10.0.0.1",
		RXBytes:      1,
		TXBytes:      1,
	})
	if inactive.State != "stopped" || inactive.Detail != "inactive" || inactiveTun.Exists || inactivePeers.State != "disconnected" || inactiveError.Code != "none" {
		t.Fatalf("inactive status is not distinguished: %#v %#v %#v %#v", inactive, inactiveTun, inactivePeers, inactiveError)
	}
}

func TestMapLocalNetworkSummaryAllowsOnlyReasonCodesAndValidCounters(t *testing.T) {
	easy, tun, peers, statusError := MapLocalNetworkSummary(LocalNetworkSummary{
		ServiceState:   "error",
		ReasonCode:     "endpoint=198.51.100.10 secret=oops",
		InterfaceUp:    true,
		InterfaceIP:    "not-an-ip",
		RXBytes:        -1,
		TXBytes:        4,
		PeerState:      "connected",
		ConnectedPeers: 3,
		TotalPeers:     1,
	})
	if easy.State != "error" || easy.Detail != "service_error" {
		t.Fatalf("unexpected easytier summary: %#v", easy)
	}
	if tun.Exists || tun.IP != "" || peers.State != "error" {
		t.Fatalf("unexpected sanitized nested status: %#v %#v", tun, peers)
	}
	if statusError.Code != "unknown" || statusError.Detail != "unknown" {
		t.Fatalf("unexpected error mapping: %#v", statusError)
	}
}

func TestNodeNetworkStatusOutputCannotContainEnvironmentSecret(t *testing.T) {
	const secret = "status-must-not-expose-this-secret"
	var output bytes.Buffer
	if err := writeNodeNetworkStatus(&output, secret); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), secret) {
		t.Fatalf("status exposed EnvironmentFile secret: %s", output.String())
	}
}
