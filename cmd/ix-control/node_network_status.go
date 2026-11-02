package main

import "net/netip"

// LocalNetworkSummary is intentionally a small, already-local observation.
// It has no peer endpoint, filesystem path, secret, or free-form diagnostic
// fields, so mapping it to StatusReport cannot accidentally disclose them.
type LocalNetworkSummary struct {
	ServiceState   string
	InterfaceUp    bool
	InterfaceIP    string
	RXBytes        int64
	TXBytes        int64
	PeerState      string
	ConnectedPeers int64
	TotalPeers     int64
	ReasonCode     string
}

var localNetworkReasonCodes = map[string]struct{}{
	"not_collected":     {},
	"inactive":          {},
	"stopped":           {},
	"service_error":     {},
	"interface_absent":  {},
	"peer_unavailable":  {},
	"local_state_error": {},
	"agent_error":       {},
	"unknown":           {},
}

// MapLocalNetworkSummary converts a local observation into the established
// closed status schema.  Unknown is distinct from inactive: unknown means no
// trustworthy observation; inactive maps to a stopped service with the fixed
// inactive reason code.  Unrecognised state and reason values never pass
// through to the output.
func MapLocalNetworkSummary(summary LocalNetworkSummary) (EasyTierStatus, TunStatus, PeerSummary, StatusErrorSummary) {
	reason := safeLocalNetworkReason(summary.ReasonCode)
	easy := EasyTierStatus{State: "unknown", Detail: "not_collected"}
	tun := TunStatus{}
	peers := PeerSummary{State: "unknown"}
	statusError := StatusErrorSummary{Code: "none"}

	switch summary.ServiceState {
	case "running":
		easy = EasyTierStatus{State: "running", Detail: reason}
		tun = sanitizedTunStatus(summary)
		peers = sanitizedPeerSummary(summary)
	case "stopped":
		easy = EasyTierStatus{State: "stopped", Detail: stoppedReason(reason)}
		peers = PeerSummary{State: "disconnected"}
	case "inactive":
		easy = EasyTierStatus{State: "stopped", Detail: "inactive"}
		peers = PeerSummary{State: "disconnected"}
	case "error":
		easy = EasyTierStatus{State: "error", Detail: errorReason(reason)}
		peers = PeerSummary{State: "error"}
		statusError = localNetworkStatusError(reason)
	case "unknown":
		// Keep the deliberately conservative defaults above.
	default:
		statusError = StatusErrorSummary{Code: "unknown", Detail: "unknown"}
	}
	return easy, tun, peers, statusError
}

// LocalNetworkSummaryToStatus is a concise alias for MapLocalNetworkSummary.
func LocalNetworkSummaryToStatus(summary LocalNetworkSummary) (EasyTierStatus, TunStatus, PeerSummary, StatusErrorSummary) {
	return MapLocalNetworkSummary(summary)
}

func safeLocalNetworkReason(reason string) string {
	if _, ok := localNetworkReasonCodes[reason]; ok {
		return reason
	}
	return "unknown"
}

func stoppedReason(reason string) string {
	if reason == "inactive" || reason == "stopped" {
		return reason
	}
	return "stopped"
}

func errorReason(reason string) string {
	if reason == "service_error" || reason == "local_state_error" || reason == "agent_error" {
		return reason
	}
	return "service_error"
}

func localNetworkStatusError(reason string) StatusErrorSummary {
	switch reason {
	case "local_state_error":
		return StatusErrorSummary{Code: "local_state_error", Detail: reason}
	case "agent_error", "service_error":
		return StatusErrorSummary{Code: "agent_error", Detail: errorReason(reason)}
	default:
		return StatusErrorSummary{Code: "unknown", Detail: "unknown"}
	}
}

func sanitizedTunStatus(summary LocalNetworkSummary) TunStatus {
	if !summary.InterfaceUp || summary.RXBytes < 0 || summary.TXBytes < 0 {
		return TunStatus{}
	}
	tun := TunStatus{Exists: true, RXBytes: summary.RXBytes, TXBytes: summary.TXBytes}
	if ip, err := netip.ParseAddr(summary.InterfaceIP); err == nil && ip.Is4() {
		tun.IP = ip.String()
	}
	return tun
}

func sanitizedPeerSummary(summary LocalNetworkSummary) PeerSummary {
	if !oneOf(summary.PeerState, "unknown", "connected", "disconnected", "error") ||
		summary.ConnectedPeers < 0 || summary.TotalPeers < 0 || summary.ConnectedPeers > summary.TotalPeers {
		return PeerSummary{State: "unknown"}
	}
	return PeerSummary{
		State:     summary.PeerState,
		Connected: summary.ConnectedPeers,
		Total:     summary.TotalPeers,
	}
}
