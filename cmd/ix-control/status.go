package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"
)

// StatusReport is deliberately a closed, small wire schema. In particular it
// has no node_id: the authenticated WebSocket hello establishes that identity.
// ReportedAt is agent-provided diagnostic time only; ReceivedAt is assigned by
// the controller and remains the authoritative freshness timestamp.
type StatusReport struct {
	AgentVersion          string             `json:"agent_version"`
	BootID                string             `json:"boot_id"`
	Generation            int64              `json:"generation"`
	Sequence              int64              `json:"sequence"`
	ReportedAt            int64              `json:"reported_at"`
	AppliedRulesetVersion int64              `json:"applied_ruleset_version"`
	AppliedRulesetHash    string             `json:"applied_ruleset_hash"`
	ControlTable          string             `json:"control_table"`
	CollectorLastSuccess  int64              `json:"collector_last_success"`
	EasyTier              EasyTierStatus     `json:"easytier"`
	Tun0                  TunStatus          `json:"tun0"`
	Peers                 PeerSummary        `json:"peers"`
	Error                 StatusErrorSummary `json:"error"`
}

type EasyTierStatus struct {
	State  string `json:"state"`
	Detail string `json:"detail"`
}

type TunStatus struct {
	Exists  bool   `json:"exists"`
	IP      string `json:"ip"`
	RXBytes int64  `json:"rx_bytes"`
	TXBytes int64  `json:"tx_bytes"`
}

type PeerSummary struct {
	State     string `json:"state"`
	Connected int64  `json:"connected"`
	Total     int64  `json:"total"`
}

type StatusErrorSummary struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

// NodeStatus is the controller's persisted view. ReceivedAt, unlike all other
// freshness information, is authoritative because it is set on receipt.
type NodeStatus struct {
	NodeID     string
	ReceivedAt int64
	StatusReport
}

var (
	bootIDRE = regexp.MustCompile(`^[a-f0-9]{32}$`)
	hashRE   = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

const maxStatusReportedAtFutureSkew = 5 * time.Minute

func decodeStatusReport(raw json.RawMessage) (StatusReport, error) {
	return decodeStatusReportWithMinimumGeneration(raw, 1)
}

// decodeStoredStatusReport accepts generation zero only for rows that the
// generation migration marked as historical. Wire reports must always use
// decodeStatusReport, which requires generation one or greater.
func decodeStoredStatusReport(raw json.RawMessage, persistedGeneration int64) (StatusReport, error) {
	if persistedGeneration < 0 {
		return StatusReport{}, errors.New("stored status has invalid generation")
	}
	minimumGeneration := int64(1)
	if persistedGeneration == 0 {
		minimumGeneration = 0
	}
	report, err := decodeStatusReportWithMinimumGeneration(raw, minimumGeneration)
	if err != nil {
		return StatusReport{}, err
	}
	if report.Generation != persistedGeneration {
		return StatusReport{}, errors.New("stored status generation does not match row")
	}
	return report, nil
}

func decodeStatusReportWithMinimumGeneration(raw json.RawMessage, minimumGeneration int64) (StatusReport, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return StatusReport{}, err
	}
	if err := requireStatusFields(fields, "agent_version", "boot_id", "generation", "sequence", "reported_at", "applied_ruleset_version", "applied_ruleset_hash", "control_table", "collector_last_success", "easytier", "tun0", "peers", "error"); err != nil {
		return StatusReport{}, err
	}
	for name, required := range map[string][]string{
		"easytier": {"state", "detail"},
		"tun0":     {"exists", "ip", "rx_bytes", "tx_bytes"},
		"peers":    {"state", "connected", "total"},
		"error":    {"code", "detail"},
	} {
		var nested map[string]json.RawMessage
		if err := json.Unmarshal(fields[name], &nested); err != nil {
			return StatusReport{}, fmt.Errorf("%s must be an object", name)
		}
		if err := requireStatusFields(nested, required...); err != nil {
			return StatusReport{}, fmt.Errorf("%s: %w", name, err)
		}
	}
	var report StatusReport
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&report); err != nil {
		return StatusReport{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return StatusReport{}, errors.New("status payload has trailing data")
	}
	if err := validateStatusReportWithMinimumGeneration(report, minimumGeneration); err != nil {
		return StatusReport{}, err
	}
	return report, nil
}

func requireStatusFields(fields map[string]json.RawMessage, required ...string) error {
	if len(fields) != len(required) {
		return errors.New("unexpected or missing fields")
	}
	for _, name := range required {
		if _, ok := fields[name]; !ok {
			return fmt.Errorf("missing %s", name)
		}
	}
	return nil
}

func validateStatusReport(r StatusReport) error {
	return validateStatusReportWithMinimumGeneration(r, 1)
}

func validateStatusReportWithMinimumGeneration(r StatusReport, minimumGeneration int64) error {
	if r.AgentVersion == "" || !validText(r.AgentVersion, 100) || !bootIDRE.MatchString(r.BootID) || r.Generation < minimumGeneration || r.Sequence < 1 {
		return errors.New("invalid agent version, boot id, generation, or sequence")
	}
	if r.ReportedAt < 0 || r.ReportedAt > time.Now().Add(maxStatusReportedAtFutureSkew).Unix() {
		return errors.New("invalid reported_at")
	}
	if (r.AppliedRulesetVersion == 0 && r.AppliedRulesetHash != "") ||
		(r.AppliedRulesetVersion > 0 && !hashRE.MatchString(r.AppliedRulesetHash)) || r.AppliedRulesetVersion < 0 {
		return errors.New("ruleset version and hash must be paired")
	}
	if !oneOf(r.ControlTable, "unknown", "present", "absent") || r.CollectorLastSuccess < 0 {
		return errors.New("invalid control table or collector status")
	}
	if !oneOf(r.EasyTier.State, "unknown", "running", "stopped", "error") || !validText(r.EasyTier.Detail, 160) {
		return errors.New("invalid EasyTier summary")
	}
	if r.Tun0.RXBytes < 0 || r.Tun0.TXBytes < 0 || !validText(r.Tun0.IP, 15) {
		return errors.New("invalid tun0 counters")
	}
	if r.Tun0.IP != "" {
		ip, err := netip.ParseAddr(r.Tun0.IP)
		if err != nil || !ip.Is4() || !r.Tun0.Exists {
			return errors.New("tun0 ip must be an IPv4 address on an existing interface")
		}
	}
	if !r.Tun0.Exists && (r.Tun0.IP != "" || r.Tun0.RXBytes != 0 || r.Tun0.TXBytes != 0) {
		return errors.New("absent tun0 cannot have address or counters")
	}
	if !oneOf(r.Peers.State, "unknown", "connected", "disconnected", "error") || r.Peers.Connected < 0 || r.Peers.Total < 0 || r.Peers.Connected > r.Peers.Total {
		return errors.New("invalid peer summary")
	}
	if !oneOf(r.Error.Code, "none", "unknown", "local_state_error", "agent_error") || !validText(r.Error.Detail, 160) || (r.Error.Code == "none" && r.Error.Detail != "") {
		return errors.New("invalid error summary")
	}
	return nil
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func validText(value string, max int) bool {
	if len(value) > max {
		return false
	}
	return strings.IndexFunc(value, unicode.IsControl) < 0
}

// recordStatus performs one conditional UPSERT. Generation is locally persisted
// and incremented at every agent lifecycle start, so it orders distinct boots
// without relying on a node wall clock. Generation always takes precedence;
// within the same generation, only a strictly newer sequence from the same
// boot wins.
func (s *Server) recordStatus(nodeID string, report StatusReport) (bool, error) {
	if err := validateStatusReport(report); err != nil {
		return false, err
	}
	b, err := json.Marshal(report)
	if err != nil {
		return false, err
	}
	result, err := s.db.Exec(`INSERT INTO node_status(node_id,boot_id,generation,sequence,received_at,report) VALUES(?,?,?,?,?,?)
ON CONFLICT(node_id) DO UPDATE SET boot_id=excluded.boot_id,generation=excluded.generation,sequence=excluded.sequence,received_at=excluded.received_at,report=excluded.report
 WHERE excluded.generation>node_status.generation
   OR (excluded.generation=node_status.generation AND node_status.boot_id=excluded.boot_id AND excluded.sequence>node_status.sequence)`, nodeID, report.BootID, report.Generation, report.Sequence, time.Now().Unix(), string(b))
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	return n == 1, err
}

// GetNodeStatus is a read helper for future CLI commands. It returns
// sql.ErrNoRows when the authenticated node has never reported status.
func (s *Server) GetNodeStatus(nodeID string) (NodeStatus, error) {
	var result NodeStatus
	var report string
	var persistedGeneration int64
	err := s.db.QueryRow(`SELECT node_id,generation,received_at,report FROM node_status WHERE node_id=?`, nodeID).Scan(&result.NodeID, &persistedGeneration, &result.ReceivedAt, &report)
	if err != nil {
		return NodeStatus{}, err
	}
	decoded, err := decodeStoredStatusReport(json.RawMessage(report), persistedGeneration)
	if err != nil {
		return NodeStatus{}, fmt.Errorf("stored status: %w", err)
	}
	result.StatusReport = decoded
	return result, nil
}

// NodeStatusOnline uses controller receipt time, never an agent clock.
func NodeStatusOnline(status NodeStatus, now time.Time, timeout time.Duration) bool {
	if status.ReceivedAt <= 0 || timeout < 0 {
		return false
	}
	return now.Unix()-status.ReceivedAt <= int64(timeout/time.Second)
}

type agentStatusReporter struct {
	rulesetState string
	// nodeNetworkConfig is optional. It is only locally checked; reporting never
	// opens the referenced secret, contacts a peer, or runs a host command.
	nodeNetworkConfig string
	bootID            string
	generation        int64
	sequence          int64
}

type persistedStatusGeneration struct {
	Generation int64 `json:"generation"`
}

// statusGenerationPath deliberately lives beside the authorized ruleset state.
// It contains only a monotonically increasing incarnation number, never a token.
func statusGenerationPath(rulesetState string) (string, error) {
	if rulesetState == "" {
		return "", errors.New("ruleset state path is required for status generation")
	}
	return rulesetState + ".status-generation", nil
}

func newAgentStatusReporter(rulesetState string, nodeNetworkConfigs ...string) (*agentStatusReporter, error) {
	statePath, err := statusGenerationPath(rulesetState)
	if err != nil {
		return nil, err
	}
	generation, err := incrementStatusGeneration(statePath)
	if err != nil {
		return nil, err
	}
	boot := make([]byte, 16)
	if _, err := rand.Read(boot); err != nil {
		return nil, fmt.Errorf("generate status boot id: %w", err)
	}
	var nodeNetworkConfig string
	if len(nodeNetworkConfigs) > 0 {
		nodeNetworkConfig = nodeNetworkConfigs[0]
	}
	return &agentStatusReporter{rulesetState: rulesetState, nodeNetworkConfig: nodeNetworkConfig, bootID: hex.EncodeToString(boot), generation: generation}, nil
}

// incrementStatusGeneration serializes read/increment/write with an exclusive
// local lock, then atomically replaces the state file. Failure is returned to
// the caller so an agent never claims a fabricated incarnation.
func incrementStatusGeneration(statePath string) (int64, error) {
	if err := os.MkdirAll(filepath.Dir(statePath), 0700); err != nil {
		return 0, fmt.Errorf("create status generation directory: %w", err)
	}
	unlock, err := lockStatusGeneration(statePath + ".guard")
	if err != nil {
		return 0, fmt.Errorf("lock status generation: %w", err)
	}
	defer unlock()

	state := persistedStatusGeneration{}
	b, err := os.ReadFile(statePath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return 0, fmt.Errorf("read status generation: %w", err)
	}
	if err == nil {
		if err := json.Unmarshal(b, &state); err != nil || state.Generation < 1 {
			return 0, errors.New("invalid persisted status generation")
		}
	}
	if state.Generation == int64(^uint64(0)>>1) {
		return 0, errors.New("status generation exhausted")
	}
	state.Generation++
	b, err = json.Marshal(state)
	if err != nil {
		return 0, err
	}
	if err := atomicWriteStatusGeneration(statePath, b); err != nil {
		return 0, err
	}
	return state.Generation, nil
}

func atomicWriteStatusGeneration(statePath string, content []byte) error {
	dir := filepath.Dir(statePath)
	tmp, err := os.CreateTemp(dir, ".status-generation-")
	if err != nil {
		return fmt.Errorf("create status generation file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, statePath); err != nil {
		return fmt.Errorf("atomically save status generation: %w", err)
	}
	return nil
}

// next only reads the persisted ruleset file. It intentionally does not invoke
// service, interface, routing, firewall, or EasyTier commands.
func (r *agentStatusReporter) next() StatusReport {
	r.sequence++
	report := StatusReport{
		AgentVersion: "ix-control/1",
		BootID:       r.bootID,
		Generation:   r.generation,
		Sequence:     r.sequence,
		ReportedAt:   time.Now().Unix(),
		ControlTable: "unknown",
		EasyTier:     EasyTierStatus{State: "unknown", Detail: "not collected"},
		Peers:        PeerSummary{State: "unknown"},
		Error:        StatusErrorSummary{Code: "none"},
	}
	if r.nodeNetworkConfig != "" {
		// The result remains deliberately unobserved: the status reporter is not
		// a service probe. A rejected local declaration is mapped to the existing
		// de-identified local_state_error vocabulary; neither its path nor the
		// parse/permission failure can enter the wire report.
		if _, err := loadLocalNodeNetworkConfig(r.nodeNetworkConfig); err != nil {
			easy, tun, peers, statusErr := MapLocalNetworkSummary(LocalNetworkSummary{
				ServiceState: "error", ReasonCode: "local_state_error",
			})
			report.EasyTier, report.Tun0, report.Peers, report.Error = easy, tun, peers, statusErr
		}
	}
	if r.rulesetState == "" {
		return report
	}
	state, err := loadRulesetState(r.rulesetState)
	if err != nil || state.Version < 1 || !hashRE.MatchString(state.Hash) {
		report.Error = StatusErrorSummary{Code: "local_state_error", Detail: "ruleset state unavailable"}
		return report
	}
	report.AppliedRulesetVersion = state.Version
	report.AppliedRulesetHash = state.Hash
	return report
}
