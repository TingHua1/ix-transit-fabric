package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const controlNFTTable = "ix_control_plane_v1"

type RuleSpec struct {
	ID          string `json:"id"`
	Protocol    string `json:"protocol"` // tcp, udp, both
	ListenPort  uint16 `json:"listen_port"`
	TargetIP    string `json:"target_ip"`
	TargetPort  uint16 `json:"target_port"`
	MatchDAddr  string `json:"match_daddr,omitempty"`
	Description string `json:"description,omitempty"`
	NoMeter     bool   `json:"no_meter,omitempty"`
}

type Ruleset struct {
	Role    string     `json:"role"` // ingress or transit
	NATETIP string     `json:"nat_et_ip,omitempty"`
	Rules   []RuleSpec `json:"rules"`
}

type CollectorState struct {
	Initialized bool              `json:"initialized"`
	Sequence    map[string]int64  `json:"sequence"`
	Last        map[string]uint64 `json:"last"`
}

var ruleIDRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}$`)

func protocols(p string) ([]string, error) {
	switch p {
	case "tcp", "udp":
		return []string{p}, nil
	case "both":
		return []string{"tcp", "udp"}, nil
	default:
		return nil, fmt.Errorf("protocol must be tcp, udp, or both")
	}
}

func validateRuleset(rs Ruleset) error {
	if rs.Role != "ingress" && rs.Role != "transit" {
		return errors.New("role must be ingress or transit")
	}
	if rs.Role == "transit" {
		if ip, err := netip.ParseAddr(rs.NATETIP); err != nil || !ip.Is4() {
			return errors.New("transit nat_et_ip must be an IPv4 address")
		}
	}
	seen := map[string]bool{}
	for _, r := range rs.Rules {
		if !ruleIDRE.MatchString(r.ID) {
			return fmt.Errorf("invalid rule id %q", r.ID)
		}
		if r.ListenPort == 0 || r.TargetPort == 0 {
			return fmt.Errorf("rule %s has invalid port", r.ID)
		}
		if ip, err := netip.ParseAddr(r.TargetIP); err != nil || !ip.Is4() {
			return fmt.Errorf("rule %s target_ip must be IPv4", r.ID)
		}
		if r.MatchDAddr != "" {
			if ip, err := netip.ParseAddr(r.MatchDAddr); err != nil || !ip.Is4() {
				return fmt.Errorf("rule %s match_daddr must be IPv4", r.ID)
			}
		}
		ps, err := protocols(r.Protocol)
		if err != nil {
			return fmt.Errorf("rule %s: %w", r.ID, err)
		}
		for _, p := range ps {
			k := p + ":" + strconv.Itoa(int(r.ListenPort))
			if seen[k] {
				return fmt.Errorf("duplicate listen selector %s", k)
			}
			seen[k] = true
		}
	}
	return nil
}

func nftRuleComment(id, proto, direction string) string {
	return "ixcp:" + id + ":" + proto + ":" + direction
}

func renderNFT(rs Ruleset) (string, error) {
	if err := validateRuleset(rs); err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "table ip %s {\n", controlNFTTable)
	b.WriteString("  chain cp_prerouting { type nat hook prerouting priority dstnat; policy accept;\n")
	for _, r := range rs.Rules {
		for _, p := range mustProtocols(r.Protocol) {
			if rs.Role == "transit" {
				fmt.Fprintf(&b, "    ip daddr %s %s dport %d dnat to %s:%d comment \"ixcp:%s:dnat\"\n", rs.NATETIP, p, r.ListenPort, r.TargetIP, r.TargetPort, r.ID)
			} else if r.MatchDAddr != "" {
				fmt.Fprintf(&b, "    ip daddr %s %s dport %d dnat to %s:%d comment \"ixcp:%s:dnat\"\n", r.MatchDAddr, p, r.ListenPort, r.TargetIP, r.TargetPort, r.ID)
			} else {
				fmt.Fprintf(&b, "    %s dport %d dnat to %s:%d comment \"ixcp:%s:dnat\"\n", p, r.ListenPort, r.TargetIP, r.TargetPort, r.ID)
			}
		}
	}
	b.WriteString("  }\n  chain cp_postrouting { type nat hook postrouting priority srcnat; policy accept;\n")
	for _, r := range rs.Rules {
		for _, p := range mustProtocols(r.Protocol) {
			fmt.Fprintf(&b, "    ip daddr %s %s dport %d masquerade comment \"ixcp:%s:snat\"\n", r.TargetIP, p, r.TargetPort, r.ID)
		}
	}
	b.WriteString("  }\n  chain cp_forward { type filter hook forward priority filter; policy accept;\n")
	for _, r := range rs.Rules {
		if r.NoMeter {
			continue
		}
		for _, p := range mustProtocols(r.Protocol) {
			fmt.Fprintf(&b, "    ct status dnat ct direction original ip daddr %s %s dport %d counter comment \"%s\"\n", r.TargetIP, p, r.TargetPort, nftRuleComment(r.ID, p, "up"))
			fmt.Fprintf(&b, "    ct status dnat ct direction reply ip saddr %s %s sport %d counter comment \"%s\"\n", r.TargetIP, p, r.TargetPort, nftRuleComment(r.ID, p, "down"))
		}
	}
	b.WriteString("  }\n}\n")
	return b.String(), nil
}
func mustProtocols(p string) []string { x, _ := protocols(p); return x }

// A conservative text check blocks same selectors already owned by the legacy table.
func legacyConflicts(nftText string, rs Ruleset) error {
	for _, r := range rs.Rules {
		for _, p := range mustProtocols(r.Protocol) {
			needle := p + " dport " + strconv.Itoa(int(r.ListenPort))
			if strings.Contains(nftText, needle) {
				return fmt.Errorf("legacy table may already own %s; refusing overlap", needle)
			}
		}
	}
	return nil
}

func nftCheckAndApply(script string) error {
	tmp, err := os.CreateTemp("", "ix-control-nft-*.nft")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.WriteString(script); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if out, err := exec.Command("nft", "-c", "-f", name).CombinedOutput(); err != nil {
		return fmt.Errorf("nft validation: %w: %s", err, strings.TrimSpace(string(out)))
	}
	// Only our dedicated table is removed. A failed delete simply means first use.
	_ = exec.Command("nft", "delete", "table", "ip", controlNFTTable).Run()
	if out, err := exec.Command("nft", "-f", name).CombinedOutput(); err != nil {
		return fmt.Errorf("nft apply: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func applyRulesetCommand(c Command) (bool, string) {
	if c.Type != "apply_ruleset" {
		return false, "unsupported command type"
	}
	var rs Ruleset
	if err := json.Unmarshal(c.Body, &rs); err != nil {
		return false, "invalid ruleset JSON: " + err.Error()
	}
	script, err := renderNFT(rs)
	if err != nil {
		return false, err.Error()
	}
	if out, err := exec.Command("nft", "list", "table", "ip", "ix_transit_fabric").CombinedOutput(); err == nil {
		if err := legacyConflicts(string(out), rs); err != nil {
			return false, err.Error()
		}
	}
	if err := nftCheckAndApply(script); err != nil {
		return false, err.Error()
	}
	return true, fmt.Sprintf("applied %d rules in %s", len(rs.Rules), controlNFTTable)
}

// nft JSON output carries counter bytes in rule expressions. Comments identify
// only this executor's counters; no existing table/counter is inspected.
func parseCounterJSON(raw []byte) (map[string]uint64, error) {
	var doc struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	out := map[string]uint64{}
	for _, entry := range doc.NFTables {
		v, ok := entry["rule"]
		if !ok {
			continue
		}
		var rule struct {
			Comment string            `json:"comment"`
			Expr    []json.RawMessage `json:"expr"`
		}
		if json.Unmarshal(v, &rule) != nil || !strings.HasPrefix(rule.Comment, "ixcp:") {
			continue
		}
		for _, e := range rule.Expr {
			var wrap struct {
				Counter *struct {
					Bytes uint64 `json:"bytes"`
				} `json:"counter"`
			}
			if json.Unmarshal(e, &wrap) == nil && wrap.Counter != nil {
				out[rule.Comment] += wrap.Counter.Bytes
			}
		}
	}
	return out, nil
}

func collectCounters(statePath, queuePath, nodeID string) error {
	out, err := exec.Command("nft", "-j", "list", "table", "ip", controlNFTTable).Output()
	if err != nil {
		return fmt.Errorf("read control nft table: %w", err)
	}
	current, err := parseCounterJSON(out)
	if err != nil {
		return err
	}
	state := CollectorState{Sequence: map[string]int64{}, Last: map[string]uint64{}}
	if b, err := os.ReadFile(statePath); err == nil {
		_ = json.Unmarshal(b, &state)
	}
	if state.Sequence == nil {
		state.Sequence = map[string]int64{}
	}
	if state.Last == nil {
		state.Last = map[string]uint64{}
	}
	// The first successful read only captures a baseline; it never bills old
	// packets that crossed before this collector owned the table.
	if !state.Initialized {
		for comment, n := range current {
			state.Last[comment] = n
		}
		state.Initialized = true
		if err := os.MkdirAll(filepath.Dir(statePath), 0700); err != nil {
			return err
		}
		b, _ := json.Marshal(state)
		return os.WriteFile(statePath, b, 0600)
	}
	type delta struct{ up, down uint64 }
	deltas := map[string]*delta{}
	for comment, n := range current {
		old := state.Last[comment]
		state.Last[comment] = n
		if n < old {
			old = 0
		} // table was rebuilt; current value is a new baseline delta.
		d := n - old
		parts := strings.Split(comment, ":")
		if len(parts) != 4 || d == 0 {
			continue
		}
		x := deltas[parts[1]]
		if x == nil {
			x = &delta{}
			deltas[parts[1]] = x
		}
		if parts[3] == "up" {
			x.up += d
		} else if parts[3] == "down" {
			x.down += d
		}
	}
	keys := make([]string, 0, len(deltas))
	for id := range deltas {
		keys = append(keys, id)
	}
	sort.Strings(keys)
	if len(keys) > 0 {
		if err := os.MkdirAll(filepath.Dir(queuePath), 0700); err != nil {
			return err
		}
		f, err := os.OpenFile(queuePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		enc := json.NewEncoder(f)
		for _, id := range keys {
			d := deltas[id]
			state.Sequence[id]++
			if err := enc.Encode(Usage{NodeID: nodeID, RuleID: id, Sequence: state.Sequence[id], UpBytes: int64(d.up), DownBytes: int64(d.down), At: time.Now().Unix()}); err != nil {
				f.Close()
				return err
			}
		}
		if err := f.Close(); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Dir(statePath), 0700); err != nil {
		return err
	}
	b, _ := json.Marshal(state)
	return os.WriteFile(statePath, b, 0600)
}

func runNFTTool(commandFile, collectState, queue, nodeID string) {
	if commandFile != "" {
		b, err := os.ReadFile(commandFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		var c Command
		if err := json.Unmarshal(b, &c); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		ok, detail := applyRulesetCommand(c)
		fmt.Println(detail)
		if !ok {
			os.Exit(1)
		}
		return
	}
	if collectState != "" {
		if err := collectCounters(collectState, queue, nodeID); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	fmt.Fprintln(os.Stderr, "nft tool needs --command-file or --collector-state")
	os.Exit(2)
}

func saveRuleset(path string, rs json.RawMessage) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp := path + ".new"
	if err := os.WriteFile(tmp, rs, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func restoreRuleset(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var rs Ruleset
	if err := json.Unmarshal(b, &rs); err != nil {
		return fmt.Errorf("invalid persisted ruleset: %w", err)
	}
	script, err := renderNFT(rs)
	if err != nil {
		return err
	}
	return nftCheckAndApply(script)
}

func runNFTHook(stateFile string) {
	var c Command
	if err := json.NewDecoder(os.Stdin).Decode(&c); err != nil {
		fmt.Fprintln(os.Stderr, "invalid command:", err)
		os.Exit(2)
	}
	ok, detail := applyRulesetCommand(c)
	if ok {
		if err := saveRuleset(stateFile, c.Body); err != nil {
			ok = false
			detail = "rules applied but state persistence failed: " + err.Error()
		}
	}
	fmt.Println(detail)
	if !ok {
		os.Exit(1)
	}
}

// Retained solely for test fixture scanners; production parser uses JSON.
func scanCounters(r *bufio.Scanner) map[string]uint64 { return map[string]uint64{} }
