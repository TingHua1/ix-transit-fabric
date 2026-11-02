package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync/atomic"
	"time"
)

// commandSequence distinguishes commands created during the same clock tick.
// It is process-wide because command IDs share one SQLite commands table.
var commandSequence uint64

type AdminRequest struct {
	Action string          `json:"action"`
	Body   json.RawMessage `json:"body"`
}
type UserSpec struct {
	ID          string `json:"id"`
	ExpiresAt   int64  `json:"expires_at,omitempty"`   // unix seconds; 0 means no expiry
	QuotaBytes  int64  `json:"quota_bytes,omitempty"`  // 0 means unlimited
	BillingMode string `json:"billing_mode,omitempty"` // both, up, down
	Enabled     bool   `json:"enabled"`
}
type ManagedRule struct {
	RuleSpec
	NodeID  string `json:"node_id"`
	UserID  string `json:"user_id"`
	Enabled bool   `json:"enabled"`
}
type NodeConfig struct {
	NodeID  string `json:"node_id"`
	Role    string `json:"role"`
	NATETIP string `json:"nat_et_ip,omitempty"`
}

// LinkSpec describes one client-facing forwarding path.  Its ingress rule is
// the sole metered rule; the transit rule exists only to complete the path.
type LinkSpec struct {
	ID              string `json:"id"`
	UserID          string `json:"user_id"`
	Enabled         bool   `json:"enabled"`
	Protocol        string `json:"protocol"`
	ClientPort      uint16 `json:"client_port"`
	IngressNodeID   string `json:"ingress_node_id"`
	IngressPublicIP string `json:"ingress_public_ip,omitempty"`
	TransitNodeID   string `json:"transit_node_id"`
	TransitEasyIP   string `json:"transit_easy_ip"`
	TransitPort     uint16 `json:"transit_port"`
	LandingIP       string `json:"landing_ip"`
	LandingPort     uint16 `json:"landing_port"`
	Description     string `json:"description,omitempty"`
}

func initManagementSchema(db *sql.DB) error {
	_, err := db.Exec(`
CREATE TABLE IF NOT EXISTS users (
  user_id TEXT PRIMARY KEY,
  enabled INTEGER NOT NULL DEFAULT 1,
  expires_at INTEGER NOT NULL DEFAULT 0,
  quota_bytes INTEGER NOT NULL DEFAULT 0,
  billing_mode TEXT NOT NULL DEFAULT 'both'
);
CREATE TABLE IF NOT EXISTS managed_rules (
  rule_id TEXT PRIMARY KEY,
  node_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  protocol TEXT NOT NULL,
  listen_port INTEGER NOT NULL,
  target_ip TEXT NOT NULL,
  target_port INTEGER NOT NULL,
  match_daddr TEXT NOT NULL DEFAULT '',
  description TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS node_config (
  node_id TEXT PRIMARY KEY,
  role TEXT NOT NULL,
  nat_et_ip TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS links (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  protocol TEXT NOT NULL,
  client_port INTEGER NOT NULL,
  ingress_node_id TEXT NOT NULL,
  ingress_public_ip TEXT NOT NULL DEFAULT '',
  transit_node_id TEXT NOT NULL,
  transit_easy_ip TEXT NOT NULL,
  transit_port INTEGER NOT NULL,
  landing_ip TEXT NOT NULL,
  landing_port INTEGER NOT NULL,
  description TEXT NOT NULL DEFAULT ''
);`)
	return err
}

func validateUser(u UserSpec) error {
	if !ruleIDRE.MatchString(u.ID) {
		return errors.New("invalid user id")
	}
	if u.QuotaBytes < 0 || u.ExpiresAt < 0 {
		return errors.New("quota/expires_at cannot be negative")
	}
	if u.BillingMode == "" {
		u.BillingMode = "both"
	}
	if u.BillingMode != "both" && u.BillingMode != "up" && u.BillingMode != "down" {
		return errors.New("billing_mode must be both, up, or down")
	}
	return nil
}
func usageForUser(db *sql.DB, userID, mode string) (int64, error) {
	var expr string
	switch mode {
	case "up":
		expr = "COALESCE(SUM(e.up_bytes),0)"
	case "down":
		expr = "COALESCE(SUM(e.down_bytes),0)"
	default:
		expr = "COALESCE(SUM(e.up_bytes+e.down_bytes),0)"
	}
	var total int64
	err := db.QueryRow(`SELECT `+expr+` FROM usage_events e
LEFT JOIN managed_rules r ON r.rule_id=e.rule_id AND r.node_id=e.node_id
LEFT JOIN links l ON l.id=e.rule_id AND l.ingress_node_id=e.node_id
WHERE r.user_id=? OR l.user_id=?`, userID, userID).Scan(&total)
	return total, err
}
func activeUser(db *sql.DB, userID string, now int64) (bool, error) {
	var enabled int
	var expires, quota int64
	var mode string
	if err := db.QueryRow(`SELECT enabled,expires_at,quota_bytes,billing_mode FROM users WHERE user_id=?`, userID).Scan(&enabled, &expires, &quota, &mode); err != nil {
		return false, err
	}
	if enabled == 0 || (expires > 0 && now >= expires) {
		return false, nil
	}
	if quota > 0 {
		used, err := usageForUser(db, userID, mode)
		if err != nil {
			return false, err
		}
		if used >= quota {
			return false, nil
		}
	}
	return true, nil
}
func queueCommand(db *sql.DB, nodeID, typ string, body any) error {
	_, err := queueCommandWithDependencies(db, nodeID, typ, body, nil)
	return err
}

func queueCommandWithDependencies(db *sql.DB, nodeID, typ string, body any, dependsOn []string) (string, error) {
	tx, err := db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	id, err := queueCommandTx(tx, nodeID, typ, body, dependsOn)
	if err != nil {
		return "", err
	}
	return id, tx.Commit()
}

func queueCommandTx(tx *sql.Tx, nodeID, typ string, body any, dependsOn []string) (string, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	id := fmt.Sprintf("cmd-%d-%d-%s", time.Now().UnixNano(), atomic.AddUint64(&commandSequence, 1), nodeID)
	deps, _ := json.Marshal(dependsOn)
	if typ != "apply_ruleset" {
		_, err = tx.Exec(`INSERT INTO commands(id,node_id,type,body,depends_on,state,created_at) VALUES(?,?,?,?,?,'pending',?)`, id, nodeID, typ, string(b), string(deps), time.Now().Unix())
		return id, err
	}
	rs, ok := body.(Ruleset)
	if !ok {
		return "", errors.New("apply_ruleset body must be Ruleset")
	}
	hash, err := rulesetHash(rs)
	if err != nil {
		return "", err
	}
	if _, err = tx.Exec(`INSERT OR IGNORE INTO node_ruleset_state(node_id) VALUES(?)`, nodeID); err != nil {
		return "", err
	}
	var next int64
	if err = tx.QueryRow(`SELECT next_version FROM node_ruleset_state WHERE node_id=?`, nodeID).Scan(&next); err != nil {
		return "", err
	}
	version := next + 1
	if _, err = tx.Exec(`UPDATE commands SET state='superseded',detail='superseded by newer full ruleset',acknowledged_at=? WHERE node_id=? AND type='apply_ruleset' AND state='pending'`, time.Now().Unix(), nodeID); err != nil {
		return "", err
	}
	if _, err = tx.Exec(`UPDATE node_ruleset_state SET next_version=?,desired_version=?,desired_hash=? WHERE node_id=?`, version, version, hash, nodeID); err != nil {
		return "", err
	}
	if _, err = tx.Exec(`INSERT INTO commands(id,node_id,type,body,depends_on,ruleset_version,ruleset_hash,state,created_at) VALUES(?,?,?,?,?,?,?,'pending',?)`, id, nodeID, typ, string(b), string(deps), version, hash, time.Now().Unix()); err != nil {
		return "", err
	}
	if err = terminateBlockedCommands(tx); err != nil {
		return "", err
	}
	return id, nil
}

func transitRuleID(linkID string) string { return "t-" + linkID }

func linkRules(l LinkSpec) (RuleSpec, RuleSpec) {
	ingress := RuleSpec{ID: l.ID, Protocol: l.Protocol, ListenPort: l.ClientPort, TargetIP: l.TransitEasyIP, TargetPort: l.TransitPort, MatchDAddr: l.IngressPublicIP, Description: l.Description}
	transit := RuleSpec{ID: transitRuleID(l.ID), Protocol: l.Protocol, ListenPort: l.TransitPort, TargetIP: l.LandingIP, TargetPort: l.LandingPort, Description: l.Description, NoMeter: true}
	return ingress, transit
}

func scanLink(s interface{ Scan(...any) error }) (LinkSpec, error) {
	var l LinkSpec
	var enabled int
	err := s.Scan(&l.ID, &l.UserID, &enabled, &l.Protocol, &l.ClientPort, &l.IngressNodeID, &l.IngressPublicIP, &l.TransitNodeID, &l.TransitEasyIP, &l.TransitPort, &l.LandingIP, &l.LandingPort, &l.Description)
	l.Enabled = enabled != 0
	return l, err
}

const linkColumns = `id,user_id,enabled,protocol,client_port,ingress_node_id,ingress_public_ip,transit_node_id,transit_easy_ip,transit_port,landing_ip,landing_port,description`

func readLink(db *sql.DB, id string) (LinkSpec, error) {
	return scanLink(db.QueryRow(`SELECT `+linkColumns+` FROM links WHERE id=?`, id))
}

func validateLinkShape(l LinkSpec) error {
	// The transit rule has a t- prefix, so leave room for it in the nft rule ID.
	if !ruleIDRE.MatchString(l.ID) || len(l.ID) > 61 {
		return errors.New("invalid link id")
	}
	if !ruleIDRE.MatchString(l.UserID) || l.IngressNodeID == "" || l.TransitNodeID == "" {
		return errors.New("user_id, ingress_node_id, and transit_node_id are required")
	}
	ingress, transit := linkRules(l)
	if err := validateRuleset(Ruleset{Role: "ingress", Rules: []RuleSpec{ingress}}); err != nil {
		return fmt.Errorf("invalid ingress link rule: %w", err)
	}
	if err := validateRuleset(Ruleset{Role: "transit", NATETIP: l.TransitEasyIP, Rules: []RuleSpec{transit}}); err != nil {
		return fmt.Errorf("invalid transit link rule: %w", err)
	}
	return nil
}

func linkNodeConfig(db *sql.DB, nodeID, wantRole string) (NodeConfig, error) {
	var n NodeConfig
	if err := db.QueryRow(`SELECT node_id,role,nat_et_ip FROM node_config WHERE node_id=?`, nodeID).Scan(&n.NodeID, &n.Role, &n.NATETIP); err != nil {
		return n, err
	}
	if n.Role != wantRole {
		return n, fmt.Errorf("node %s must have %s role", nodeID, wantRole)
	}
	return n, nil
}

func selectorConflict(seen map[string]string, protocol string, port uint16, owner string) error {
	ps, err := protocols(protocol)
	if err != nil {
		return err
	}
	for _, p := range ps {
		key := p + ":" + fmt.Sprint(port)
		if prior, ok := seen[key]; ok {
			return fmt.Errorf("listen selector %s conflicts between %s and %s", key, prior, owner)
		}
		seen[key] = owner
	}
	return nil
}

// validateLinkPortConflicts checks the configured enabled objects, rather than
// only currently billable users. This prevents a future user re-enable from
// creating an ambiguous selector on a node.
func validateLinkPortConflicts(db *sql.DB, l LinkSpec) error {
	if !l.Enabled {
		return nil
	}
	selectors := map[string]map[string]string{}
	add := func(nodeID, protocol string, port uint16, owner string) error {
		if selectors[nodeID] == nil {
			selectors[nodeID] = map[string]string{}
		}
		return selectorConflict(selectors[nodeID], protocol, port, owner)
	}
	if err := add(l.IngressNodeID, l.Protocol, l.ClientPort, "link "+l.ID+" ingress"); err != nil {
		return err
	}
	if err := add(l.TransitNodeID, l.Protocol, l.TransitPort, "link "+l.ID+" transit"); err != nil {
		return err
	}
	for nodeID, seen := range selectors {
		rows, err := db.Query(`SELECT rule_id,protocol,listen_port FROM managed_rules WHERE node_id=? AND enabled!=0`, nodeID)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id, protocol string
			var port uint16
			if err := rows.Scan(&id, &protocol, &port); err != nil {
				rows.Close()
				return err
			}
			if err := selectorConflict(seen, protocol, port, "managed rule "+id); err != nil {
				rows.Close()
				return err
			}
		}
		if err := rows.Close(); err != nil {
			return err
		}
		rows, err = db.Query(`SELECT `+linkColumns+` FROM links WHERE enabled!=0 AND id<>? AND (ingress_node_id=? OR transit_node_id=?) ORDER BY id`, l.ID, nodeID, nodeID)
		if err != nil {
			return err
		}
		for rows.Next() {
			other, err := scanLink(rows)
			if err != nil {
				rows.Close()
				return err
			}
			if other.IngressNodeID == nodeID {
				if err := selectorConflict(seen, other.Protocol, other.ClientPort, "link "+other.ID+" ingress"); err != nil {
					rows.Close()
					return err
				}
			}
			if other.TransitNodeID == nodeID {
				if err := selectorConflict(seen, other.Protocol, other.TransitPort, "link "+other.ID+" transit"); err != nil {
					rows.Close()
					return err
				}
			}
		}
		if err := rows.Close(); err != nil {
			return err
		}
	}
	return nil
}

func validateLink(db *sql.DB, l LinkSpec) error {
	if err := validateLinkShape(l); err != nil {
		return err
	}
	if _, err := linkNodeConfig(db, l.IngressNodeID, "ingress"); err != nil {
		return err
	}
	transit, err := linkNodeConfig(db, l.TransitNodeID, "transit")
	if err != nil {
		return err
	}
	if transit.NATETIP != l.TransitEasyIP {
		return errors.New("transit_easy_ip must match transit node nat_et_ip")
	}
	var exists int
	if err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM users WHERE user_id=?)`, l.UserID).Scan(&exists); err != nil {
		return err
	}
	if exists == 0 {
		return errors.New("unknown link user")
	}
	if err := validateGlobalRuleID(db, l.ID, "link", l.ID); err != nil {
		return err
	}
	if err := validateGlobalRuleID(db, transitRuleID(l.ID), "link", l.ID); err != nil {
		return err
	}
	return validateLinkPortConflicts(db, l)
}

func validateGlobalRuleID(db *sql.DB, id, ownerType, ownerID string) error {
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM managed_rules WHERE rule_id=?`, id).Scan(&count); err != nil {
		return err
	}
	if count != 0 && !(ownerType == "managed" && ownerID == id) {
		return fmt.Errorf("rule id %s conflicts with managed rule", id)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM links WHERE (id=? OR 't-' || id=?) AND id<>?`, id, id, ownerID).Scan(&count); err != nil {
		return err
	}
	if count != 0 {
		return fmt.Errorf("rule id %s conflicts with link", id)
	}
	return nil
}

func syncUserNodes(db *sql.DB, userID string) error {
	rows, err := db.Query(`SELECT DISTINCT node_id FROM (
SELECT node_id FROM managed_rules WHERE user_id=?
UNION SELECT ingress_node_id FROM links WHERE user_id=?
UNION SELECT transit_node_id FROM links WHERE user_id=?
) ORDER BY node_id`, userID, userID, userID)
	if err != nil {
		return err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	return syncNodesTransitFirst(db, ids...)
}

func syncUserNodesTx(tx *sql.Tx, userID string) error {
	rows, err := tx.Query(`SELECT DISTINCT node_id FROM (
SELECT node_id FROM managed_rules WHERE user_id=?
UNION SELECT ingress_node_id FROM links WHERE user_id=?
UNION SELECT transit_node_id FROM links WHERE user_id=?
) ORDER BY node_id`, userID, userID, userID)
	if err != nil {
		return err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	return syncNodesTransitFirstTx(tx, ids, nil)
}

func upsertUser(db *sql.DB, u UserSpec) error {
	if err := validateUser(u); err != nil {
		return err
	}
	if u.BillingMode == "" {
		u.BillingMode = "both"
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	enabled := 0
	if u.Enabled {
		enabled = 1
	}
	if _, err := tx.Exec(`INSERT INTO users(user_id,enabled,expires_at,quota_bytes,billing_mode) VALUES(?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET enabled=excluded.enabled,expires_at=excluded.expires_at,quota_bytes=excluded.quota_bytes,billing_mode=excluded.billing_mode`, u.ID, enabled, u.ExpiresAt, u.QuotaBytes, u.BillingMode); err != nil {
		return err
	}
	if err := syncUserNodesTx(tx, u.ID); err != nil {
		return err
	}
	return tx.Commit()
}

func upsertManagedRule(db *sql.DB, r ManagedRule) error {
	if err := validateRuleset(Ruleset{Role: "ingress", Rules: []RuleSpec{r.RuleSpec}}); err != nil {
		return err
	}
	if r.NodeID == "" || r.UserID == "" {
		return errors.New("node_id and user_id required")
	}
	if err := validateGlobalRuleID(db, r.ID, "managed", r.ID); err != nil {
		return err
	}
	if err := validateManagedRulePortConflicts(db, r); err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	enabled := 0
	if r.Enabled {
		enabled = 1
	}
	if _, err := tx.Exec(`INSERT INTO managed_rules(rule_id,node_id,user_id,enabled,protocol,listen_port,target_ip,target_port,match_daddr,description) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(rule_id) DO UPDATE SET node_id=excluded.node_id,user_id=excluded.user_id,enabled=excluded.enabled,protocol=excluded.protocol,listen_port=excluded.listen_port,target_ip=excluded.target_ip,target_port=excluded.target_port,match_daddr=excluded.match_daddr,description=excluded.description`, r.ID, r.NodeID, r.UserID, enabled, r.Protocol, r.ListenPort, r.TargetIP, r.TargetPort, r.MatchDAddr, r.Description); err != nil {
		return err
	}
	if err := syncNodesTransitFirstTx(tx, []string{r.NodeID}, nil); err != nil {
		return err
	}
	return tx.Commit()
}

func validateManagedRulePortConflicts(db *sql.DB, r ManagedRule) error {
	if !r.Enabled {
		return nil
	}
	seen := map[string]string{}
	if err := selectorConflict(seen, r.Protocol, r.ListenPort, "managed rule "+r.ID); err != nil {
		return err
	}
	managedRows, err := db.Query(`SELECT rule_id,protocol,listen_port FROM managed_rules WHERE node_id=? AND enabled!=0 AND rule_id<>? ORDER BY rule_id`, r.NodeID, r.ID)
	if err != nil {
		return err
	}
	for managedRows.Next() {
		var id, protocol string
		var port uint16
		if err := managedRows.Scan(&id, &protocol, &port); err != nil {
			managedRows.Close()
			return err
		}
		if err := selectorConflict(seen, protocol, port, "managed rule "+id); err != nil {
			managedRows.Close()
			return err
		}
	}
	if err := managedRows.Close(); err != nil {
		return err
	}
	rows, err := db.Query(`SELECT `+linkColumns+` FROM links WHERE enabled!=0 AND (ingress_node_id=? OR transit_node_id=?) ORDER BY id`, r.NodeID, r.NodeID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		l, err := scanLink(rows)
		if err != nil {
			return err
		}
		if l.IngressNodeID == r.NodeID {
			if err := selectorConflict(seen, l.Protocol, l.ClientPort, "link "+l.ID+" ingress"); err != nil {
				return err
			}
		}
		if l.TransitNodeID == r.NodeID {
			if err := selectorConflict(seen, l.Protocol, l.TransitPort, "link "+l.ID+" transit"); err != nil {
				return err
			}
		}
	}
	return rows.Err()
}

func syncNodesTransitFirst(db *sql.DB, nodeIDs ...string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := syncNodesTransitFirstTx(tx, nodeIDs, nil); err != nil {
		return err
	}
	return tx.Commit()
}

func syncNodesTransitFirstTx(tx *sql.Tx, nodeIDs []string, oldLinks []LinkSpec) error {
	unique := map[string]bool{}
	for _, id := range nodeIDs {
		if id != "" {
			unique[id] = true
		}
	}
	type queuedNode struct{ id, role string }
	nodes := make([]queuedNode, 0, len(unique))
	for id := range unique {
		var role string
		if err := tx.QueryRow(`SELECT role FROM node_config WHERE node_id=?`, id).Scan(&role); err != nil {
			return err
		}
		nodes = append(nodes, queuedNode{id: id, role: role})
	}
	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].role != nodes[j].role {
			return nodes[i].role == "transit"
		}
		return nodes[i].id < nodes[j].id
	})
	// Include the transit side for links currently rendered by an explicitly
	// requested ingress, and for a removed/changed old link. This makes a
	// full ingress replacement wait only on its own forwarding paths.
	for _, old := range oldLinks {
		if old.TransitNodeID != "" {
			unique[old.TransitNodeID] = true
		}
	}
	for _, n := range nodes {
		if n.role != "ingress" {
			continue
		}
		rows, err := tx.Query(`SELECT DISTINCT transit_node_id FROM links WHERE ingress_node_id=?`, n.id)
		if err != nil {
			return err
		}
		for rows.Next() {
			var transitID string
			if err := rows.Scan(&transitID); err != nil {
				rows.Close()
				return err
			}
			unique[transitID] = true
		}
		if err := rows.Close(); err != nil {
			return err
		}
	}
	// Rebuild the list after adding required transit nodes.
	nodes = nodes[:0]
	for id := range unique {
		var role string
		if err := tx.QueryRow(`SELECT role FROM node_config WHERE node_id=?`, id).Scan(&role); err != nil {
			return err
		}
		nodes = append(nodes, queuedNode{id: id, role: role})
	}
	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].role != nodes[j].role {
			return nodes[i].role == "transit"
		}
		return nodes[i].id < nodes[j].id
	})
	transit := map[string]string{}
	for _, n := range nodes {
		if n.role != "transit" {
			continue
		}
		rs, err := buildNodeRulesetTx(tx, n.id)
		if err != nil {
			return fmt.Errorf("sync %s: %w", n.id, err)
		}
		id, err := queueCommandTx(tx, n.id, "apply_ruleset", rs, nil)
		if err != nil {
			return err
		}
		transit[n.id] = id
	}
	for _, n := range nodes {
		if n.role == "transit" {
			continue
		}
		rs, err := buildNodeRulesetTx(tx, n.id)
		if err != nil {
			return fmt.Errorf("sync %s: %w", n.id, err)
		}
		deps, err := ingressTransitDependencies(tx, n.id, oldLinks, transit)
		if err != nil {
			return err
		}
		if _, err := queueCommandTx(tx, n.id, "apply_ruleset", rs, deps); err != nil {
			return err
		}
	}
	return nil
}

func ingressTransitDependencies(tx *sql.Tx, ingressID string, oldLinks []LinkSpec, commands map[string]string) ([]string, error) {
	transits := map[string]bool{}
	rows, err := tx.Query(`SELECT DISTINCT transit_node_id FROM links WHERE ingress_node_id=?`, ingressID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		transits[id] = true
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for _, old := range oldLinks {
		if old.IngressNodeID == ingressID && old.TransitNodeID != "" {
			transits[old.TransitNodeID] = true
		}
	}
	var deps []string
	for transitID := range transits {
		if id := commands[transitID]; id != "" {
			deps = append(deps, id)
		}
	}
	sort.Strings(deps)
	return deps, nil
}

func upsertLink(db *sql.DB, l LinkSpec) error {
	var old LinkSpec
	old, oldErr := readLink(db, l.ID)
	if oldErr != nil && !errors.Is(oldErr, sql.ErrNoRows) {
		return oldErr
	}
	if err := validateLink(db, l); err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	enabled := 0
	if l.Enabled {
		enabled = 1
	}
	if _, err := tx.Exec(`INSERT INTO links(`+linkColumns+`) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET user_id=excluded.user_id,enabled=excluded.enabled,protocol=excluded.protocol,client_port=excluded.client_port,ingress_node_id=excluded.ingress_node_id,ingress_public_ip=excluded.ingress_public_ip,transit_node_id=excluded.transit_node_id,transit_easy_ip=excluded.transit_easy_ip,transit_port=excluded.transit_port,landing_ip=excluded.landing_ip,landing_port=excluded.landing_port,description=excluded.description`, l.ID, l.UserID, enabled, l.Protocol, l.ClientPort, l.IngressNodeID, l.IngressPublicIP, l.TransitNodeID, l.TransitEasyIP, l.TransitPort, l.LandingIP, l.LandingPort, l.Description); err != nil {
		return err
	}
	if err := syncNodesTransitFirstTx(tx, []string{old.IngressNodeID, old.TransitNodeID, l.IngressNodeID, l.TransitNodeID}, []LinkSpec{old}); err != nil {
		return err
	}
	return tx.Commit()
}

func deleteLink(db *sql.DB, id string) error {
	old, err := readLink(db, id)
	if err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM links WHERE id=?`, id); err != nil {
		return err
	}
	if err := syncNodesTransitFirstTx(tx, []string{old.IngressNodeID, old.TransitNodeID}, []LinkSpec{old}); err != nil {
		return err
	}
	return tx.Commit()
}

func syncNode(db *sql.DB, nodeID string) error {
	return syncNodesTransitFirst(db, nodeID)
}

func buildNodeRuleset(db *sql.DB, nodeID string) (Ruleset, error) {
	var nc NodeConfig
	if err := db.QueryRow(`SELECT node_id,role,nat_et_ip FROM node_config WHERE node_id=?`, nodeID).Scan(&nc.NodeID, &nc.Role, &nc.NATETIP); err != nil {
		return Ruleset{}, err
	}
	rs := Ruleset{Role: nc.Role, NATETIP: nc.NATETIP}
	now := time.Now().Unix()
	rows, err := db.Query(`SELECT rule_id,user_id,enabled,protocol,listen_port,target_ip,target_port,match_daddr,description FROM managed_rules WHERE node_id=? ORDER BY rule_id`, nodeID)
	if err != nil {
		return Ruleset{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var r ManagedRule
		var enabled int
		if err := rows.Scan(&r.ID, &r.UserID, &enabled, &r.Protocol, &r.ListenPort, &r.TargetIP, &r.TargetPort, &r.MatchDAddr, &r.Description); err != nil {
			return Ruleset{}, err
		}
		active, err := activeUser(db, r.UserID, now)
		if err != nil {
			return Ruleset{}, err
		}
		if enabled != 0 && active {
			rs.Rules = append(rs.Rules, r.RuleSpec)
		}
	}
	if err := rows.Err(); err != nil {
		return Ruleset{}, err
	}
	linkRows, err := db.Query(`SELECT `+linkColumns+` FROM links WHERE ingress_node_id=? OR transit_node_id=? ORDER BY id`, nodeID, nodeID)
	if err != nil {
		return Ruleset{}, err
	}
	defer linkRows.Close()
	for linkRows.Next() {
		l, err := scanLink(linkRows)
		if err != nil {
			return Ruleset{}, err
		}
		active, err := activeUser(db, l.UserID, now)
		if err != nil {
			return Ruleset{}, err
		}
		if !l.Enabled || !active {
			continue
		}
		ingress, transit := linkRules(l)
		if l.IngressNodeID == nodeID {
			rs.Rules = append(rs.Rules, ingress)
		}
		if l.TransitNodeID == nodeID {
			rs.Rules = append(rs.Rules, transit)
		}
	}
	if err := linkRows.Err(); err != nil {
		return Ruleset{}, err
	}
	sort.Slice(rs.Rules, func(i, j int) bool { return rs.Rules[i].ID < rs.Rules[j].ID })
	if _, err := renderNFT(rs); err != nil {
		return Ruleset{}, err
	}
	return rs, nil
}

func activeUserTx(tx *sql.Tx, userID string, now int64) (bool, error) {
	var enabled int
	var expires, quota int64
	var mode string
	if err := tx.QueryRow(`SELECT enabled,expires_at,quota_bytes,billing_mode FROM users WHERE user_id=?`, userID).Scan(&enabled, &expires, &quota, &mode); err != nil {
		return false, err
	}
	if enabled == 0 || (expires > 0 && now >= expires) {
		return false, nil
	}
	if quota == 0 {
		return true, nil
	}
	var used int64
	var query string
	switch mode {
	case "up":
		query = `SELECT COALESCE(SUM(e.up_bytes),0) FROM usage_events e LEFT JOIN managed_rules r ON r.rule_id=e.rule_id AND r.node_id=e.node_id LEFT JOIN links l ON l.id=e.rule_id AND l.ingress_node_id=e.node_id WHERE r.user_id=? OR l.user_id=?`
	case "down":
		query = `SELECT COALESCE(SUM(e.down_bytes),0) FROM usage_events e LEFT JOIN managed_rules r ON r.rule_id=e.rule_id AND r.node_id=e.node_id LEFT JOIN links l ON l.id=e.rule_id AND l.ingress_node_id=e.node_id WHERE r.user_id=? OR l.user_id=?`
	default:
		query = `SELECT COALESCE(SUM(e.up_bytes+e.down_bytes),0) FROM usage_events e LEFT JOIN managed_rules r ON r.rule_id=e.rule_id AND r.node_id=e.node_id LEFT JOIN links l ON l.id=e.rule_id AND l.ingress_node_id=e.node_id WHERE r.user_id=? OR l.user_id=?`
	}
	if err := tx.QueryRow(query, userID, userID).Scan(&used); err != nil {
		return false, err
	}
	return used < quota, nil
}

func buildNodeRulesetTx(tx *sql.Tx, nodeID string) (Ruleset, error) {
	var nc NodeConfig
	if err := tx.QueryRow(`SELECT node_id,role,nat_et_ip FROM node_config WHERE node_id=?`, nodeID).Scan(&nc.NodeID, &nc.Role, &nc.NATETIP); err != nil {
		return Ruleset{}, err
	}
	rs := Ruleset{Role: nc.Role, NATETIP: nc.NATETIP}
	now := time.Now().Unix()
	rows, err := tx.Query(`SELECT rule_id,user_id,enabled,protocol,listen_port,target_ip,target_port,match_daddr,description FROM managed_rules WHERE node_id=? ORDER BY rule_id`, nodeID)
	if err != nil {
		return Ruleset{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var r ManagedRule
		var enabled int
		if err := rows.Scan(&r.ID, &r.UserID, &enabled, &r.Protocol, &r.ListenPort, &r.TargetIP, &r.TargetPort, &r.MatchDAddr, &r.Description); err != nil {
			return Ruleset{}, err
		}
		active, err := activeUserTx(tx, r.UserID, now)
		if err != nil {
			return Ruleset{}, err
		}
		if enabled != 0 && active {
			rs.Rules = append(rs.Rules, r.RuleSpec)
		}
	}
	if err := rows.Err(); err != nil {
		return Ruleset{}, err
	}
	linkRows, err := tx.Query(`SELECT `+linkColumns+` FROM links WHERE ingress_node_id=? OR transit_node_id=? ORDER BY id`, nodeID, nodeID)
	if err != nil {
		return Ruleset{}, err
	}
	defer linkRows.Close()
	for linkRows.Next() {
		l, err := scanLink(linkRows)
		if err != nil {
			return Ruleset{}, err
		}
		active, err := activeUserTx(tx, l.UserID, now)
		if err != nil {
			return Ruleset{}, err
		}
		if !l.Enabled || !active {
			continue
		}
		ingress, transit := linkRules(l)
		if l.IngressNodeID == nodeID {
			rs.Rules = append(rs.Rules, ingress)
		}
		if l.TransitNodeID == nodeID {
			rs.Rules = append(rs.Rules, transit)
		}
	}
	if err := linkRows.Err(); err != nil {
		return Ruleset{}, err
	}
	sort.Slice(rs.Rules, func(i, j int) bool { return rs.Rules[i].ID < rs.Rules[j].ID })
	if _, err := renderNFT(rs); err != nil {
		return Ruleset{}, err
	}
	return rs, nil
}
func runAdmin(database, requestFile string) {
	if requestFile == "" {
		fmt.Fprintln(os.Stderr, "--admin-file required")
		os.Exit(2)
	}
	b, err := os.ReadFile(requestFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	var req AdminRequest
	if err := json.Unmarshal(b, &req); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	db := openDB(database)
	defer db.Close()
	if err := initManagementSchema(db); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	switch req.Action {
	case "upsert_user":
		var u UserSpec
		if err := json.Unmarshal(req.Body, &u); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		err = upsertUser(db, u)
	case "upsert_node":
		var n NodeConfig
		if err := json.Unmarshal(req.Body, &n); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		if n.NodeID == "" || (n.Role != "ingress" && n.Role != "transit") {
			err = errors.New("invalid node config")
		} else if n.Role == "transit" && n.NATETIP == "" {
			err = errors.New("transit node requires nat_et_ip")
		} else {
			_, err = db.Exec(`INSERT INTO node_config(node_id,role,nat_et_ip) VALUES(?,?,?) ON CONFLICT(node_id) DO UPDATE SET role=excluded.role,nat_et_ip=excluded.nat_et_ip`, n.NodeID, n.Role, n.NATETIP)
		}
	case "upsert_rule":
		var r ManagedRule
		if err := json.Unmarshal(req.Body, &r); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		err = upsertManagedRule(db, r)
	case "upsert_link":
		var l LinkSpec
		if err := json.Unmarshal(req.Body, &l); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		err = upsertLink(db, l)
	case "delete_link":
		var body struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(req.Body, &body); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		if !ruleIDRE.MatchString(body.ID) {
			err = errors.New("invalid link id")
		} else {
			err = deleteLink(db, body.ID)
		}
	case "sync_node":
		var n struct {
			NodeID string `json:"node_id"`
		}
		if err := json.Unmarshal(req.Body, &n); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		err = syncNode(db, n.NodeID)
	default:
		err = errors.New("unsupported admin action")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("ok")
}

func reconcileAll(db *sql.DB) error {
	rows, err := db.Query(`SELECT node_id FROM node_config ORDER BY node_id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var nodes []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return err
		}
		nodes = append(nodes, id)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	return syncNodesTransitFirst(db, nodes...)
}

func runReconcile(database string) {
	db := openDB(database)
	defer db.Close()
	if err := initManagementSchema(db); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := reconcileAll(db); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("ok")
}

// Guard duplicate rule IDs deterministically in tests and future callers.
func sortedRuleIDs(rs []RuleSpec) []string {
	o := make([]string, len(rs))
	for i := range rs {
		o[i] = rs[i].ID
	}
	sort.Strings(o)
	return o
}
