package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"time"
)

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
	err := db.QueryRow(`SELECT `+expr+` FROM usage_events e JOIN managed_rules r ON r.rule_id=e.rule_id WHERE r.user_id=?`, userID).Scan(&total)
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
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	id := fmt.Sprintf("cmd-%d-%s", time.Now().UnixNano(), nodeID)
	_, err = db.Exec(`INSERT INTO commands(id,node_id,type,body,state,created_at) VALUES(?,?,?,?, 'pending',?)`, id, nodeID, typ, string(b), time.Now().Unix())
	return err
}
func syncNode(db *sql.DB, nodeID string) error {
	var nc NodeConfig
	if err := db.QueryRow(`SELECT node_id,role,nat_et_ip FROM node_config WHERE node_id=?`, nodeID).Scan(&nc.NodeID, &nc.Role, &nc.NATETIP); err != nil {
		return err
	}
	rows, err := db.Query(`SELECT rule_id,user_id,enabled,protocol,listen_port,target_ip,target_port,match_daddr,description FROM managed_rules WHERE node_id=? ORDER BY rule_id`, nodeID)
	if err != nil {
		return err
	}
	defer rows.Close()
	rs := Ruleset{Role: nc.Role, NATETIP: nc.NATETIP}
	now := time.Now().Unix()
	for rows.Next() {
		var r ManagedRule
		var enabled int
		if err := rows.Scan(&r.ID, &r.UserID, &enabled, &r.Protocol, &r.ListenPort, &r.TargetIP, &r.TargetPort, &r.MatchDAddr, &r.Description); err != nil {
			return err
		}
		active, err := activeUser(db, r.UserID, now)
		if err != nil {
			return err
		}
		if enabled != 0 && active {
			rs.Rules = append(rs.Rules, r.RuleSpec)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if _, err := renderNFT(rs); err != nil {
		return err
	}
	return queueCommand(db, nodeID, "apply_ruleset", rs)
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
		if err := validateUser(u); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		if u.BillingMode == "" {
			u.BillingMode = "both"
		}
		en := 0
		if u.Enabled {
			en = 1
		}
		_, err = db.Exec(`INSERT INTO users(user_id,enabled,expires_at,quota_bytes,billing_mode) VALUES(?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET enabled=excluded.enabled,expires_at=excluded.expires_at,quota_bytes=excluded.quota_bytes,billing_mode=excluded.billing_mode`, u.ID, en, u.ExpiresAt, u.QuotaBytes, u.BillingMode)
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
		if err = validateRuleset(Ruleset{Role: "ingress", Rules: []RuleSpec{r.RuleSpec}}); err == nil && (r.NodeID == "" || r.UserID == "") {
			err = errors.New("node_id and user_id required")
		}
		if err == nil {
			en := 0
			if r.Enabled {
				en = 1
			}
			_, err = db.Exec(`INSERT INTO managed_rules(rule_id,node_id,user_id,enabled,protocol,listen_port,target_ip,target_port,match_daddr,description) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(rule_id) DO UPDATE SET node_id=excluded.node_id,user_id=excluded.user_id,enabled=excluded.enabled,protocol=excluded.protocol,listen_port=excluded.listen_port,target_ip=excluded.target_ip,target_port=excluded.target_port,match_daddr=excluded.match_daddr,description=excluded.description`, r.ID, r.NodeID, r.UserID, en, r.Protocol, r.ListenPort, r.TargetIP, r.TargetPort, r.MatchDAddr, r.Description)
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
	for _, id := range nodes {
		if err := syncNode(db, id); err != nil {
			return fmt.Errorf("sync %s: %w", id, err)
		}
	}
	return nil
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
