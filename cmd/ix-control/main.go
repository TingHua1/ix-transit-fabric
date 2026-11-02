// ix-control is a compact control-plane and node-agent for ix-transit-fabric.
//
// Server mode owns the SQLite ledger and exposes a single WebSocket endpoint.
// Agent mode makes an outbound WebSocket connection, reports idempotent traffic
// deltas, and receives commands. It deliberately does not execute shell commands:
// the embedding caller must implement command application after reviewing it.
package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	_ "github.com/mattn/go-sqlite3"
)

const protocolVersion = 2

type Message struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data,omitempty"`
}

type Hello struct {
	NodeID              string `json:"node_id"`
	Token               string `json:"token"`
	RulesetVersion      int64  `json:"ruleset_version,omitempty"`
	RulesetHash         string `json:"ruleset_hash,omitempty"`
	RulesetVersionGuard bool   `json:"ruleset_version_guard"`
}

type Usage struct {
	NodeID    string `json:"node_id"`
	RuleID    string `json:"rule_id"`
	Sequence  int64  `json:"sequence"`
	UpBytes   int64  `json:"up_bytes"`
	DownBytes int64  `json:"down_bytes"`
	At        int64  `json:"at"`
}

type Command struct {
	ID             string          `json:"id"`
	NodeID         string          `json:"node_id"`
	Type           string          `json:"type"`
	Body           json.RawMessage `json:"body"`
	DependsOn      []string        `json:"depends_on,omitempty"`
	RulesetVersion int64           `json:"ruleset_version,omitempty"`
	RulesetHash    string          `json:"ruleset_hash,omitempty"`
	Detail         string          `json:"detail,omitempty"`
}

type CommandAck struct {
	ID     string `json:"id"`
	NodeID string `json:"node_id"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

type Server struct {
	db       *sql.DB
	nodeLock sync.Mutex
	upgrader websocket.Upgrader
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func openDB(path string) *sql.DB {
	dsn, dbPath := sqliteDSN(path)
	if dbPath != "" {
		must(os.MkdirAll(filepath.Dir(dbPath), 0700))
	}
	db, err := sql.Open("sqlite3", dsn)
	must(err)
	must(db.Ping())
	must(initSchema(db))
	return db
}

// sqliteDSN preserves caller supplied SQLite options while supplying the
// defaults required by the controller. In particular, file DSNs that already
// have a query string use '&', never a second '?'.
func sqliteDSN(dsn string) (string, string) {
	base, query, hasQuery := strings.Cut(dsn, "?")
	values, _ := url.ParseQuery(query)
	missing := make([]string, 0, 2)
	if _, ok := values["_busy_timeout"]; !ok {
		missing = append(missing, "_busy_timeout=5000")
	}
	if _, ok := values["_journal_mode"]; !ok {
		missing = append(missing, "_journal_mode=WAL")
	}
	if len(missing) > 0 {
		separator := "?"
		if hasQuery {
			separator = "&"
		}
		dsn += separator + strings.Join(missing, "&")
	}
	if !strings.HasPrefix(base, "file:") {
		return dsn, base
	}
	if base == "file::memory:" || values.Get("mode") == "memory" {
		return dsn, ""
	}
	fileURL, err := url.Parse(base)
	if err != nil || fileURL.Path == "" {
		return dsn, ""
	}
	return dsn, fileURL.Path
}

func initSchema(db *sql.DB) error {
	_, err := db.Exec(`
CREATE TABLE IF NOT EXISTS nodes (
  node_id TEXT PRIMARY KEY,
  token TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  last_seen INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS rules (
  rule_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  expires_at INTEGER NOT NULL DEFAULT 0,
  quota_bytes INTEGER NOT NULL DEFAULT 0,
  billing_mode TEXT NOT NULL DEFAULT 'both'
);
CREATE TABLE IF NOT EXISTS usage_events (
  node_id TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  sequence INTEGER NOT NULL,
  up_bytes INTEGER NOT NULL,
  down_bytes INTEGER NOT NULL,
  at INTEGER NOT NULL,
  PRIMARY KEY (node_id, rule_id, sequence)
);
CREATE TABLE IF NOT EXISTS commands (
  id TEXT PRIMARY KEY,
  node_id TEXT NOT NULL,
  type TEXT NOT NULL,
  body TEXT NOT NULL DEFAULT '{}',
  state TEXT NOT NULL DEFAULT 'pending',
   depends_on TEXT NOT NULL DEFAULT '[]',
   ruleset_version INTEGER NOT NULL DEFAULT 0,
   ruleset_hash TEXT NOT NULL DEFAULT '',
   detail TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  acknowledged_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS node_ruleset_state (
   node_id TEXT PRIMARY KEY,
   next_version INTEGER NOT NULL DEFAULT 0,
   desired_version INTEGER NOT NULL DEFAULT 0,
   desired_hash TEXT NOT NULL DEFAULT '',
   applied_version INTEGER NOT NULL DEFAULT 0,
    applied_hash TEXT NOT NULL DEFAULT ''
 );
CREATE TABLE IF NOT EXISTS node_status (
   node_id TEXT PRIMARY KEY,
   boot_id TEXT NOT NULL,
   generation INTEGER NOT NULL,
   sequence INTEGER NOT NULL,
   received_at INTEGER NOT NULL,
   report TEXT NOT NULL
);
`)
	if err != nil {
		return err
	}
	// Existing installations predate dependency and ruleset metadata. SQLite has
	// no ADD COLUMN IF NOT EXISTS, so duplicate-column errors are deliberately
	// ignored after the idempotent table creation above.
	for _, statement := range []string{
		`ALTER TABLE commands ADD COLUMN depends_on TEXT NOT NULL DEFAULT '[]'`,
		`ALTER TABLE commands ADD COLUMN ruleset_version INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE commands ADD COLUMN ruleset_hash TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE commands ADD COLUMN detail TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE commands ADD COLUMN acknowledged_at INTEGER NOT NULL DEFAULT 0`,
	} {
		if _, e := db.Exec(statement); e != nil && !strings.Contains(e.Error(), "duplicate column name") {
			return e
		}
	}
	if err := migrateNodeStatusGeneration(db); err != nil {
		return err
	}
	return nil
}

// migrateNodeStatusGeneration recognizes every pre-generation node_status
// shape. Existing status is retained at generation zero; GetNodeStatus treats
// those rows as historical-only compatibility data, and the first persistent
// local generation (one) always supersedes them.
func migrateNodeStatusGeneration(db *sql.DB) error {
	rows, err := db.Query(`PRAGMA table_info(node_status)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	hasGeneration := false
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull, pk int
		var defaultValue any
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
			return err
		}
		if name == "generation" {
			hasGeneration = true
		}
	}
	if err := rows.Err(); err != nil || hasGeneration {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`ALTER TABLE node_status RENAME TO node_status_legacy_generation`); err != nil {
		return err
	}
	if _, err := tx.Exec(`CREATE TABLE node_status (
   node_id TEXT PRIMARY KEY,
   boot_id TEXT NOT NULL,
   generation INTEGER NOT NULL,
   sequence INTEGER NOT NULL,
   received_at INTEGER NOT NULL,
   report TEXT NOT NULL
)`); err != nil {
		return err
	}
	rows, err = tx.Query(`SELECT node_id,boot_id,sequence,received_at,report FROM node_status_legacy_generation`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var nodeID, bootID, report string
		var sequence, receivedAt int64
		if err := rows.Scan(&nodeID, &bootID, &sequence, &receivedAt, &report); err != nil {
			return err
		}
		var payload map[string]any
		if err := json.Unmarshal([]byte(report), &payload); err != nil {
			return fmt.Errorf("decode legacy node status: %w", err)
		}
		delete(payload, "boot_epoch")
		// Both the row and its diagnostic JSON are historical generation zero.
		payload["generation"] = 0
		updated, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO node_status(node_id,boot_id,generation,sequence,received_at,report) VALUES(?,?,?,?,?,?)`, nodeID, bootID, 0, sequence, receivedAt, string(updated)); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if _, err := tx.Exec(`DROP TABLE node_status_legacy_generation`); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Server) authenticate(h Hello) error {
	if h.NodeID == "" || h.Token == "" {
		return errors.New("node_id and token are required")
	}
	var token string
	var enabled int
	err := s.db.QueryRow(`SELECT token, enabled FROM nodes WHERE node_id=?`, h.NodeID).Scan(&token, &enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("unknown node")
	}
	if err != nil {
		return err
	}
	if enabled == 0 || token != h.Token {
		return errors.New("node rejected")
	}
	_, err = s.db.Exec(`UPDATE nodes SET last_seen=? WHERE node_id=?`, time.Now().Unix(), h.NodeID)
	return err
}

func (s *Server) ws(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	var first Message
	if err := conn.ReadJSON(&first); err != nil || first.Type != "hello" {
		_ = conn.WriteJSON(Message{Type: "error", Data: json.RawMessage(`"hello required"`)})
		return
	}
	var hello Hello
	if json.Unmarshal(first.Data, &hello) != nil || s.authenticate(hello) != nil {
		_ = conn.WriteJSON(Message{Type: "error", Data: json.RawMessage(`"authentication failed"`)})
		return
	}
	if !hello.RulesetVersionGuard {
		_ = conn.WriteJSON(Message{Type: "error", Data: json.RawMessage(`"protocol v2 ruleset_version_guard capability required"`)})
		return
	}
	if err := s.recordHello(hello); err != nil {
		return
	}
	if err := conn.WriteJSON(Message{Type: "welcome", Data: json.RawMessage(fmt.Sprintf(`{"protocol":%d}`, protocolVersion))}); err != nil {
		return
	}
	for {
		var m Message
		if err := conn.ReadJSON(&m); err != nil {
			return
		}
		switch m.Type {
		case "usage":
			var u Usage
			if err := json.Unmarshal(m.Data, &u); err != nil || u.NodeID != hello.NodeID || u.Sequence < 1 || u.UpBytes < 0 || u.DownBytes < 0 {
				_ = conn.WriteJSON(Message{Type: "error", Data: json.RawMessage(`"invalid usage"`)})
				continue
			}
			if u.At == 0 {
				u.At = time.Now().Unix()
			}
			result, err := s.db.Exec(`INSERT OR IGNORE INTO usage_events(node_id,rule_id,sequence,up_bytes,down_bytes,at) VALUES(?,?,?,?,?,?)`, u.NodeID, u.RuleID, u.Sequence, u.UpBytes, u.DownBytes, u.At)
			if err != nil {
				_ = conn.WriteJSON(Message{Type: "error", Data: json.RawMessage(`"ledger write failed"`)})
				continue
			}
			n, _ := result.RowsAffected()
			_ = conn.WriteJSON(Message{Type: "usage_ack", Data: mustJSON(map[string]any{"rule_id": u.RuleID, "sequence": u.Sequence, "accepted": n == 1})})
		case "status_report":
			report, err := decodeStatusReport(m.Data)
			if err != nil {
				_ = conn.WriteJSON(Message{Type: "error", Data: json.RawMessage(`"invalid status report"`)})
				continue
			}
			accepted, err := s.recordStatus(hello.NodeID, report)
			if err != nil {
				_ = conn.WriteJSON(Message{Type: "error", Data: json.RawMessage(`"status write failed"`)})
				continue
			}
			_ = conn.WriteJSON(Message{Type: "status_ack", Data: mustJSON(map[string]any{"boot_id": report.BootID, "sequence": report.Sequence, "accepted": accepted})})
		case "poll":
			commands, err := s.pendingCommands(hello.NodeID)
			if err != nil {
				_ = conn.WriteJSON(Message{Type: "error", Data: json.RawMessage(`"command read failed"`)})
				continue
			}
			_ = conn.WriteJSON(Message{Type: "commands", Data: mustJSON(commands)})
		case "command_ack":
			var a CommandAck
			if err := json.Unmarshal(m.Data, &a); err != nil || a.NodeID != hello.NodeID || a.ID == "" {
				_ = conn.WriteJSON(Message{Type: "error", Data: json.RawMessage(`"invalid command acknowledgement"`)})
				continue
			}
			state := "failed"
			if a.OK {
				state = "done"
			}
			accepted, err := s.ackCommand(hello.NodeID, a.ID, state, a.Detail)
			if err != nil {
				_ = conn.WriteJSON(Message{Type: "error", Data: json.RawMessage(`"command acknowledgement failed"`)})
				continue
			}
			_ = conn.WriteJSON(Message{Type: "command_ack", Data: mustJSON(map[string]any{"id": a.ID, "accepted": accepted})})
		default:
			_ = conn.WriteJSON(Message{Type: "error", Data: json.RawMessage(`"unknown message"`)})
		}
	}
}

func (s *Server) pendingCommands(nodeID string) ([]Command, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := terminateBlockedCommands(tx); err != nil {
		return nil, err
	}
	rows, err := tx.Query(`SELECT id,node_id,type,body,depends_on,ruleset_version,ruleset_hash,detail FROM commands WHERE node_id=? AND state='pending' ORDER BY created_at,id`, nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Command
	for rows.Next() {
		var c Command
		var body string
		var deps string
		if err := rows.Scan(&c.ID, &c.NodeID, &c.Type, &body, &deps, &c.RulesetVersion, &c.RulesetHash, &c.Detail); err != nil {
			return nil, err
		}
		c.Body = json.RawMessage(body)
		if json.Unmarshal([]byte(deps), &c.DependsOn) != nil {
			continue
		}
		if commandDependenciesDone(tx, c.DependsOn) {
			out = append(out, c)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, tx.Commit()
}

func (s *Server) ackCommand(nodeID, id, state, detail string) (bool, error) {
	if state != "done" && state != "failed" {
		return false, errors.New("invalid acknowledgement state")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	result, err := tx.Exec(`UPDATE commands SET state=?, detail=?, acknowledged_at=? WHERE id=? AND node_id=? AND state='pending'`, state, detail, time.Now().Unix(), id, nodeID)
	if err != nil {
		return false, err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		var current string
		if err = tx.QueryRow(`SELECT state FROM commands WHERE id=? AND node_id=?`, id, nodeID).Scan(&current); err != nil {
			return false, err
		}
	}
	if err := terminateBlockedCommands(tx); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return n == 1, nil
}

func (s *Server) recordHello(h Hello) error {
	if h.RulesetVersion < 0 {
		return errors.New("invalid ruleset version")
	}
	_, err := s.db.Exec(`INSERT INTO node_ruleset_state(node_id,applied_version,applied_hash) VALUES(?,?,?) ON CONFLICT(node_id) DO UPDATE SET applied_version=CASE WHEN excluded.applied_version>applied_version THEN excluded.applied_version ELSE applied_version END, applied_hash=CASE WHEN excluded.applied_version>=applied_version THEN excluded.applied_hash ELSE applied_hash END`, h.NodeID, h.RulesetVersion, h.RulesetHash)
	return err
}

// terminateBlockedCommands reaches a fixed point, so a failed transit command
// also terminates ingress commands which depend on a command already cancelled.
func terminateBlockedCommands(tx *sql.Tx) error {
	for {
		rows, err := tx.Query(`SELECT id,depends_on FROM commands WHERE state='pending'`)
		if err != nil {
			return err
		}
		var doomed []struct{ id, state string }
		for rows.Next() {
			var id, raw string
			if err := rows.Scan(&id, &raw); err != nil {
				rows.Close()
				return err
			}
			var deps []string
			if json.Unmarshal([]byte(raw), &deps) != nil {
				doomed = append(doomed, struct{ id, state string }{id, "failed"})
				continue
			}
			for _, dep := range deps {
				var state string
				err := tx.QueryRow(`SELECT state FROM commands WHERE id=?`, dep).Scan(&state)
				if errors.Is(err, sql.ErrNoRows) {
					doomed = append(doomed, struct{ id, state string }{id, "failed"})
					break
				}
				if err != nil {
					rows.Close()
					return err
				}
				if state == "superseded" {
					doomed = append(doomed, struct{ id, state string }{id, "superseded"})
					break
				}
				if state == "failed" || state == "cancelled" {
					doomed = append(doomed, struct{ id, state string }{id, "cancelled"})
					break
				}
			}
		}
		if err := rows.Close(); err != nil {
			return err
		}
		if len(doomed) == 0 {
			return nil
		}
		for _, d := range doomed {
			if _, err := tx.Exec(`UPDATE commands SET state=?,detail=?,acknowledged_at=? WHERE id=? AND state='pending'`, d.state, "blocked by dependency", time.Now().Unix(), d.id); err != nil {
				return err
			}
		}
	}
}

func commandDependenciesDone(tx *sql.Tx, deps []string) bool {
	for _, dep := range deps {
		var state string
		if tx.QueryRow(`SELECT state FROM commands WHERE id=?`, dep).Scan(&state) != nil || state != "done" {
			return false
		}
	}
	return true
}

func mustJSON(v any) json.RawMessage { b, _ := json.Marshal(v); return b }

func runServer(addr, database string) {
	// Node authentication is enforced by the initial hello message. Agents do
	// not normally send a browser Origin header, so Origin is not an auth layer.
	s := &Server{db: openDB(database), upgrader: websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}}
	defer s.db.Close()
	http.HandleFunc("/v1/ws", s.ws)
	http.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	log.Printf("ix-control server listening on %s", addr)
	must(http.ListenAndServe(addr, nil))
}

func runAgent(serverURL, nodeID, token, tokenFile, usageFile, applyHook, rulesetState string) {
	if tokenFile != "" {
		b, err := os.ReadFile(tokenFile)
		if err != nil {
			log.Fatalf("read token file: %v", err)
		}
		token = strings.TrimSpace(string(b))
	}
	if nodeID == "" || token == "" {
		log.Fatal("--node-id and --token or --token-file are required")
	}
	reporter, err := newAgentStatusReporter(rulesetState)
	if err != nil {
		log.Fatalf("initialize persistent local status generation: %v", err)
	}
	for {
		conn, _, err := websocket.DefaultDialer.Dial(serverURL, nil)
		if err != nil {
			log.Printf("control-plane unavailable: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}
		hello := Hello{NodeID: nodeID, Token: token, RulesetVersionGuard: true}
		if state, err := loadRulesetState(rulesetState); err == nil {
			hello.RulesetVersion = state.Version
			hello.RulesetHash = state.Hash
		}
		if err := conn.WriteJSON(Message{Type: "hello", Data: mustJSON(hello)}); err != nil {
			conn.Close()
			continue
		}
		var welcome Message
		if err := conn.ReadJSON(&welcome); err != nil || welcome.Type != "welcome" {
			conn.Close()
			time.Sleep(5 * time.Second)
			continue
		}
		log.Printf("connected to control-plane as %s", nodeID)
		if err := agentSession(conn, nodeID, usageFile, applyHook, rulesetState, reporter); err != nil {
			log.Printf("agent reconnect: %v", err)
		}
		conn.Close()
		time.Sleep(2 * time.Second)
	}
}

// Usage input is newline-delimited JSON Usage objects. Producers append only
// deltas, with a monotonic sequence per node/rule. Accepted entries are removed.
func agentSession(conn *websocket.Conn, nodeID, usageFile, applyHook, rulesetState string, reporter *agentStatusReporter) error {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	reportStatus := func() error {
		report := reporter.next()
		if err := conn.WriteJSON(Message{Type: "status_report", Data: mustJSON(report)}); err != nil {
			return err
		}
		var ack Message
		if err := conn.ReadJSON(&ack); err != nil {
			return err
		}
		if ack.Type != "status_ack" {
			return fmt.Errorf("unexpected status acknowledgement response: %s", ack.Type)
		}
		return nil
	}
	// Report immediately after authentication, then keep status and the existing
	// usage/command work on the same periodic tick.
	if err := reportStatus(); err != nil {
		return err
	}
	for {
		select {
		case <-tick.C:
			if err := reportStatus(); err != nil {
				return err
			}
			for _, u := range readUsage(usageFile, nodeID) {
				if err := conn.WriteJSON(Message{Type: "usage", Data: mustJSON(u)}); err != nil {
					return err
				}
				var ack Message
				if err := conn.ReadJSON(&ack); err != nil {
					return err
				}
				if ack.Type == "usage_ack" {
					markUsageAcked(usageFile, u)
				}
			}
			if err := conn.WriteJSON(Message{Type: "poll", Data: json.RawMessage(`{}`)}); err != nil {
				return err
			}
			var reply Message
			if err := conn.ReadJSON(&reply); err != nil {
				return err
			}
			if reply.Type == "commands" {
				var cs []Command
				_ = json.Unmarshal(reply.Data, &cs)
				for _, c := range cs {
					ok, detail := applyAgentCommand(applyHook, rulesetState, c)
					if err := conn.WriteJSON(Message{Type: "command_ack", Data: mustJSON(CommandAck{ID: c.ID, NodeID: nodeID, OK: ok, Detail: detail})}); err != nil {
						return err
					}
					var ack Message
					if err := conn.ReadJSON(&ack); err != nil {
						return err
					}
					if ack.Type != "command_ack" {
						return fmt.Errorf("unexpected command acknowledgement response: %s", ack.Type)
					}
				}
			}
		}
	}
}

func applyAgentCommand(hook, rulesetState string, c Command) (bool, string) {
	if c.Type == "apply_ruleset" {
		return applyPersistedRulesetCommand(rulesetState, c)
	}
	return applyCommand(hook, c)
}

// The controller cannot select a shell command. An operator may configure one
// reviewed local hook; it receives a structured Command object on stdin.
func applyCommand(hook string, c Command) (bool, string) {
	if hook == "" {
		return false, "no local apply hook configured"
	}
	payload, _ := json.Marshal(c)
	cmd := exec.Command(hook)
	cmd.Stdin = strings.NewReader(string(payload))
	out, err := cmd.CombinedOutput()
	detail := strings.TrimSpace(string(out))
	if len(detail) > 500 {
		detail = detail[:500]
	}
	if err != nil {
		if detail == "" {
			detail = err.Error()
		}
		return false, detail
	}
	return true, detail
}

func readUsage(path, nodeID string) []Usage {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []Usage
	for _, line := range strings.Split(string(b), "\n") {
		var u Usage
		if json.Unmarshal([]byte(line), &u) == nil && u.NodeID == nodeID {
			out = append(out, u)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].RuleID+fmt.Sprint(out[i].Sequence) < out[j].RuleID+fmt.Sprint(out[j].Sequence)
	})
	return out
}

func markUsageAcked(path string, accepted Usage) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var keep []string
	for _, line := range strings.Split(string(b), "\n") {
		var u Usage
		if json.Unmarshal([]byte(line), &u) == nil && u.NodeID == accepted.NodeID && u.RuleID == accepted.RuleID && u.Sequence == accepted.Sequence {
			continue
		}
		if strings.TrimSpace(line) != "" {
			keep = append(keep, line)
		}
	}
	_ = os.WriteFile(path, []byte(strings.Join(keep, "\n")+"\n"), 0600)
}

func main() {
	mode := flag.String("mode", "server", "server, agent, nft, nft-hook, restore, reconcile, admin, or systemd-render")
	addr := flag.String("listen", "127.0.0.1:8787", "server listen address")
	db := flag.String("db", "./ix-control.db", "sqlite database")
	url := flag.String("server", "", "control websocket URL")
	node := flag.String("node-id", "", "node ID")
	token := flag.String("token", "", "node token")
	tokenFile := flag.String("token-file", "", "0600 file containing node token")
	usage := flag.String("usage-file", "./usage.ndjson", "agent usage input")
	applyHook := flag.String("apply-hook", "", "absolute reviewed local command adapter")
	commandFile := flag.String("command-file", "", "structured apply_ruleset command JSON for nft mode")
	collectorState := flag.String("collector-state", "", "collector state file for nft mode")
	rulesetState := flag.String("ruleset-state", "/var/lib/ix-control/ruleset.json", "persisted authorized ruleset path")
	adminFile := flag.String("admin-file", "", "management request JSON for admin mode")
	systemdRole := flag.String("systemd-role", "", "systemd-render role: node or controller")
	systemdOutputDir := flag.String("systemd-output-dir", "", "deprecated; systemd-render only writes to stdout")
	systemdBinary := flag.String("systemd-binary", "/usr/local/bin/ix-control", "systemd-render ix-control binary path")
	systemdStateDir := flag.String("systemd-state-dir", SystemdStateDir, "systemd-render state directory")
	systemdDBDSN := flag.String("systemd-db-dsn", "file:/var/lib/ix-control/ix-control.db?_busy_timeout=5000&_journal_mode=WAL", "systemd-render SQLite file DSN")
	systemdTokenFileMode := flag.String("systemd-token-file-mode", "0600", "systemd-render declared token-file mode; must be 0600")
	flag.Parse()
	if *mode == "systemd-render" {
		if *systemdOutputDir != "" {
			log.Fatal("--systemd-output-dir is not supported; systemd-render only writes to stdout")
		}
		tokenMode, err := ParseSystemdTokenFileMode(*systemdTokenFileMode)
		if err != nil {
			log.Fatal(err)
		}
		in := SystemdRenderInput{
			BinaryPath:    *systemdBinary,
			NodeID:        *node,
			ServerURL:     *url,
			TokenFile:     *tokenFile,
			TokenFileMode: tokenMode,
			StateDir:      *systemdStateDir,
			DatabaseDSN:   *systemdDBDSN,
		}
		if err := GenerateSystemdTemplates(SystemdRole(*systemdRole), in, "", os.Stdout); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *mode == "server" {
		runServer(*addr, *db)
		return
	}
	if *mode == "agent" {
		runAgent(*url, *node, *token, *tokenFile, *usage, *applyHook, *rulesetState)
		return
	}
	if *mode == "nft" {
		runNFTTool(*commandFile, *collectorState, *usage, *node)
		return
	}
	if *mode == "nft-hook" {
		runNFTHook(*rulesetState)
		return
	}
	if *mode == "restore" {
		if err := restoreRuleset(*rulesetState); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *mode == "reconcile" {
		runReconcile(*db)
		return
	}
	if *mode == "admin" {
		runAdmin(*db, *adminFile)
		return
	}
	log.Fatal("--mode must be server, agent, nft, nft-hook, restore, reconcile, admin, or systemd-render")
}
