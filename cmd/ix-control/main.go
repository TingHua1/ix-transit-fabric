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

const protocolVersion = 1

type Message struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data,omitempty"`
}

type Hello struct {
	NodeID string `json:"node_id"`
	Token  string `json:"token"`
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
	ID     string          `json:"id"`
	NodeID string          `json:"node_id"`
	Type   string          `json:"type"`
	Body   json.RawMessage `json:"body"`
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
	must(os.MkdirAll(filepath.Dir(path), 0700))
	db, err := sql.Open("sqlite3", path+"?_busy_timeout=5000&_journal_mode=WAL")
	must(err)
	must(db.Ping())
	must(initSchema(db))
	return db
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
  detail TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  acknowledged_at INTEGER NOT NULL DEFAULT 0
);
`)
	return err
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
			result, err := s.db.Exec(`UPDATE commands SET state=?, detail=?, acknowledged_at=? WHERE id=? AND node_id=? AND state='pending'`, state, a.Detail, time.Now().Unix(), a.ID, hello.NodeID)
			if err != nil {
				_ = conn.WriteJSON(Message{Type: "error", Data: json.RawMessage(`"command acknowledgement failed"`)})
				continue
			}
			n, _ := result.RowsAffected()
			_ = conn.WriteJSON(Message{Type: "command_ack", Data: mustJSON(map[string]any{"id": a.ID, "accepted": n == 1})})
		default:
			_ = conn.WriteJSON(Message{Type: "error", Data: json.RawMessage(`"unknown message"`)})
		}
	}
}

func (s *Server) pendingCommands(nodeID string) ([]Command, error) {
	rows, err := s.db.Query(`SELECT id,node_id,type,body FROM commands WHERE node_id=? AND state='pending' ORDER BY created_at,id LIMIT 100`, nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Command
	for rows.Next() {
		var c Command
		var body string
		if err := rows.Scan(&c.ID, &c.NodeID, &c.Type, &body); err != nil {
			return nil, err
		}
		c.Body = json.RawMessage(body)
		out = append(out, c)
	}
	return out, rows.Err()
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

func runAgent(serverURL, nodeID, token, tokenFile, usageFile, applyHook string) {
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
	for {
		conn, _, err := websocket.DefaultDialer.Dial(serverURL, nil)
		if err != nil {
			log.Printf("control-plane unavailable: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}
		if err := conn.WriteJSON(Message{Type: "hello", Data: mustJSON(Hello{NodeID: nodeID, Token: token})}); err != nil {
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
		if err := agentSession(conn, nodeID, usageFile, applyHook); err != nil {
			log.Printf("agent reconnect: %v", err)
		}
		conn.Close()
		time.Sleep(2 * time.Second)
	}
}

// Usage input is newline-delimited JSON Usage objects. Producers append only
// deltas, with a monotonic sequence per node/rule. Accepted entries are removed.
func agentSession(conn *websocket.Conn, nodeID, usageFile, applyHook string) error {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
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
					ok, detail := applyCommand(applyHook, c)
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
	mode := flag.String("mode", "server", "server, agent, nft, nft-hook, or admin")
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
	adminFile := flag.String("admin-file", "", "management request JSON for admin mode")
	flag.Parse()
	if *mode == "server" {
		runServer(*addr, *db)
		return
	}
	if *mode == "agent" {
		runAgent(*url, *node, *token, *tokenFile, *usage, *applyHook)
		return
	}
	if *mode == "nft" {
		runNFTTool(*commandFile, *collectorState, *usage, *node)
		return
	}
	if *mode == "nft-hook" {
		runNFTHook()
		return
	}
	if *mode == "admin" {
		runAdmin(*db, *adminFile)
		return
	}
	log.Fatal("--mode must be server, agent, nft, nft-hook, or admin")
}
