package main

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
)

func TestWebSocketUsageIsIdempotentAndCommandsAck(t *testing.T) {
	db, err := sql.Open("sqlite3", "file:ixcontroltest?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := initSchema(db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO nodes(node_id,token) VALUES('soy-ix','test-token')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO commands(id,node_id,type,body,created_at) VALUES('cmd-1','soy-ix','disable_rule','{}',1)`); err != nil {
		t.Fatal(err)
	}

	s := &Server{db: db, upgrader: websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}}
	h := httptest.NewServer(http.HandlerFunc(s.ws))
	defer h.Close()
	wsURL := "ws" + strings.TrimPrefix(h.URL, "http")
	c, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.WriteJSON(Message{Type: "hello", Data: mustJSON(Hello{NodeID: "soy-ix", Token: "test-token", RulesetVersionGuard: true})}); err != nil {
		t.Fatal(err)
	}
	var got Message
	if err := c.ReadJSON(&got); err != nil || got.Type != "welcome" {
		t.Fatalf("welcome: %#v, %v", got, err)
	}

	u := Usage{NodeID: "soy-ix", RuleID: "r1", Sequence: 1, UpBytes: 12, DownBytes: 345}
	for i := 0; i < 2; i++ {
		if err := c.WriteJSON(Message{Type: "usage", Data: mustJSON(u)}); err != nil {
			t.Fatal(err)
		}
		if err := c.ReadJSON(&got); err != nil || got.Type != "usage_ack" {
			t.Fatalf("usage ack: %#v, %v", got, err)
		}
	}
	var count, up, down int64
	if err := db.QueryRow(`SELECT count(*),sum(up_bytes),sum(down_bytes) FROM usage_events`).Scan(&count, &up, &down); err != nil {
		t.Fatal(err)
	}
	if count != 1 || up != 12 || down != 345 {
		t.Fatalf("ledger count=%d up=%d down=%d", count, up, down)
	}

	if err := c.WriteJSON(Message{Type: "poll", Data: []byte(`{}`)}); err != nil {
		t.Fatal(err)
	}
	if err := c.ReadJSON(&got); err != nil || got.Type != "commands" {
		t.Fatalf("commands: %#v %v", got, err)
	}
	if err := c.WriteJSON(Message{Type: "command_ack", Data: mustJSON(CommandAck{ID: "cmd-1", NodeID: "soy-ix", OK: true, Detail: "applied"})}); err != nil {
		t.Fatal(err)
	}
	if err := c.ReadJSON(&got); err != nil || got.Type != "command_ack" {
		t.Fatalf("command ack confirmation: %#v %v", got, err)
	}
	var state string
	if err := db.QueryRow(`SELECT state FROM commands WHERE id='cmd-1'`).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "done" {
		t.Fatalf("command state %q", state)
	}
}

func TestWebSocketRejectsAgentWithoutRulesetVersionGuard(t *testing.T) {
	db, err := sql.Open("sqlite3", "file:ixcontrolcapabilitytest?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := initSchema(db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO nodes(node_id,token) VALUES('node','token'); INSERT INTO commands(id,node_id,type,body,created_at) VALUES('command','node','apply_ruleset','{}',1)`); err != nil {
		t.Fatal(err)
	}

	s := &Server{db: db, upgrader: websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}}
	h := httptest.NewServer(http.HandlerFunc(s.ws))
	defer h.Close()
	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(h.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.WriteJSON(Message{Type: "hello", Data: mustJSON(Hello{NodeID: "node", Token: "token"})}); err != nil {
		t.Fatal(err)
	}
	var reply Message
	if err := c.ReadJSON(&reply); err != nil {
		t.Fatal(err)
	}
	if reply.Type != "error" || !strings.Contains(string(reply.Data), "ruleset_version_guard") {
		t.Fatalf("expected capability error, got %#v", reply)
	}
	if err := c.ReadJSON(&reply); err == nil {
		t.Fatalf("rejected agent unexpectedly received %#v", reply)
	}
}

func TestPendingCommandsRespectDependenciesAndPropagateFailure(t *testing.T) {
	db, err := sql.Open("sqlite3", "file:ixcontroldepstest?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := initSchema(db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO commands(id,node_id,type,body,depends_on,created_at) VALUES
('transit','t','apply_ruleset','{}','[]',1),
('ingress','i','apply_ruleset','{}','["transit"]',2)`); err != nil {
		t.Fatal(err)
	}
	s := &Server{db: db}
	if got, err := s.pendingCommands("i"); err != nil || len(got) != 0 {
		t.Fatalf("dependent ingress leaked: %#v %v", got, err)
	}
	if ok, err := s.ackCommand("t", "transit", "failed", "nft failed"); err != nil || !ok {
		t.Fatalf("ack: %v %v", ok, err)
	}
	var state string
	if err := db.QueryRow(`SELECT state FROM commands WHERE id='ingress'`).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "cancelled" {
		t.Fatalf("ingress state=%q", state)
	}
}

func TestSupersededDependencyPropagatesAcrossNodes(t *testing.T) {
	db, err := sql.Open("sqlite3", "file:ixcontrolsupersedetest?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := initSchema(db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO commands(id,node_id,type,body,depends_on,created_at) VALUES
('transit','t','apply_ruleset','{}','[]',1),
('ingress','i','apply_ruleset','{}','["transit"]',2)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE commands SET state='superseded' WHERE id='transit'`); err != nil {
		t.Fatal(err)
	}
	s := &Server{db: db}
	if _, err := s.pendingCommands("i"); err != nil {
		t.Fatal(err)
	}
	var state string
	if err := db.QueryRow(`SELECT state FROM commands WHERE id='ingress'`).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "superseded" {
		t.Fatalf("ingress state=%q", state)
	}
}

func TestAckRejectsTerminalAndInvalidStates(t *testing.T) {
	db, err := sql.Open("sqlite3", "file:ixcontrolackstates?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := initSchema(db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO commands(id,node_id,type,body,state,created_at) VALUES('done','n','x','{}','done',1)`); err != nil {
		t.Fatal(err)
	}
	s := &Server{db: db}
	if accepted, err := s.ackCommand("n", "done", "done", "again"); err != nil || accepted {
		t.Fatalf("terminal ack accepted=%v err=%v", accepted, err)
	}
	if accepted, err := s.ackCommand("n", "done", "cancelled", "bad"); err == nil || accepted {
		t.Fatalf("invalid ack accepted=%v err=%v", accepted, err)
	}
}
