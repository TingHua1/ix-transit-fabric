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
	if err := c.WriteJSON(Message{Type: "hello", Data: mustJSON(Hello{NodeID: "soy-ix", Token: "test-token"})}); err != nil {
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
