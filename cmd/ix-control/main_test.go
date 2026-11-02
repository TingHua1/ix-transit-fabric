package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
)

func TestMigrateNodeStatusGenerationSchemas(t *testing.T) {
	tests := []struct {
		name        string
		legacyDDL   string
		report      string
		wantMigrate bool
	}{
		{name: "no table"},
		{name: "initial", legacyDDL: `CREATE TABLE node_status (node_id TEXT PRIMARY KEY, boot_id TEXT NOT NULL, sequence INTEGER NOT NULL, received_at INTEGER NOT NULL, report TEXT NOT NULL)`, report: `{"boot_id":"boot"}`, wantMigrate: true},
		{name: "boot epoch", legacyDDL: `CREATE TABLE node_status (node_id TEXT PRIMARY KEY, boot_id TEXT NOT NULL, boot_epoch INTEGER NOT NULL, sequence INTEGER NOT NULL, received_at INTEGER NOT NULL, report TEXT NOT NULL)`, report: `{"boot_id":"boot","boot_epoch":9}`, wantMigrate: true},
		{name: "generation", legacyDDL: `CREATE TABLE node_status (node_id TEXT PRIMARY KEY, boot_id TEXT NOT NULL, generation INTEGER NOT NULL, sequence INTEGER NOT NULL, received_at INTEGER NOT NULL, report TEXT NOT NULL)`, report: `{"boot_id":"boot","generation":7}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "controller.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if tt.legacyDDL != "" {
				if _, err := db.Exec(tt.legacyDDL); err != nil {
					t.Fatal(err)
				}
				if strings.Contains(tt.legacyDDL, "boot_epoch") {
					_, err = db.Exec(`INSERT INTO node_status(node_id,boot_id,boot_epoch,sequence,received_at,report) VALUES('node','boot',9,3,4,?)`, tt.report)
				} else if strings.Contains(tt.legacyDDL, "generation") {
					_, err = db.Exec(`INSERT INTO node_status(node_id,boot_id,generation,sequence,received_at,report) VALUES('node','boot',7,3,4,?)`, tt.report)
				} else {
					_, err = db.Exec(`INSERT INTO node_status(node_id,boot_id,sequence,received_at,report) VALUES('node','boot',3,4,?)`, tt.report)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := initSchema(db); err != nil {
				t.Fatal(err)
			}
			columns := nodeStatusColumns(t, db)
			if !columns["generation"] || columns["boot_epoch"] {
				t.Fatalf("node_status columns after migration: %#v", columns)
			}
			if !tt.wantMigrate {
				if tt.name == "generation" {
					var generation int64
					var report string
					if err := db.QueryRow(`SELECT generation,report FROM node_status WHERE node_id='node'`).Scan(&generation, &report); err != nil {
						t.Fatal(err)
					}
					if generation != 7 || report != tt.report {
						t.Fatalf("generation schema was unexpectedly rewritten: generation=%d report=%q", generation, report)
					}
				}
				return
			}
			var generation, sequence, receivedAt int64
			var report string
			if err := db.QueryRow(`SELECT generation,sequence,received_at,report FROM node_status WHERE node_id='node'`).Scan(&generation, &sequence, &receivedAt, &report); err != nil {
				t.Fatal(err)
			}
			if generation != 0 || sequence != 3 || receivedAt != 4 {
				t.Fatalf("migrated row = generation %d, sequence %d, received_at %d", generation, sequence, receivedAt)
			}
			var payload map[string]any
			if err := json.Unmarshal([]byte(report), &payload); err != nil {
				t.Fatal(err)
			}
			if payload["generation"] != float64(0) || payload["boot_epoch"] != nil {
				t.Fatalf("migrated report = %#v", payload)
			}
			if _, err := db.Exec(`INSERT INTO node_status(node_id,boot_id,generation,sequence,received_at,report) VALUES('node','other',0,1,1,'{}')`); err == nil {
				t.Fatal("node_status primary-key constraint was not retained")
			}
		})
	}
}

func TestGetNodeStatusReadsMigratedGenerationZero(t *testing.T) {
	for _, tt := range []struct {
		name      string
		legacyDDL string
		bootEpoch bool
	}{
		{name: "initial", legacyDDL: `CREATE TABLE node_status (node_id TEXT PRIMARY KEY, boot_id TEXT NOT NULL, sequence INTEGER NOT NULL, received_at INTEGER NOT NULL, report TEXT NOT NULL)`},
		{name: "boot epoch", legacyDDL: `CREATE TABLE node_status (node_id TEXT PRIMARY KEY, boot_id TEXT NOT NULL, boot_epoch INTEGER NOT NULL, sequence INTEGER NOT NULL, received_at INTEGER NOT NULL, report TEXT NOT NULL)`, bootEpoch: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "controller.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if _, err := db.Exec(tt.legacyDDL); err != nil {
				t.Fatal(err)
			}
			report := testStatus(3)
			payload := map[string]any{}
			if err := json.Unmarshal(mustJSON(report), &payload); err != nil {
				t.Fatal(err)
			}
			delete(payload, "generation")
			if tt.bootEpoch {
				payload["boot_epoch"] = 9
			}
			raw, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			if tt.bootEpoch {
				_, err = db.Exec(`INSERT INTO node_status(node_id,boot_id,boot_epoch,sequence,received_at,report) VALUES(?,?,?,?,?,?)`, "node", report.BootID, 9, report.Sequence, 4, string(raw))
			} else {
				_, err = db.Exec(`INSERT INTO node_status(node_id,boot_id,sequence,received_at,report) VALUES(?,?,?,?,?)`, "node", report.BootID, report.Sequence, 4, string(raw))
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := initSchema(db); err != nil {
				t.Fatal(err)
			}
			status, err := (&Server{db: db}).GetNodeStatus("node")
			if err != nil {
				t.Fatal(err)
			}
			if status.Generation != 0 || status.Sequence != report.Sequence || status.BootID != report.BootID {
				t.Fatalf("migrated status = %#v", status)
			}
		})
	}
}

func nodeStatusColumns(t *testing.T, db *sql.DB) map[string]bool {
	t.Helper()
	rows, err := db.Query(`PRAGMA table_info(node_status)`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	columns := make(map[string]bool)
	for rows.Next() {
		var cid, notNull, pk int
		var name, typ string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
			t.Fatal(err)
		}
		columns[name] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return columns
}

func TestOpenDBAcceptsRenderedControllerDSNWithQuery(t *testing.T) {
	in := validNodeSystemdInput()
	in.DatabaseDSN = "file:/var/lib/ix-control/controller-test.db?cache=shared&_busy_timeout=123&_journal_mode=WAL"
	unit, err := RenderSystemdTemplate(serverUnit, in)
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(unit, "--db ")
	if start < 0 {
		t.Fatalf("controller unit lacks DB argument: %s", unit)
	}
	dsn := strings.Fields(unit[start:])[1]
	db := openDB(dsn)
	u, err := url.Parse(dsn)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		_ = os.Remove(u.Path)
		for dir := filepath.Dir(u.Path); dir != "." && dir != string(filepath.Separator); dir = filepath.Dir(dir) {
			if err := os.Remove(dir); err != nil {
				break
			}
		}
	})
	if strings.Count(sqliteDSNForTest(dsn), "?") != 1 {
		t.Fatalf("DSN has repeated query separator: %s", sqliteDSNForTest(dsn))
	}
	for _, want := range []string{"cache=shared", "_busy_timeout=123", "_journal_mode=WAL"} {
		if !strings.Contains(sqliteDSNForTest(dsn), want) {
			t.Fatalf("DB defaults/options missing %q from %s", want, sqliteDSNForTest(dsn))
		}
	}
}

func sqliteDSNForTest(dsn string) string { got, _ := sqliteDSN(dsn); return got }

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
