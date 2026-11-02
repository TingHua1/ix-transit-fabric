package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func testStatus(sequence int64) StatusReport {
	return StatusReport{
		AgentVersion:          "test-agent/1",
		BootID:                "0123456789abcdef0123456789abcdef",
		Generation:            1,
		Sequence:              sequence,
		ReportedAt:            time.Now().Unix(),
		AppliedRulesetVersion: 1,
		AppliedRulesetHash:    strings.Repeat("a", 64),
		ControlTable:          "unknown",
		EasyTier:              EasyTierStatus{State: "unknown", Detail: "not collected"},
		Tun0:                  TunStatus{},
		Peers:                 PeerSummary{State: "unknown"},
		Error:                 StatusErrorSummary{Code: "none"},
	}
}

func newStatusTestServer(t *testing.T) (*sql.DB, *httptest.Server) {
	t.Helper()
	db, err := sql.Open("sqlite3", "file:"+strings.ReplaceAll(t.Name(), "/", "_")+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	if err := initSchema(db); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO nodes(node_id,token) VALUES('node','token')`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	s := &Server{db: db, upgrader: websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}}
	return db, httptest.NewServer(http.HandlerFunc(s.ws))
}

func openStatusSocket(t *testing.T, h *httptest.Server) *websocket.Conn {
	t.Helper()
	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(h.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.WriteJSON(Message{Type: "hello", Data: mustJSON(Hello{NodeID: "node", Token: "token", RulesetVersionGuard: true})}); err != nil {
		c.Close()
		t.Fatal(err)
	}
	var reply Message
	if err := c.ReadJSON(&reply); err != nil || reply.Type != "welcome" {
		c.Close()
		t.Fatalf("welcome: %#v, %v", reply, err)
	}
	return c
}

func TestWebSocketStatusUpdatesAndRejectsOldSequence(t *testing.T) {
	db, h := newStatusTestServer(t)
	defer db.Close()
	defer h.Close()
	c := openStatusSocket(t, h)
	defer c.Close()

	first := testStatus(2)
	first.EasyTier.State = "running"
	for _, report := range []StatusReport{first, testStatus(1)} {
		if err := c.WriteJSON(Message{Type: "status_report", Data: mustJSON(report)}); err != nil {
			t.Fatal(err)
		}
		var ack Message
		if err := c.ReadJSON(&ack); err != nil || ack.Type != "status_ack" {
			t.Fatalf("status acknowledgement: %#v, %v", ack, err)
		}
	}
	var stored StatusReport
	var raw string
	if err := db.QueryRow(`SELECT report FROM node_status WHERE node_id='node'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(raw), &stored); err != nil {
		t.Fatal(err)
	}
	if stored.Sequence != 2 || stored.EasyTier.State != "running" {
		t.Fatalf("old sequence overwrote stored status: %#v", stored)
	}
}

func TestWebSocketStatusRejectsInvalidFields(t *testing.T) {
	db, h := newStatusTestServer(t)
	defer db.Close()
	defer h.Close()
	c := openStatusSocket(t, h)
	defer c.Close()
	report := testStatus(1)
	report.Tun0 = TunStatus{Exists: true, IP: "not-an-ip"}
	if err := c.WriteJSON(Message{Type: "status_report", Data: mustJSON(report)}); err != nil {
		t.Fatal(err)
	}
	var reply Message
	if err := c.ReadJSON(&reply); err != nil || reply.Type != "error" {
		t.Fatalf("invalid report result: %#v, %v", reply, err)
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM node_status`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("invalid report persisted: n=%d err=%v", n, err)
	}
}

func TestWebSocketStatusRejectsFarFutureAndUnknownNestedFields(t *testing.T) {
	db, h := newStatusTestServer(t)
	defer db.Close()
	defer h.Close()
	c := openStatusSocket(t, h)
	defer c.Close()

	future := testStatus(1)
	future.ReportedAt = time.Now().Add(maxStatusReportedAtFutureSkew + time.Minute).Unix()
	for _, payload := range []json.RawMessage{
		mustJSON(future),
		json.RawMessage(`{"agent_version":"test-agent/1","boot_id":"0123456789abcdef0123456789abcdef","generation":1,"sequence":2,"reported_at":1,"applied_ruleset_version":1,"applied_ruleset_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","control_table":"unknown","collector_last_success":0,"easytier":{"state":"unknown","detail":"not collected","unexpected":true},"tun0":{"exists":false,"ip":"","rx_bytes":0,"tx_bytes":0},"peers":{"state":"unknown","connected":0,"total":0},"error":{"code":"none","detail":""}}`),
	} {
		if err := c.WriteJSON(Message{Type: "status_report", Data: payload}); err != nil {
			t.Fatal(err)
		}
		var reply Message
		if err := c.ReadJSON(&reply); err != nil || reply.Type != "error" {
			t.Fatalf("invalid report result: %#v, %v", reply, err)
		}
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM node_status`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("invalid report persisted: n=%d err=%v", n, err)
	}
}

func TestDecodeStatusReportRejectsGenerationZeroOnWire(t *testing.T) {
	report := testStatus(1)
	report.Generation = 0
	if _, err := decodeStatusReport(mustJSON(report)); err == nil {
		t.Fatal("generation-zero wire status unexpectedly accepted")
	}
}

func TestNodeStatusOnlineUsesReceivedAt(t *testing.T) {
	now := time.Unix(1_000, 0)
	if !NodeStatusOnline(NodeStatus{ReceivedAt: 971}, now, 30*time.Second) {
		t.Fatal("status at timeout boundary should be online")
	}
	if NodeStatusOnline(NodeStatus{ReceivedAt: 969}, now, 30*time.Second) {
		t.Fatal("old status should be offline")
	}
}

func TestStatusReporterIsSharedAcrossReconnectSessions(t *testing.T) {
	reporter, err := newAgentStatusReporter(filepath.Join(t.TempDir(), "ruleset.json"))
	if err != nil {
		t.Fatal(err)
	}
	first := reporter.next()
	// A session only receives a reporter; reconnecting must not allocate a new
	// boot ID or reset its sequence.
	second := reporter.next()
	if first.BootID != second.BootID || first.Generation != second.Generation || second.Sequence != first.Sequence+1 {
		t.Fatalf("reporter reset across sessions: first=%#v second=%#v", first, second)
	}
}

func TestRecordStatusOrdersNewBootAndRejectsOldSession(t *testing.T) {
	db, err := sql.Open("sqlite3", "file:statusbootordertest?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := initSchema(db); err != nil {
		t.Fatal(err)
	}
	s := &Server{db: db}
	old := testStatus(8)
	old.Generation = 10
	if accepted, err := s.recordStatus("node", old); err != nil || !accepted {
		t.Fatalf("initial status accepted=%v err=%v", accepted, err)
	}
	newer := testStatus(1)
	newer.BootID = "fedcba9876543210fedcba9876543210"
	newer.Generation = 11
	if accepted, err := s.recordStatus("node", newer); err != nil || !accepted {
		t.Fatalf("new boot accepted=%v err=%v", accepted, err)
	}
	old.Sequence = 9
	if accepted, err := s.recordStatus("node", old); err != nil || accepted {
		t.Fatalf("old session overwrote new boot: accepted=%v err=%v", accepted, err)
	}
	stored, err := s.GetNodeStatus("node")
	if err != nil {
		t.Fatal(err)
	}
	if stored.BootID != newer.BootID || stored.Sequence != newer.Sequence {
		t.Fatalf("stored old boot after ordering check: %#v", stored)
	}
}

func TestRecordStatusHigherGenerationSupersedesMigratedStatus(t *testing.T) {
	db, err := sql.Open("sqlite3", "file:statusmigratedgenerationordertest?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := initSchema(db); err != nil {
		t.Fatal(err)
	}
	s := &Server{db: db}
	migrated := testStatus(100)
	migrated.Generation = 0
	raw, err := json.Marshal(migrated)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO node_status(node_id,boot_id,generation,sequence,received_at,report) VALUES(?,?,?,?,?,?)`, "node", migrated.BootID, migrated.Generation, migrated.Sequence, time.Now().Unix(), string(raw)); err != nil {
		t.Fatal(err)
	}

	current := testStatus(1)
	if accepted, err := s.recordStatus("node", current); err != nil || !accepted {
		t.Fatalf("generation-one status accepted=%v err=%v", accepted, err)
	}
	stored, err := s.GetNodeStatus("node")
	if err != nil {
		t.Fatal(err)
	}
	if stored.Generation != current.Generation || stored.Sequence != current.Sequence || stored.BootID != current.BootID {
		t.Fatalf("higher generation did not supersede migrated status: %#v", stored)
	}
}

func TestPersistentGenerationOrdersBootsWithoutWallClock(t *testing.T) {
	state := filepath.Join(t.TempDir(), "ruleset.json")
	oldReporter, err := newAgentStatusReporter(state)
	if err != nil {
		t.Fatal(err)
	}
	newReporter, err := newAgentStatusReporter(state)
	if err != nil {
		t.Fatal(err)
	}
	old := oldReporter.next()
	newer := newReporter.next()
	if old.Generation != 1 || newer.Generation != 2 {
		t.Fatalf("generations = %d, %d; want 1, 2", old.Generation, newer.Generation)
	}
	generationFile := state + ".status-generation"
	info, err := os.Stat(generationFile)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatalf("generation state mode = %04o, want 0600", info.Mode().Perm())
	}
	contents, err := os.ReadFile(generationFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(contents)), "token") {
		t.Fatalf("generation state must not contain token material: %q", contents)
	}
	// Deliberately make diagnostics look like the wall clock moved backwards.
	// Ordering must still be exclusively generation-based.
	old.ReportedAt = 9_999_999
	newer.ReportedAt = 1
	db, err := sql.Open("sqlite3", "file:statusgenerationordertest?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := initSchema(db); err != nil {
		t.Fatal(err)
	}
	s := &Server{db: db}
	if accepted, err := s.recordStatus("node", old); err != nil || !accepted {
		t.Fatalf("old generation accepted=%v err=%v", accepted, err)
	}
	if accepted, err := s.recordStatus("node", newer); err != nil || !accepted {
		t.Fatalf("new generation accepted=%v err=%v", accepted, err)
	}
	old.Sequence++
	if accepted, err := s.recordStatus("node", old); err != nil || accepted {
		t.Fatalf("delayed old generation accepted=%v err=%v", accepted, err)
	}
	stored, err := s.GetNodeStatus("node")
	if err != nil {
		t.Fatal(err)
	}
	if stored.Generation != newer.Generation || stored.BootID != newer.BootID {
		t.Fatalf("stored status was overwritten by old generation: %#v", stored)
	}
}

func TestStatusGenerationCreatesMissingParentAndIgnoresLegacyLock(t *testing.T) {
	state := filepath.Join(t.TempDir(), "new", "state", "ruleset.json")
	reporter, err := newAgentStatusReporter(state)
	if err != nil {
		t.Fatal(err)
	}
	if got := reporter.next().Generation; got != 1 {
		t.Fatalf("generation = %d, want 1", got)
	}

	legacyState := filepath.Join(t.TempDir(), "ruleset.json")
	legacyLock := legacyState + ".status-generation.lock"
	if err := os.WriteFile(legacyLock, []byte("stale legacy lock"), 0600); err != nil {
		t.Fatal(err)
	}
	legacyReporter, err := newAgentStatusReporter(legacyState)
	if err != nil {
		t.Fatal(err)
	}
	if got := legacyReporter.next().Generation; got != 1 {
		t.Fatalf("generation with legacy lock = %d, want 1", got)
	}
	if _, err := os.Stat(legacyLock); err != nil {
		t.Fatalf("legacy lock was unexpectedly removed: %v", err)
	}
}

func TestStatusGenerationConcurrentReportersDoNotRepeat(t *testing.T) {
	state := filepath.Join(t.TempDir(), "ruleset.json")
	const reporters = 24
	results := make(chan int64, reporters)
	errs := make(chan error, reporters)
	var wg sync.WaitGroup
	for range reporters {
		wg.Add(1)
		go func() {
			defer wg.Done()
			reporter, err := newAgentStatusReporter(state)
			if err != nil {
				errs <- err
				return
			}
			results <- reporter.generation
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	seen := make(map[int64]bool, reporters)
	for generation := range results {
		if generation < 1 || generation > reporters || seen[generation] {
			t.Fatalf("duplicate or invalid generation %d", generation)
		}
		seen[generation] = true
	}
	if len(seen) != reporters {
		t.Fatalf("got %d generations, want %d", len(seen), reporters)
	}
}

func TestStatusGenerationStateFailuresAreReturned(t *testing.T) {
	if _, err := newAgentStatusReporter(""); err == nil {
		t.Fatal("empty ruleset state path unexpectedly accepted")
	}
	state := filepath.Join(t.TempDir(), "ruleset.json")
	if err := os.WriteFile(state+".status-generation", []byte(`{"generation":0}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := newAgentStatusReporter(state); err == nil {
		t.Fatal("invalid persistent generation unexpectedly accepted")
	}
}
