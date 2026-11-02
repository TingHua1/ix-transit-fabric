package main

import (
	"database/sql"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func testManagementDB(t *testing.T, name string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", "file:"+name+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	if err := initSchema(db); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := initManagementSchema(db); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO users VALUES('u1',1,0,0,'both'); INSERT INTO node_config VALUES('ing','ingress',''),('tran','transit','10.9.0.2');`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	return db
}

func testLink(id string, clientPort, transitPort uint16) LinkSpec {
	return LinkSpec{ID: id, UserID: "u1", Enabled: true, Protocol: "tcp", ClientPort: clientPort, IngressNodeID: "ing", IngressPublicIP: "203.0.113.2", TransitNodeID: "tran", TransitEasyIP: "10.9.0.2", TransitPort: transitPort, LandingIP: "192.0.2.10", LandingPort: 443}
}

func latestRuleset(t *testing.T, db *sql.DB, nodeID string) Ruleset {
	t.Helper()
	var body string
	if err := db.QueryRow(`SELECT body FROM commands WHERE node_id=? ORDER BY rowid DESC LIMIT 1`, nodeID).Scan(&body); err != nil {
		t.Fatal(err)
	}
	var rs Ruleset
	if err := json.Unmarshal([]byte(body), &rs); err != nil {
		t.Fatal(err)
	}
	return rs
}

func TestActiveUserHonorsExpiryAndQuota(t *testing.T) {
	db, err := sql.Open("sqlite3", "file:ixcontroladmin?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := initSchema(db); err != nil {
		t.Fatal(err)
	}
	if err := initManagementSchema(db); err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO users(user_id,enabled,expires_at,quota_bytes,billing_mode) VALUES('u1',1,0,100,'both'); INSERT INTO managed_rules(rule_id,node_id,user_id,enabled,protocol,listen_port,target_ip,target_port) VALUES('r1','n1','u1',1,'tcp',30000,'1.1.1.1',443); INSERT INTO usage_events(node_id,rule_id,sequence,up_bytes,down_bytes,at) VALUES('n1','r1',1,40,60,1);`)
	if err != nil {
		t.Fatal(err)
	}
	active, err := activeUser(db, "u1", time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	if active {
		t.Fatal("quota reached user must be inactive")
	}
	if _, err := db.Exec(`UPDATE users SET quota_bytes=101`); err != nil {
		t.Fatal(err)
	}
	active, err = activeUser(db, "u1", time.Now().Unix())
	if err != nil || !active {
		t.Fatalf("quota below limit should be active: %v", err)
	}
	if _, err := db.Exec(`UPDATE users SET expires_at=?`, time.Now().Add(-time.Second).Unix()); err != nil {
		t.Fatal(err)
	}
	active, err = activeUser(db, "u1", time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	if active {
		t.Fatal("expired user must be inactive")
	}
}

func TestSyncNodeQueuesOnlyActiveRules(t *testing.T) {
	db, err := sql.Open("sqlite3", "file:ixcontrolsync?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := initSchema(db); err != nil {
		t.Fatal(err)
	}
	if err := initManagementSchema(db); err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO users VALUES('ok',1,0,0,'both'),('off',0,0,0,'both'); INSERT INTO node_config VALUES('n1','ingress',''); INSERT INTO managed_rules(rule_id,node_id,user_id,enabled,protocol,listen_port,target_ip,target_port,match_daddr,description) VALUES('a','n1','ok',1,'tcp',31001,'1.1.1.1',443,'',''),('b','n1','off',1,'tcp',31002,'2.2.2.2',443,'','');`)
	if err != nil {
		t.Fatal(err)
	}
	if err := syncNode(db, "n1"); err != nil {
		t.Fatal(err)
	}
	var body string
	if err := db.QueryRow(`SELECT body FROM commands WHERE node_id='n1'`).Scan(&body); err != nil {
		t.Fatal(err)
	}
	var rs Ruleset
	if err := json.Unmarshal([]byte(body), &rs); err != nil {
		t.Fatal(err)
	}
	if len(rs.Rules) != 1 || rs.Rules[0].ID != "a" {
		t.Fatalf("unexpected active rules: %#v", rs.Rules)
	}
}

func TestLinkAggregationAndTwoNodeExpansion(t *testing.T) {
	db := testManagementDB(t, "ixcontrollinksaggregate")
	defer db.Close()
	if err := upsertLink(db, testLink("l1", 32001, 42001)); err != nil {
		t.Fatal(err)
	}
	if err := upsertLink(db, testLink("l2", 32002, 42002)); err != nil {
		t.Fatal(err)
	}
	ingress := latestRuleset(t, db, "ing")
	if ingress.Role != "ingress" || len(ingress.Rules) != 2 || ingress.Rules[0].ID != "l1" || ingress.Rules[1].ID != "l2" || ingress.Rules[0].TargetIP != "10.9.0.2" || ingress.Rules[0].MatchDAddr != "203.0.113.2" {
		t.Fatalf("unexpected ingress ruleset: %#v", ingress)
	}
	transit := latestRuleset(t, db, "tran")
	if transit.Role != "transit" || len(transit.Rules) != 2 || transit.Rules[0].ID != "t-l1" || transit.Rules[1].ID != "t-l2" || transit.Rules[0].TargetIP != "192.0.2.10" {
		t.Fatalf("unexpected transit ruleset: %#v", transit)
	}
}

func TestLinkInactiveUsersDoNotGenerateRules(t *testing.T) {
	db := testManagementDB(t, "ixcontrollinksinactive")
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO users VALUES('off',0,0,0,'both'),('expired',1,1,0,'both'),('full',1,0,10,'both');`); err != nil {
		t.Fatal(err)
	}
	links := []LinkSpec{testLink("off-link", 32101, 42101), testLink("expired-link", 32102, 42102), testLink("full-link", 32103, 42103)}
	links[0].UserID, links[1].UserID, links[2].UserID = "off", "expired", "full"
	for _, l := range links {
		if err := upsertLink(db, l); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`INSERT INTO usage_events VALUES('ing','full-link',1,5,5,1)`); err != nil {
		t.Fatal(err)
	}
	if err := syncNode(db, "ing"); err != nil {
		t.Fatal(err)
	}
	if got := latestRuleset(t, db, "ing"); len(got.Rules) != 0 {
		t.Fatalf("inactive links must not be queued: %#v", got.Rules)
	}
}

func TestLinkQueuesTransitBeforeIngress(t *testing.T) {
	db := testManagementDB(t, "ixcontrollinkorder")
	defer db.Close()
	if err := upsertLink(db, testLink("order", 32201, 42201)); err != nil {
		t.Fatal(err)
	}
	rows, err := db.Query(`SELECT node_id FROM commands ORDER BY rowid`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if len(ids) != 2 || ids[0] != "tran" || ids[1] != "ing" {
		t.Fatalf("expected transit then ingress, got %v", ids)
	}
}

func TestReconcileAllQueuesTransitBeforeIngress(t *testing.T) {
	db := testManagementDB(t, "ixcontrollinkreconcileorder")
	defer db.Close()
	if err := reconcileAll(db); err != nil {
		t.Fatal(err)
	}
	rows, err := db.Query(`SELECT node_id FROM commands ORDER BY rowid`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if len(ids) != 2 || ids[0] != "tran" || ids[1] != "ing" {
		t.Fatalf("expected transit then ingress, got %v", ids)
	}
}

func TestLinkRejectsProtocolPortConflicts(t *testing.T) {
	db := testManagementDB(t, "ixcontrollinkconflicts")
	defer db.Close()
	if err := upsertLink(db, testLink("first", 32301, 42301)); err != nil {
		t.Fatal(err)
	}
	conflict := testLink("both", 32301, 42302)
	conflict.Protocol = "both"
	if err := upsertLink(db, conflict); err == nil {
		t.Fatal("both protocol must conflict with existing tcp listener")
	}
	if _, err := db.Exec(`INSERT INTO managed_rules VALUES('managed','ing','u1',1,'udp',32302,'192.0.2.20',53,'','')`); err != nil {
		t.Fatal(err)
	}
	managedConflict := testLink("managed-link", 32302, 42303)
	managedConflict.Protocol = "both"
	if err := upsertLink(db, managedConflict); err == nil {
		t.Fatal("link must conflict with managed rule selector")
	}
}

func TestLinkUpdateDeleteRemoveOldRulesAndMeterOnlyIngress(t *testing.T) {
	db := testManagementDB(t, "ixcontrollinkupdate")
	defer db.Close()
	l := testLink("metered", 32401, 42401)
	if err := upsertLink(db, l); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO usage_events VALUES('ing','metered',1,3,7,1),('tran','t-metered',1,100,100,1)`); err != nil {
		t.Fatal(err)
	}
	used, err := usageForUser(db, "u1", "both")
	if err != nil || used != 10 {
		t.Fatalf("link usage must count ingress only: used=%d err=%v", used, err)
	}
	l.ClientPort, l.TransitPort = 32402, 42402
	if err := upsertLink(db, l); err != nil {
		t.Fatal(err)
	}
	if got := latestRuleset(t, db, "ing"); len(got.Rules) != 1 || got.Rules[0].ListenPort != 32402 {
		t.Fatalf("updated ingress ruleset retained old rule: %#v", got.Rules)
	}
	if got := latestRuleset(t, db, "tran"); len(got.Rules) != 1 || got.Rules[0].ListenPort != 42402 {
		t.Fatalf("updated transit ruleset retained old rule: %#v", got.Rules)
	}
	if err := deleteLink(db, "metered"); err != nil {
		t.Fatal(err)
	}
	if got := latestRuleset(t, db, "ing"); len(got.Rules) != 0 {
		t.Fatalf("deleted ingress rule retained: %#v", got.Rules)
	}
	if got := latestRuleset(t, db, "tran"); len(got.Rules) != 0 {
		t.Fatalf("deleted transit rule retained: %#v", got.Rules)
	}
}

func commandDeps(t *testing.T, db *sql.DB, nodeID string) []string {
	t.Helper()
	var raw string
	if err := db.QueryRow(`SELECT depends_on FROM commands WHERE node_id=? ORDER BY rowid DESC LIMIT 1`, nodeID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var deps []string
	if err := json.Unmarshal([]byte(raw), &deps); err != nil {
		t.Fatal(err)
	}
	return deps
}

func TestGlobalRuleIDConflicts(t *testing.T) {
	db := testManagementDB(t, "ixcontrolglobalids")
	defer db.Close()
	if err := upsertLink(db, testLink("link", 33001, 43001)); err != nil {
		t.Fatal(err)
	}
	managed := ManagedRule{RuleSpec: RuleSpec{ID: "link", Protocol: "tcp", ListenPort: 33002, TargetIP: "192.0.2.3", TargetPort: 443}, NodeID: "ing", UserID: "u1", Enabled: true}
	if err := upsertManagedRule(db, managed); err == nil {
		t.Fatal("managed id matching link id accepted")
	}
	managed.ID = "t-link"
	if err := upsertManagedRule(db, managed); err == nil {
		t.Fatal("managed id matching transit link id accepted")
	}
	if err := upsertLink(db, testLink("t-link", 33003, 43003)); err == nil {
		t.Fatal("link id matching another transit link id accepted")
	}
}

func TestIngressDependenciesOnlyIncludeItsTransitAndOldLink(t *testing.T) {
	db := testManagementDB(t, "ixcontroldepsprecise")
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO node_config VALUES('tran2','transit','10.9.0.3')`); err != nil {
		t.Fatal(err)
	}
	first := testLink("first", 33101, 43101)
	if err := upsertLink(db, first); err != nil {
		t.Fatal(err)
	}
	other := testLink("other", 33102, 43102)
	other.TransitNodeID, other.TransitEasyIP = "tran2", "10.9.0.3"
	if err := upsertLink(db, other); err != nil {
		t.Fatal(err)
	}
	var tranID, tran2ID string
	if err := db.QueryRow(`SELECT id FROM commands WHERE node_id='tran' ORDER BY rowid DESC LIMIT 1`).Scan(&tranID); err != nil { t.Fatal(err) }
	if err := db.QueryRow(`SELECT id FROM commands WHERE node_id='tran2' ORDER BY rowid DESC LIMIT 1`).Scan(&tran2ID); err != nil { t.Fatal(err) }
	deps := commandDeps(t, db, "ing")
	if len(deps) != 2 || !containsText(strings.Join(deps, ","), tranID) || !containsText(strings.Join(deps, ","), tran2ID) {
		t.Fatalf("aggregated ingress must depend on both own transits: %v", deps)
	}
	if err := deleteLink(db, "other"); err != nil {
		t.Fatal(err)
	}
	deps = commandDeps(t, db, "ing")
	if len(deps) != 2 {
		t.Fatalf("delete must retain old transit gate: %v", deps)
	}
}

func TestSyncNodeIngressWaitsForTransitCommand(t *testing.T) {
	db := testManagementDB(t, "ixcontrolsyncnodegate")
	defer db.Close()
	if err := upsertLink(db, testLink("sync-gate", 33151, 43151)); err != nil {
		t.Fatal(err)
	}
	if err := syncNode(db, "ing"); err != nil {
		t.Fatal(err)
	}
	var transitID string
	if err := db.QueryRow(`SELECT id FROM commands WHERE node_id='tran' ORDER BY rowid DESC LIMIT 1`).Scan(&transitID); err != nil {
		t.Fatal(err)
	}
	deps := commandDeps(t, db, "ing")
	if len(deps) != 1 || deps[0] != transitID {
		t.Fatalf("sync ingress dependencies=%v transit=%s", deps, transitID)
	}
	s := &Server{db: db}
	commands, err := s.pendingCommands("ing")
	if err != nil {
		t.Fatal(err)
	}
	if len(commands) != 0 {
		t.Fatalf("ingress leaked before transit acknowledgement: %#v", commands)
	}
	if ok, err := s.ackCommand("tran", transitID, "done", "applied"); err != nil || !ok {
		t.Fatalf("transit acknowledgement ok=%v err=%v", ok, err)
	}
	commands, err = s.pendingCommands("ing")
	if err != nil || len(commands) != 1 {
		t.Fatalf("ingress after transit done commands=%#v err=%v", commands, err)
	}
}

func TestLinkWriteRollsBackWhenPlanningFails(t *testing.T) {
	db := testManagementDB(t, "ixcontrolrollback")
	defer db.Close()
	if _, err := db.Exec(`CREATE TRIGGER reject_planned_command BEFORE INSERT ON commands BEGIN SELECT RAISE(ABORT, 'planner blocked'); END`); err != nil {
		t.Fatal(err)
	}
	if err := upsertLink(db, testLink("rollback", 33201, 43201)); err == nil {
		t.Fatal("expected planner failure")
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM links WHERE id='rollback'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("link write survived failed planning transaction")
	}
}
func containsText(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
