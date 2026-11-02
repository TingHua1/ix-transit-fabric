package main

import (
	"database/sql"
	"encoding/json"
	"testing"
	"time"
)

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
func containsText(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
