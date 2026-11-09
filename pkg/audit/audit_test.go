package audit_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"sync"
	"testing"

	"github.com/davidparkercodes/claustral/pkg/audit"
	"github.com/davidparkercodes/claustral/pkg/claustral"
	"github.com/davidparkercodes/claustral/pkg/sqlite"
)

func open(t *testing.T) (*audit.Log, *sql.DB) {
	t.Helper()
	db, err := sqlite.Open(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	l, err := audit.New(db)
	if err != nil {
		t.Fatal(err)
	}
	return l, db
}

func fill(t *testing.T, l *audit.Log, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, err := l.Append(context.Background(), claustral.Event{
			Action: claustral.ActionOpen, Outcome: claustral.OutcomeAllow, ObjectID: "obj-0001",
			Backend: "local", EntityID: "agent", Attributes: []string{"a/b"},
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestChainVerifies(t *testing.T) {
	l, _ := open(t)
	fill(t, l, 5)
	res, err := l.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.Events != 5 || res.HeadSeq != 5 {
		t.Fatalf("verify: %+v", res)
	}
	evs, err := l.Query(context.Background(), audit.Filter{ObjectID: "obj-0001"})
	if err != nil || len(evs) != 5 {
		t.Fatalf("query: %d %v", len(evs), err)
	}
	if evs[1].PrevHash != evs[0].Hash {
		t.Fatal("events not chained")
	}
}

func TestEmptyLogVerifies(t *testing.T) {
	l, _ := open(t)
	res, err := l.Verify(context.Background())
	if err != nil || !res.OK || res.HeadHash != claustral.GenesisHash {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestTriggersBlockUpdateAndDelete(t *testing.T) {
	l, db := open(t)
	fill(t, l, 2)
	if _, err := db.Exec(`UPDATE audit_events SET outcome = 'deny' WHERE seq = 1`); err == nil {
		t.Fatal("update should be rejected")
	}
	if _, err := db.Exec(`DELETE FROM audit_events WHERE seq = 1`); err == nil {
		t.Fatal("delete should be rejected")
	}
}

func TestTamperModifiedRowDetected(t *testing.T) {
	l, db := open(t)
	fill(t, l, 4)
	mustExec(t, db, `DROP TRIGGER audit_events_no_update`)
	mustExec(t, db, `UPDATE audit_events SET entity_id = 'someone-else' WHERE seq = 2`)
	res, err := l.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.OK || res.BrokenAt != 2 {
		t.Fatalf("tamper not detected: %+v", res)
	}
}

func TestTamperRecomputedHashDetectedByNextLink(t *testing.T) {
	l, db := open(t)
	fill(t, l, 4)
	evs, _ := l.Query(context.Background(), audit.Filter{})
	forged := evs[1]
	forged.Outcome = claustral.OutcomeDeny
	forged.Hash = forged.ComputeHash()
	mustExec(t, db, `DROP TRIGGER audit_events_no_update`)
	mustExec(t, db, `UPDATE audit_events SET outcome = ?, hash = ? WHERE seq = 2`, string(forged.Outcome), forged.Hash)
	res, _ := l.Verify(context.Background())
	if res.OK || res.BrokenAt != 3 {
		t.Fatalf("expected break at 3, got %+v", res)
	}
}

func TestTamperDeletedRowDetected(t *testing.T) {
	l, db := open(t)
	fill(t, l, 4)
	mustExec(t, db, `DROP TRIGGER audit_events_no_delete`)
	mustExec(t, db, `DELETE FROM audit_events WHERE seq = 2`)
	res, _ := l.Verify(context.Background())
	if res.OK || res.BrokenAt != 3 {
		t.Fatalf("expected break at 3, got %+v", res)
	}
}

func TestConcurrentAppendsStayChained(t *testing.T) {
	l, _ := open(t)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				if _, err := l.Append(context.Background(), claustral.Event{Action: claustral.ActionProtect, Outcome: claustral.OutcomeAllow, Backend: "local"}); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
	res, err := l.Verify(context.Background())
	if err != nil || !res.OK || res.Events != 80 {
		t.Fatalf("%+v %v", res, err)
	}
}

func mustExec(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.Exec(q, args...); err != nil {
		t.Fatal(err)
	}
}
