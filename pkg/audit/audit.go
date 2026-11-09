// Package audit is an append-only, hash-chained SQLite audit log for claustral events.
package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/davidparkercodes/claustral/pkg/claustral"
)

const schema = `
CREATE TABLE IF NOT EXISTS audit_events (
	seq        INTEGER PRIMARY KEY,
	ts         TEXT NOT NULL,
	action     TEXT NOT NULL,
	outcome    TEXT NOT NULL,
	object_id  TEXT NOT NULL DEFAULT '',
	backend    TEXT NOT NULL,
	entity_id  TEXT NOT NULL DEFAULT '',
	attributes TEXT NOT NULL DEFAULT '[]',
	reason     TEXT NOT NULL DEFAULT '',
	prev_hash  TEXT NOT NULL,
	hash       TEXT NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS audit_events_object ON audit_events(object_id);
CREATE INDEX IF NOT EXISTS audit_events_entity ON audit_events(entity_id);
CREATE TRIGGER IF NOT EXISTS audit_events_no_update BEFORE UPDATE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_events_no_delete BEFORE DELETE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
`

type Log struct {
	db *sql.DB
}

var _ claustral.AuditLog = (*Log)(nil)

func New(db *sql.DB) (*Log, error) {
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("audit: migrate: %w", err)
	}
	return &Log{db: db}, nil
}

func (l *Log) Append(ctx context.Context, e claustral.Event) (claustral.Event, error) {
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return claustral.Event{}, fmt.Errorf("audit: begin: %w", err)
	}
	defer tx.Rollback()

	var lastSeq sql.NullInt64
	var lastHash sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT seq, hash FROM audit_events ORDER BY seq DESC LIMIT 1`).Scan(&lastSeq, &lastHash)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return claustral.Event{}, fmt.Errorf("audit: read head: %w", err)
	}
	e.Seq = 1
	e.PrevHash = claustral.GenesisHash
	if lastSeq.Valid {
		e.Seq = lastSeq.Int64 + 1
		e.PrevHash = lastHash.String
	}
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	e.Time = e.Time.UTC()
	e.Hash = e.ComputeHash()

	attrs, err := json.Marshal(nonNil(e.Attributes))
	if err != nil {
		return claustral.Event{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_events
		(seq, ts, action, outcome, object_id, backend, entity_id, attributes, reason, prev_hash, hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.Seq, e.Time.Format(time.RFC3339Nano), string(e.Action), string(e.Outcome), e.ObjectID, e.Backend,
		e.EntityID, string(attrs), e.Reason, e.PrevHash, e.Hash); err != nil {
		return claustral.Event{}, fmt.Errorf("audit: insert: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return claustral.Event{}, fmt.Errorf("audit: commit: %w", err)
	}
	return e, nil
}

type Filter struct {
	ObjectID string
	EntityID string
	Action   claustral.Action
	Outcome  claustral.Outcome
	AfterSeq int64
	Limit    int
}

func (l *Log) Query(ctx context.Context, f Filter) ([]claustral.Event, error) {
	var where []string
	var args []any
	if f.ObjectID != "" {
		where = append(where, "object_id = ?")
		args = append(args, f.ObjectID)
	}
	if f.EntityID != "" {
		where = append(where, "entity_id = ?")
		args = append(args, f.EntityID)
	}
	if f.Action != "" {
		where = append(where, "action = ?")
		args = append(args, string(f.Action))
	}
	if f.Outcome != "" {
		where = append(where, "outcome = ?")
		args = append(args, string(f.Outcome))
	}
	if f.AfterSeq > 0 {
		where = append(where, "seq > ?")
		args = append(args, f.AfterSeq)
	}
	limit := f.Limit
	if limit <= 0 || limit > 10000 {
		limit = 100
	}
	q := `SELECT seq, ts, action, outcome, object_id, backend, entity_id, attributes, reason, prev_hash, hash FROM audit_events`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY seq ASC LIMIT ?"
	args = append(args, limit)
	rows, err := l.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("audit: query: %w", err)
	}
	defer rows.Close()
	var out []claustral.Event
	for rows.Next() {
		e, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

type VerifyResult struct {
	OK       bool   `json:"ok"`
	Events   int64  `json:"events"`
	HeadSeq  int64  `json:"head_seq"`
	HeadHash string `json:"head_hash"`
	BrokenAt int64  `json:"broken_at,omitempty"`
	Problem  string `json:"problem,omitempty"`
}

func (l *Log) Verify(ctx context.Context) (VerifyResult, error) {
	rows, err := l.db.QueryContext(ctx, `SELECT seq, ts, action, outcome, object_id, backend, entity_id, attributes, reason, prev_hash, hash FROM audit_events ORDER BY seq ASC`)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("audit: verify: %w", err)
	}
	defer rows.Close()
	res := VerifyResult{OK: true, HeadHash: claustral.GenesisHash}
	prev := claustral.GenesisHash
	var expectSeq int64 = 1
	for rows.Next() {
		e, err := scan(rows)
		if err != nil {
			return VerifyResult{}, err
		}
		res.Events++
		fail := func(problem string) {
			if res.OK {
				res.OK = false
				res.BrokenAt = e.Seq
				res.Problem = problem
			}
		}
		switch {
		case e.Seq != expectSeq:
			fail(fmt.Sprintf("sequence gap: expected %d", expectSeq))
		case e.PrevHash != prev:
			fail("prev_hash does not match previous event")
		case e.ComputeHash() != e.Hash:
			fail("event hash mismatch (contents modified)")
		}
		prev = e.Hash
		expectSeq = e.Seq + 1
		res.HeadSeq = e.Seq
		res.HeadHash = e.Hash
	}
	return res, rows.Err()
}

type scanner interface {
	Scan(dest ...any) error
}

func scan(r scanner) (claustral.Event, error) {
	var e claustral.Event
	var ts, action, outcome, attrs string
	if err := r.Scan(&e.Seq, &ts, &action, &outcome, &e.ObjectID, &e.Backend, &e.EntityID, &attrs, &e.Reason, &e.PrevHash, &e.Hash); err != nil {
		return e, fmt.Errorf("audit: scan: %w", err)
	}
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return e, fmt.Errorf("audit: bad timestamp at seq %d: %w", e.Seq, err)
	}
	e.Time = t
	e.Action = claustral.Action(action)
	e.Outcome = claustral.Outcome(outcome)
	if err := json.Unmarshal([]byte(attrs), &e.Attributes); err != nil {
		return e, fmt.Errorf("audit: bad attributes at seq %d: %w", e.Seq, err)
	}
	if len(e.Attributes) == 0 {
		e.Attributes = nil
	}
	return e, nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
