package claustral

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

type Action string

const (
	ActionProtect Action = "protect"
	ActionOpen    Action = "open"
	ActionRevoke  Action = "revoke"
)

type Outcome string

const (
	OutcomeAllow Outcome = "allow"
	OutcomeDeny  Outcome = "deny"
	OutcomeError Outcome = "error"
)

type Event struct {
	Seq        int64     `json:"seq"`
	Time       time.Time `json:"time"`
	Action     Action    `json:"action"`
	Outcome    Outcome   `json:"outcome"`
	ObjectID   string    `json:"object_id,omitempty"`
	Backend    string    `json:"backend"`
	EntityID   string    `json:"entity_id,omitempty"`
	Attributes []string  `json:"attributes,omitempty"`
	Reason     string    `json:"reason,omitempty"`
	PrevHash   string    `json:"prev_hash"`
	Hash       string    `json:"hash"`
}

type AuditLog interface {
	Append(ctx context.Context, e Event) (Event, error)
}

const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

func (e Event) ComputeHash() string {
	body := struct {
		Seq        int64    `json:"seq"`
		Time       string   `json:"time"`
		Action     Action   `json:"action"`
		Outcome    Outcome  `json:"outcome"`
		ObjectID   string   `json:"object_id"`
		Backend    string   `json:"backend"`
		EntityID   string   `json:"entity_id"`
		Attributes []string `json:"attributes"`
		Reason     string   `json:"reason"`
		PrevHash   string   `json:"prev_hash"`
	}{e.Seq, e.Time.UTC().Format(time.RFC3339Nano), e.Action, e.Outcome, e.ObjectID, e.Backend, e.EntityID, e.Attributes, e.Reason, e.PrevHash}
	if body.Attributes == nil {
		body.Attributes = []string{}
	}
	b, _ := json.Marshal(body)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
