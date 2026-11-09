// Package claustral seals data under attribute policies, opens it only for entities that satisfy them, and audits every access.
package claustral

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

var (
	ErrDenied        = errors.New("claustral: access denied")
	ErrRevoked       = errors.New("claustral: object revoked")
	ErrInvalidPolicy = errors.New("claustral: invalid policy")
	ErrInvalidEntity = errors.New("claustral: invalid entity")
	ErrMalformed     = errors.New("claustral: malformed or tampered object")
	ErrUnsupported   = errors.New("claustral: operation not supported by backend")
	ErrAudit         = errors.New("claustral: audit log unavailable")
	ErrNotFound      = errors.New("claustral: unknown object")
)

type Meta struct {
	ID      string `json:"id"`
	Backend string `json:"backend"`
	Policy  Policy `json:"policy"`
}

type Sealed struct {
	ID   string
	Blob []byte
}

type Backend interface {
	Name() string
	Seal(ctx context.Context, id string, data []byte, p Policy) ([]byte, error)
	Unseal(ctx context.Context, blob []byte, e Entity) ([]byte, Meta, error)
	Inspect(blob []byte) (Meta, error)
	Revoke(ctx context.Context, id string) error
}

type Client struct {
	backend Backend
	audit   AuditLog
	now     func() time.Time
}

type Option func(*Client)

func WithClock(now func() time.Time) Option {
	return func(c *Client) { c.now = now }
}

func New(b Backend, log AuditLog, opts ...Option) (*Client, error) {
	if b == nil {
		return nil, errors.New("claustral: backend is required")
	}
	if log == nil {
		return nil, errors.New("claustral: audit log is required")
	}
	c := &Client{backend: b, audit: log, now: time.Now}
	for _, o := range opts {
		o(c)
	}
	return c, nil
}

func (c *Client) Backend() Backend { return c.backend }

type protectConfig struct {
	actor string
	id    string
}

type ProtectOption func(*protectConfig)

func WithActor(id string) ProtectOption {
	return func(p *protectConfig) { p.actor = id }
}

func WithObjectID(id string) ProtectOption {
	return func(p *protectConfig) { p.id = id }
}

func (c *Client) Protect(ctx context.Context, data []byte, p Policy, opts ...ProtectOption) (Sealed, error) {
	cfg := protectConfig{}
	for _, o := range opts {
		o(&cfg)
	}
	p = p.Normalize()
	if err := p.Validate(); err != nil {
		return Sealed{}, err
	}
	id := cfg.id
	if id == "" {
		var err error
		if id, err = NewID(); err != nil {
			return Sealed{}, err
		}
	} else if err := ValidateID(id); err != nil {
		return Sealed{}, err
	}
	blob, err := c.backend.Seal(ctx, id, data, p)
	if err != nil {
		return Sealed{}, err
	}
	if _, err := c.audit.Append(ctx, Event{
		Time: c.now().UTC(), Action: ActionProtect, Outcome: OutcomeAllow,
		ObjectID: id, Backend: c.backend.Name(), EntityID: cfg.actor, Attributes: p.Attributes,
	}); err != nil {
		if rerr := c.backend.Revoke(ctx, id); rerr != nil && !errors.Is(rerr, ErrUnsupported) {
			return Sealed{}, fmt.Errorf("%w: %v (rollback revoke also failed: %v)", ErrAudit, err, rerr)
		}
		return Sealed{}, fmt.Errorf("%w: %v", ErrAudit, err)
	}
	return Sealed{ID: id, Blob: blob}, nil
}

func (c *Client) Open(ctx context.Context, blob []byte, e Entity) ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	data, meta, err := c.backend.Unseal(ctx, blob, e)
	if err != nil {
		if meta.ID == "" {
			if m, ierr := c.backend.Inspect(blob); ierr == nil {
				meta = m
			}
		}
		ev := Event{
			Time: c.now().UTC(), Action: ActionOpen, Outcome: OutcomeDeny,
			ObjectID: meta.ID, Backend: c.backend.Name(), EntityID: e.ID,
			Attributes: meta.Policy.Attributes, Reason: denyReason(err),
		}
		if _, aerr := c.audit.Append(ctx, ev); aerr != nil {
			return nil, errors.Join(err, fmt.Errorf("%w: %v", ErrAudit, aerr))
		}
		return nil, err
	}
	if _, aerr := c.audit.Append(ctx, Event{
		Time: c.now().UTC(), Action: ActionOpen, Outcome: OutcomeAllow,
		ObjectID: meta.ID, Backend: c.backend.Name(), EntityID: e.ID, Attributes: meta.Policy.Attributes,
	}); aerr != nil {
		clear(data)
		return nil, fmt.Errorf("%w: %v", ErrAudit, aerr)
	}
	return data, nil
}

func (c *Client) Revoke(ctx context.Context, id, actor, reason string) error {
	if err := ValidateID(id); err != nil {
		return err
	}
	err := c.backend.Revoke(ctx, id)
	outcome := OutcomeAllow
	why := reason
	if err != nil {
		outcome = OutcomeError
		why = err.Error()
	}
	if _, aerr := c.audit.Append(ctx, Event{
		Time: c.now().UTC(), Action: ActionRevoke, Outcome: outcome,
		ObjectID: id, Backend: c.backend.Name(), EntityID: actor, Reason: why,
	}); aerr != nil {
		return errors.Join(err, fmt.Errorf("%w: %v", ErrAudit, aerr))
	}
	return err
}

func (c *Client) Inspect(blob []byte) (Meta, error) {
	return c.backend.Inspect(blob)
}

func denyReason(err error) string {
	switch {
	case errors.Is(err, ErrRevoked):
		return "revoked"
	case errors.Is(err, ErrDenied):
		return err.Error()
	case errors.Is(err, ErrMalformed):
		return "malformed"
	default:
		return "error: " + err.Error()
	}
}

func NewID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("claustral: generate id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func ValidateID(id string) error {
	if len(id) < 8 || len(id) > 128 {
		return fmt.Errorf("claustral: object id must be 8-128 characters")
	}
	for _, r := range id {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.'
		if !ok {
			return fmt.Errorf("claustral: object id may only contain [A-Za-z0-9._-]")
		}
	}
	return nil
}
