// Package local is a zero-infrastructure claustral backend: AES-256-GCM with per-object data keys wrapped by a local master key.
package local

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/davidparkercodes/claustral/pkg/claustral"
)

const (
	BackendName   = "local"
	formatVersion = 1
	maxHeaderLen  = 64 << 10
	nonceSize     = 12
)

var magic = []byte("CLST")

const schema = `
CREATE TABLE IF NOT EXISTS object_keys (
	id            TEXT PRIMARY KEY,
	kek_id        TEXT NOT NULL,
	policy        TEXT NOT NULL,
	policy_digest TEXT NOT NULL,
	wrapped_dek   BLOB,
	created_at    TEXT NOT NULL,
	revoked_at    TEXT
);
`

type header struct {
	Version int              `json:"v"`
	ID      string           `json:"id"`
	Backend string           `json:"backend"`
	KEKID   string           `json:"kek_id"`
	Policy  claustral.Policy `json:"policy"`
}

type Backend struct {
	db  *sql.DB
	kek *MasterKey
	now func() time.Time
}

var _ claustral.Backend = (*Backend)(nil)

func New(db *sql.DB, kek *MasterKey) (*Backend, error) {
	if db == nil || kek == nil {
		return nil, errors.New("local: db and master key are required")
	}
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("local: migrate: %w", err)
	}
	return &Backend{db: db, kek: kek, now: time.Now}, nil
}

func (b *Backend) Name() string { return BackendName }

func (b *Backend) Seal(ctx context.Context, id string, data []byte, p claustral.Policy) ([]byte, error) {
	p = p.Normalize()
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if err := claustral.ValidateID(id); err != nil {
		return nil, err
	}

	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return nil, err
	}
	defer clear(dek)

	hdr, err := json.Marshal(header{Version: formatVersion, ID: id, Backend: BackendName, KEKID: b.kek.id, Policy: p})
	if err != nil {
		return nil, err
	}
	prefix := make([]byte, 0, len(magic)+1+4+len(hdr))
	prefix = append(prefix, magic...)
	prefix = append(prefix, formatVersion)
	prefix = binary.BigEndian.AppendUint32(prefix, uint32(len(hdr)))
	prefix = append(prefix, hdr...)

	sealedData, err := gcmSeal(dek, data, prefix)
	if err != nil {
		return nil, err
	}
	wrapped, err := gcmSeal(b.kek.key[:], dek, dekAAD(id, p))
	if err != nil {
		return nil, err
	}
	policyJSON, _ := json.Marshal(p)
	_, err = b.db.ExecContext(ctx, `INSERT INTO object_keys (id, kek_id, policy, policy_digest, wrapped_dek, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		id, b.kek.id, string(policyJSON), p.Digest(), wrapped, b.now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") || strings.Contains(err.Error(), "constraint") {
			return nil, fmt.Errorf("local: object id %s already exists", id)
		}
		return nil, fmt.Errorf("local: store key: %w", err)
	}
	return append(prefix, sealedData...), nil
}

func (b *Backend) Inspect(blob []byte) (claustral.Meta, error) {
	h, _, _, err := parse(blob)
	if err != nil {
		return claustral.Meta{}, err
	}
	return claustral.Meta{ID: h.ID, Backend: BackendName, Policy: h.Policy}, nil
}

func (b *Backend) Unseal(ctx context.Context, blob []byte, e claustral.Entity) ([]byte, claustral.Meta, error) {
	h, prefix, body, err := parse(blob)
	if err != nil {
		return nil, claustral.Meta{}, err
	}
	meta := claustral.Meta{ID: h.ID, Backend: BackendName, Policy: h.Policy}

	var kekID, policyJSON, digest string
	var wrapped []byte
	var revokedAt sql.NullString
	err = b.db.QueryRowContext(ctx, `SELECT kek_id, policy, policy_digest, wrapped_dek, revoked_at FROM object_keys WHERE id = ?`, h.ID).
		Scan(&kekID, &policyJSON, &digest, &wrapped, &revokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, meta, fmt.Errorf("%w: %w", claustral.ErrDenied, claustral.ErrNotFound)
	}
	if err != nil {
		return nil, meta, fmt.Errorf("local: key lookup: %w", err)
	}
	if revokedAt.Valid || len(wrapped) == 0 {
		return nil, meta, claustral.ErrRevoked
	}
	var stored claustral.Policy
	if err := json.Unmarshal([]byte(policyJSON), &stored); err != nil {
		return nil, meta, fmt.Errorf("local: stored policy corrupt: %w", err)
	}
	if !stored.Equal(h.Policy) || stored.Digest() != digest {
		return nil, meta, fmt.Errorf("%w: policy in object does not match key store", claustral.ErrMalformed)
	}
	meta.Policy = stored
	if !stored.Allows(e) {
		return nil, meta, fmt.Errorf("%w: missing attributes %s", claustral.ErrDenied, strings.Join(stored.Missing(e), ", "))
	}
	if kekID != b.kek.id || h.KEKID != b.kek.id {
		return nil, meta, fmt.Errorf("local: object %s was sealed under master key %s, loaded key is %s", h.ID, kekID, b.kek.id)
	}
	dek, err := gcmOpen(b.kek.key[:], wrapped, dekAAD(h.ID, stored))
	if err != nil {
		return nil, meta, fmt.Errorf("%w: data key unwrap failed", claustral.ErrMalformed)
	}
	defer clear(dek)
	plain, err := gcmOpen(dek, body, prefix)
	if err != nil {
		return nil, meta, fmt.Errorf("%w: ciphertext authentication failed", claustral.ErrMalformed)
	}
	return plain, meta, nil
}

func (b *Backend) Revoke(ctx context.Context, id string) error {
	res, err := b.db.ExecContext(ctx, `UPDATE object_keys SET wrapped_dek = NULL, revoked_at = ? WHERE id = ? AND revoked_at IS NULL`,
		b.now().UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return fmt.Errorf("local: revoke: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		var exists int
		if err := b.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM object_keys WHERE id = ?`, id).Scan(&exists); err != nil {
			return fmt.Errorf("local: revoke: %w", err)
		}
		if exists == 0 {
			return claustral.ErrNotFound
		}
		return nil
	}
	_, _ = b.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`)
	return nil
}

type Status struct {
	ID        string           `json:"id"`
	Policy    claustral.Policy `json:"policy"`
	CreatedAt string           `json:"created_at"`
	RevokedAt string           `json:"revoked_at,omitempty"`
}

func (b *Backend) Status(ctx context.Context, id string) (Status, error) {
	var s Status
	var policyJSON string
	var revoked sql.NullString
	err := b.db.QueryRowContext(ctx, `SELECT id, policy, created_at, revoked_at FROM object_keys WHERE id = ?`, id).Scan(&s.ID, &policyJSON, &s.CreatedAt, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return s, claustral.ErrNotFound
	}
	if err != nil {
		return s, err
	}
	_ = json.Unmarshal([]byte(policyJSON), &s.Policy)
	s.RevokedAt = revoked.String
	return s, nil
}

func parse(blob []byte) (header, []byte, []byte, error) {
	var h header
	fixed := len(magic) + 1 + 4
	if len(blob) < fixed || !bytes.Equal(blob[:len(magic)], magic) {
		return h, nil, nil, fmt.Errorf("%w: not a claustral local object", claustral.ErrMalformed)
	}
	if blob[len(magic)] != formatVersion {
		return h, nil, nil, fmt.Errorf("%w: unsupported format version %d", claustral.ErrMalformed, blob[len(magic)])
	}
	hlen := binary.BigEndian.Uint32(blob[len(magic)+1 : fixed])
	if hlen == 0 || hlen > maxHeaderLen || int(hlen) > len(blob)-fixed {
		return h, nil, nil, fmt.Errorf("%w: bad header length", claustral.ErrMalformed)
	}
	end := fixed + int(hlen)
	dec := json.NewDecoder(bytes.NewReader(blob[fixed:end]))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&h); err != nil {
		return h, nil, nil, fmt.Errorf("%w: bad header: %v", claustral.ErrMalformed, err)
	}
	if h.Version != formatVersion || h.Backend != BackendName || claustral.ValidateID(h.ID) != nil {
		return h, nil, nil, fmt.Errorf("%w: bad header fields", claustral.ErrMalformed)
	}
	if err := h.Policy.Validate(); err != nil {
		return h, nil, nil, fmt.Errorf("%w: %v", claustral.ErrMalformed, err)
	}
	body := blob[end:]
	if len(body) < nonceSize+16 {
		return h, nil, nil, fmt.Errorf("%w: ciphertext too short", claustral.ErrMalformed)
	}
	return h, blob[:end], body, nil
}

func dekAAD(id string, p claustral.Policy) []byte {
	return []byte("claustral/local/dek\x00" + id + "\x00" + p.Digest())
}

func gcmSeal(key, plaintext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return g.Seal(nonce, nonce, plaintext, aad), nil
}

func gcmOpen(key, sealed, aad []byte) ([]byte, error) {
	if len(sealed) < nonceSize {
		return nil, errors.New("sealed value too short")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return g.Open(nil, sealed[:nonceSize], sealed[nonceSize:], aad)
}
