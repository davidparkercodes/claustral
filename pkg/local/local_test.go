package local_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/davidparkercodes/claustral/pkg/claustral"
	"github.com/davidparkercodes/claustral/pkg/local"
	"github.com/davidparkercodes/claustral/pkg/sqlite"
)

var ctx = context.Background()

func setup(t *testing.T) (*local.Backend, *sql.DB, *local.MasterKey) {
	t.Helper()
	db, err := sqlite.Open(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	k, err := local.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	b, err := local.New(db, k)
	if err != nil {
		t.Fatal(err)
	}
	return b, db, k
}

func policy(t *testing.T, attrs ...string) claustral.Policy {
	t.Helper()
	p, err := claustral.NewPolicy(attrs...)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func entity(attrs ...string) claustral.Entity {
	return claustral.Entity{ID: "agent-1", Attributes: attrs}
}

func TestRoundTrip(t *testing.T) {
	b, _, _ := setup(t)
	plain := []byte("quarterly numbers: 42")
	blob, err := b.Seal(ctx, "obj-00000001", plain, policy(t, "dept/finance"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, plain) || bytes.Contains(blob, []byte("quarterly")) {
		t.Fatal("plaintext visible in sealed blob")
	}
	got, meta, err := b.Unseal(ctx, blob, entity("dept/finance"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) || meta.ID != "obj-00000001" {
		t.Fatalf("got %q %+v", got, meta)
	}
}

func TestEmptyPlaintext(t *testing.T) {
	b, _, _ := setup(t)
	blob, err := b.Seal(ctx, "obj-empty-01", nil, policy(t, "a"))
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := b.Unseal(ctx, blob, entity("a"))
	if err != nil || len(got) != 0 {
		t.Fatalf("%q %v", got, err)
	}
}

func TestDeniedWithoutAllAttributes(t *testing.T) {
	b, _, _ := setup(t)
	blob, _ := b.Seal(ctx, "obj-00000002", []byte("x"), policy(t, "dept/legal", "clearance/secret"))
	for _, e := range []claustral.Entity{entity(), entity("dept/legal"), entity("clearance/secret"), entity("*")} {
		if _, _, err := b.Unseal(ctx, blob, e); !errors.Is(err, claustral.ErrDenied) {
			t.Errorf("entity %v: want denied, got %v", e.Attributes, err)
		}
	}
	if _, _, err := b.Unseal(ctx, blob, entity("clearance/secret", "dept/legal")); err != nil {
		t.Fatal(err)
	}
}

func TestRevokedCopiedCiphertextNeverOpens(t *testing.T) {
	b, db, k := setup(t)
	blob, _ := b.Seal(ctx, "obj-00000003", []byte("memory"), policy(t, "a"))
	copied := append([]byte(nil), blob...)
	if err := b.Revoke(ctx, "obj-00000003"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.Unseal(ctx, copied, entity("a")); !errors.Is(err, claustral.ErrRevoked) {
		t.Fatalf("want revoked, got %v", err)
	}
	var wrapped []byte
	if err := db.QueryRow(`SELECT wrapped_dek FROM object_keys WHERE id = ?`, "obj-00000003").Scan(&wrapped); err != nil {
		t.Fatal(err)
	}
	if wrapped != nil {
		t.Fatal("wrapped data key must be destroyed on revoke")
	}
	mustExec(t, db, `UPDATE object_keys SET revoked_at = NULL WHERE id = ?`, "obj-00000003")
	if _, _, err := b.Unseal(ctx, copied, entity("a")); err == nil {
		t.Fatal("clearing the revoked flag must not resurrect the object")
	}
	b2, _ := local.New(db, k)
	if _, _, err := b2.Unseal(ctx, copied, entity("a")); err == nil {
		t.Fatal("a fresh backend with the same master key must not open a revoked object")
	}
	if err := b.Revoke(ctx, "obj-00000003"); err != nil {
		t.Fatalf("revoke must be idempotent: %v", err)
	}
}

func TestRevokeUnknown(t *testing.T) {
	b, _, _ := setup(t)
	if err := b.Revoke(ctx, "obj-unknown-1"); !errors.Is(err, claustral.ErrNotFound) {
		t.Fatalf("got %v", err)
	}
}

func TestUnknownObjectDenied(t *testing.T) {
	b, _, _ := setup(t)
	other, _, _ := setup(t)
	blob, _ := other.Seal(ctx, "obj-00000004", []byte("x"), policy(t, "a"))
	if _, _, err := b.Unseal(ctx, blob, entity("a")); !errors.Is(err, claustral.ErrDenied) || !errors.Is(err, claustral.ErrNotFound) {
		t.Fatalf("got %v", err)
	}
}

func TestWrongMasterKeyCannotOpen(t *testing.T) {
	b, db, _ := setup(t)
	blob, _ := b.Seal(ctx, "obj-00000005", []byte("x"), policy(t, "a"))
	k2, _ := local.GenerateMasterKey()
	b2, _ := local.New(db, k2)
	if _, _, err := b2.Unseal(ctx, blob, entity("a")); err == nil || !strings.Contains(err.Error(), "master key") {
		t.Fatalf("got %v", err)
	}
}

func TestTamperedCiphertextRejected(t *testing.T) {
	b, _, _ := setup(t)
	blob, _ := b.Seal(ctx, "obj-00000006", []byte("payload bytes"), policy(t, "a"))
	for _, pos := range []int{len(blob) - 1, len(blob) - 20} {
		bad := append([]byte(nil), blob...)
		bad[pos] ^= 0x01
		if _, _, err := b.Unseal(ctx, bad, entity("a")); !errors.Is(err, claustral.ErrMalformed) {
			t.Errorf("pos %d: got %v", pos, err)
		}
	}
	if _, _, err := b.Unseal(ctx, blob[:len(blob)-5], entity("a")); !errors.Is(err, claustral.ErrMalformed) {
		t.Errorf("truncated: got %v", err)
	}
	if _, _, err := b.Unseal(ctx, []byte("garbage"), entity("a")); !errors.Is(err, claustral.ErrMalformed) {
		t.Errorf("garbage: got %v", err)
	}
}

func TestPolicyDowngradeInHeaderRejected(t *testing.T) {
	b, _, _ := setup(t)
	blob, _ := b.Seal(ctx, "obj-00000007", []byte("x"), policy(t, "clearance/secret"))
	forged := rewriteHeader(t, blob, func(h string) string {
		return strings.Replace(h, "clearance/secret", "clearance/public", 1)
	})
	if _, _, err := b.Unseal(ctx, forged, entity("clearance/public")); !errors.Is(err, claustral.ErrMalformed) {
		t.Fatalf("want malformed, got %v", err)
	}
}

func TestPolicyDowngradeInKeyStoreRejected(t *testing.T) {
	b, db, _ := setup(t)
	blob, _ := b.Seal(ctx, "obj-00000008", []byte("x"), policy(t, "clearance/secret"))
	weak := policy(t, "clearance/public")
	mustExec(t, db, `UPDATE object_keys SET policy = '{"attributes":["clearance/public"]}', policy_digest = ? WHERE id = ?`, weak.Digest(), "obj-00000008")
	forged := rewriteHeader(t, blob, func(h string) string {
		return strings.Replace(h, "clearance/secret", "clearance/public", 1)
	})
	if _, _, err := b.Unseal(ctx, forged, entity("clearance/public")); !errors.Is(err, claustral.ErrMalformed) {
		t.Fatalf("want malformed (key wrap bound to original policy), got %v", err)
	}
}

func TestSwappedObjectIDRejected(t *testing.T) {
	b, _, _ := setup(t)
	blobA, _ := b.Seal(ctx, "obj-aaaaaaaa", []byte("a secret"), policy(t, "x"))
	if _, err := b.Seal(ctx, "obj-bbbbbbbb", []byte("b"), policy(t, "x")); err != nil {
		t.Fatal(err)
	}
	forged := rewriteHeader(t, blobA, func(h string) string {
		return strings.Replace(h, "obj-aaaaaaaa", "obj-bbbbbbbb", 1)
	})
	if _, _, err := b.Unseal(ctx, forged, entity("x")); !errors.Is(err, claustral.ErrMalformed) {
		t.Fatalf("got %v", err)
	}
}

func TestDuplicateIDRejected(t *testing.T) {
	b, _, _ := setup(t)
	if _, err := b.Seal(ctx, "obj-00000009", []byte("x"), policy(t, "a")); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Seal(ctx, "obj-00000009", []byte("y"), policy(t, "a")); err == nil {
		t.Fatal("duplicate id must fail")
	}
}

func TestInspectDoesNotDecrypt(t *testing.T) {
	b, _, _ := setup(t)
	blob, _ := b.Seal(ctx, "obj-00000010", []byte("x"), policy(t, "b", "a"))
	m, err := b.Inspect(blob)
	if err != nil {
		t.Fatal(err)
	}
	if m.ID != "obj-00000010" || len(m.Policy.Attributes) != 2 || m.Policy.Attributes[0] != "a" {
		t.Fatalf("%+v", m)
	}
}

func TestConcurrentSealOpenRevoke(t *testing.T) {
	b, _, _ := setup(t)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				id, _ := claustral.NewID()
				blob, err := b.Seal(ctx, id, []byte(id), policy(t, "a"))
				if err != nil {
					t.Error(err)
					return
				}
				got, _, err := b.Unseal(ctx, blob, entity("a"))
				if err != nil || string(got) != id {
					t.Errorf("open: %v", err)
					return
				}
				if i%2 == 0 {
					if err := b.Revoke(ctx, id); err != nil {
						t.Error(err)
						return
					}
					if _, _, err := b.Unseal(ctx, blob, entity("a")); !errors.Is(err, claustral.ErrRevoked) {
						t.Errorf("after revoke: %v", err)
					}
				}
			}
		}(g)
	}
	wg.Wait()
}

func TestMasterKeyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "master.key")
	k, _ := local.GenerateMasterKey()
	if err := local.WriteMasterKeyFile(path, k); err != nil {
		t.Fatal(err)
	}
	if err := local.WriteMasterKeyFile(path, k); err == nil {
		t.Fatal("must refuse to overwrite")
	}
	k2, err := local.LoadMasterKeyFile(path)
	if err != nil || k2.ID() != k.ID() {
		t.Fatalf("%v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := local.LoadMasterKeyFile(path); err == nil {
		t.Fatal("world-readable key file must be rejected")
	}
	if _, err := local.LoadMasterKeyFile(filepath.Join(dir, "missing")); err == nil || !strings.Contains(err.Error(), "keygen") {
		t.Fatalf("missing key must not be auto-created: %v", err)
	}
}

func TestParseMasterKey(t *testing.T) {
	k, _ := local.GenerateMasterKey()
	k2, err := local.ParseMasterKey(k.Encode())
	if err != nil || k2.ID() != k.ID() {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "secret", strings.Repeat("0", 64), "abcd"} {
		if _, err := local.ParseMasterKey(bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

func rewriteHeader(t *testing.T, blob []byte, f func(string) string) []byte {
	t.Helper()
	hlen := binary.BigEndian.Uint32(blob[5:9])
	h := f(string(blob[9 : 9+hlen]))
	out := append([]byte(nil), blob[:5]...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(h)))
	out = append(out, h...)
	return append(out, blob[9+hlen:]...)
}

func mustExec(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.Exec(q, args...); err != nil {
		t.Fatal(err)
	}
}
