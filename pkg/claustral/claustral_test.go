package claustral_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/davidparkercodes/claustral/pkg/claustral"
)

type memAudit struct {
	mu     sync.Mutex
	events []claustral.Event
	fail   error
}

func (m *memAudit) Append(_ context.Context, e claustral.Event) (claustral.Event, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail != nil {
		return e, m.fail
	}
	m.events = append(m.events, e)
	return e, nil
}

type fakeBackend struct {
	objects map[string]claustral.Policy
	data    map[string][]byte
	revoked map[string]bool
}

func newFake() *fakeBackend {
	return &fakeBackend{objects: map[string]claustral.Policy{}, data: map[string][]byte{}, revoked: map[string]bool{}}
}

func (f *fakeBackend) Name() string { return "fake" }
func (f *fakeBackend) Seal(_ context.Context, id string, data []byte, p claustral.Policy) ([]byte, error) {
	f.objects[id] = p
	f.data[id] = append([]byte(nil), data...)
	return []byte(id), nil
}
func (f *fakeBackend) Unseal(_ context.Context, blob []byte, e claustral.Entity) ([]byte, claustral.Meta, error) {
	id := string(blob)
	p, ok := f.objects[id]
	if !ok {
		return nil, claustral.Meta{}, claustral.ErrNotFound
	}
	m := claustral.Meta{ID: id, Backend: "fake", Policy: p}
	if f.revoked[id] {
		return nil, m, claustral.ErrRevoked
	}
	if !p.Allows(e) {
		return nil, m, claustral.ErrDenied
	}
	return append([]byte(nil), f.data[id]...), m, nil
}
func (f *fakeBackend) Inspect(blob []byte) (claustral.Meta, error) {
	p, ok := f.objects[string(blob)]
	if !ok {
		return claustral.Meta{}, claustral.ErrMalformed
	}
	return claustral.Meta{ID: string(blob), Backend: "fake", Policy: p}, nil
}
func (f *fakeBackend) Revoke(_ context.Context, id string) error {
	if _, ok := f.objects[id]; !ok {
		return claustral.ErrNotFound
	}
	f.revoked[id] = true
	return nil
}

func TestPolicyNormalizeAndValidate(t *testing.T) {
	p, err := claustral.NewPolicy(" b ", "a", "b", "")
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Attributes; len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("normalize: %v", got)
	}
	for _, bad := range [][]string{nil, {""}, {"has space"}, {"tab\tx"}, {string(make([]byte, 600))}} {
		if _, err := claustral.NewPolicy(bad...); !errors.Is(err, claustral.ErrInvalidPolicy) {
			t.Errorf("expected invalid policy for %q, got %v", bad, err)
		}
	}
}

func TestPolicyAllowsIsAllOf(t *testing.T) {
	p, _ := claustral.NewPolicy("dept/legal", "clearance/secret")
	cases := []struct {
		attrs []string
		want  bool
	}{
		{[]string{"dept/legal", "clearance/secret"}, true},
		{[]string{"dept/legal", "clearance/secret", "extra"}, true},
		{[]string{"dept/legal"}, false},
		{[]string{"*"}, false},
		{nil, false},
	}
	for _, c := range cases {
		if got := p.Allows(claustral.Entity{ID: "e", Attributes: c.attrs}); got != c.want {
			t.Errorf("Allows(%v) = %v, want %v", c.attrs, got, c.want)
		}
	}
	if (claustral.Policy{}).Allows(claustral.Entity{ID: "e", Attributes: []string{"x"}}) {
		t.Error("empty policy must allow nobody")
	}
	if p.Digest() != (claustral.Policy{Attributes: []string{"clearance/secret", "dept/legal"}}).Digest() {
		t.Error("digest must be order independent")
	}
}

func TestClientAuditsEveryAction(t *testing.T) {
	ctx := context.Background()
	a := &memAudit{}
	c, err := claustral.New(newFake(), a)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := claustral.NewPolicy("team/a")
	s, err := c.Protect(ctx, []byte("hello"), p, claustral.WithActor("writer"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Open(ctx, s.Blob, claustral.Entity{ID: "good", Attributes: []string{"team/a"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Open(ctx, s.Blob, claustral.Entity{ID: "bad"}); !errors.Is(err, claustral.ErrDenied) {
		t.Fatalf("want denied, got %v", err)
	}
	if err := c.Revoke(ctx, s.ID, "admin", "leaked"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Open(ctx, s.Blob, claustral.Entity{ID: "good", Attributes: []string{"team/a"}}); !errors.Is(err, claustral.ErrRevoked) {
		t.Fatalf("want revoked, got %v", err)
	}
	want := []struct {
		a claustral.Action
		o claustral.Outcome
		e string
	}{
		{claustral.ActionProtect, claustral.OutcomeAllow, "writer"},
		{claustral.ActionOpen, claustral.OutcomeAllow, "good"},
		{claustral.ActionOpen, claustral.OutcomeDeny, "bad"},
		{claustral.ActionRevoke, claustral.OutcomeAllow, "admin"},
		{claustral.ActionOpen, claustral.OutcomeDeny, "good"},
	}
	if len(a.events) != len(want) {
		t.Fatalf("got %d events, want %d", len(a.events), len(want))
	}
	for i, w := range want {
		ev := a.events[i]
		if ev.Action != w.a || ev.Outcome != w.o || ev.EntityID != w.e || ev.ObjectID != s.ID {
			t.Errorf("event %d = %+v, want %v/%v/%v", i, ev, w.a, w.o, w.e)
		}
	}
	if a.events[4].Reason != "revoked" {
		t.Errorf("revoked deny reason = %q", a.events[4].Reason)
	}
}

func TestOpenFailsClosedWhenAuditFails(t *testing.T) {
	ctx := context.Background()
	a := &memAudit{}
	c, _ := claustral.New(newFake(), a)
	p, _ := claustral.NewPolicy("x")
	s, err := c.Protect(ctx, []byte("secret"), p)
	if err != nil {
		t.Fatal(err)
	}
	a.fail = errors.New("disk full")
	data, err := c.Open(ctx, s.Blob, claustral.Entity{ID: "e", Attributes: []string{"x"}})
	if !errors.Is(err, claustral.ErrAudit) || data != nil {
		t.Fatalf("expected audit failure and no data, got %q %v", data, err)
	}
}

func TestProtectRollsBackWhenAuditFails(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	c, _ := claustral.New(f, &memAudit{fail: errors.New("down")})
	p, _ := claustral.NewPolicy("x")
	_, err := c.Protect(ctx, []byte("secret"), p, claustral.WithObjectID("object-0001"))
	if !errors.Is(err, claustral.ErrAudit) {
		t.Fatalf("want audit error, got %v", err)
	}
	if !f.revoked["object-0001"] {
		t.Fatal("object sealed without an audit record must be revoked")
	}
}

func TestNewRequiresAudit(t *testing.T) {
	if _, err := claustral.New(newFake(), nil); err == nil {
		t.Fatal("expected error without audit log")
	}
	if _, err := claustral.New(nil, &memAudit{}); err == nil {
		t.Fatal("expected error without backend")
	}
}

func TestOpenRequiresEntityID(t *testing.T) {
	c, _ := claustral.New(newFake(), &memAudit{})
	if _, err := c.Open(context.Background(), []byte("x"), claustral.Entity{}); !errors.Is(err, claustral.ErrInvalidEntity) {
		t.Fatalf("got %v", err)
	}
}

func TestValidateID(t *testing.T) {
	for _, ok := range []string{"abcdefgh", "doc-2026_11.v1"} {
		if err := claustral.ValidateID(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"short", "has space here", "semi;colon1", "../../etc/pw"} {
		if err := claustral.ValidateID(bad); err == nil {
			t.Errorf("%q should be invalid", bad)
		}
	}
}

func TestEventHashCoversFields(t *testing.T) {
	e := claustral.Event{Seq: 1, Action: claustral.ActionOpen, Outcome: claustral.OutcomeAllow, ObjectID: "o", EntityID: "e", PrevHash: claustral.GenesisHash}
	h := e.ComputeHash()
	e2 := e
	e2.EntityID = "f"
	if e2.ComputeHash() == h {
		t.Fatal("hash must change when entity changes")
	}
	e3 := e
	e3.Outcome = claustral.OutcomeDeny
	if e3.ComputeHash() == h {
		t.Fatal("hash must change when outcome changes")
	}
}
