package server_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/davidparkercodes/claustral/internal/server"
	"github.com/davidparkercodes/claustral/pkg/audit"
	"github.com/davidparkercodes/claustral/pkg/claustral"
	"github.com/davidparkercodes/claustral/pkg/local"
	"github.com/davidparkercodes/claustral/pkg/sqlite"
)

const token = "test-token-0123456789-abcdefghijklmnop"

func newServer(t *testing.T, reg *server.Registry) *httptest.Server {
	t.Helper()
	db, err := sqlite.Open(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	k, _ := local.GenerateMasterKey()
	b, err := local.New(db, k)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := audit.New(db)
	c, _ := claustral.New(b, a)
	h, err := server.New(server.Config{Client: c, Audit: a, Token: token, Entities: reg, MaxBody: 1 << 20, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return ts
}

func call(t *testing.T, ts *httptest.Server, method, path, tok string, body any, hdr map[string]string) (int, map[string]any) {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, ts.URL+path, r)
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestNewRejectsWeakToken(t *testing.T) {
	for _, tok := range []string{"", "secret", strings.Repeat(" ", 40)} {
		if _, err := server.New(server.Config{Client: &claustral.Client{}, Audit: &audit.Log{}, Token: tok}); err == nil {
			t.Errorf("token %q should be rejected", tok)
		}
	}
}

func TestAuthRequired(t *testing.T) {
	ts := newServer(t, nil)
	if code, _ := call(t, ts, "GET", "/healthz", "", nil, nil); code != 200 {
		t.Fatalf("healthz: %d", code)
	}
	for _, tok := range []string{"", "wrong-token-wrong-token-wrong-token"} {
		if code, _ := call(t, ts, "GET", "/v1/audit", tok, nil, nil); code != 401 {
			t.Errorf("token %q: got %d", tok, code)
		}
	}
	req, _ := http.NewRequest("GET", ts.URL+"/v1/audit", nil)
	req.Header.Set("Authorization", "Basic "+token)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != 401 {
		t.Errorf("basic scheme: got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestProtectOpenDenyRevokeFlow(t *testing.T) {
	ts := newServer(t, nil)
	data := base64.StdEncoding.EncodeToString([]byte("customer record"))
	code, out := call(t, ts, "POST", "/v1/protect", token, map[string]any{"data": data, "attributes": []string{"team/support", "region/eu"}}, nil)
	if code != 201 {
		t.Fatalf("protect: %d %v", code, out)
	}
	id, sealed := out["id"].(string), out["sealed"].(string)

	code, out = call(t, ts, "POST", "/v1/open", token, map[string]any{"sealed": sealed, "entity": map[string]any{"id": "agent-eu", "attributes": []string{"team/support", "region/eu"}}}, nil)
	if code != 200 || out["data"] != data {
		t.Fatalf("open: %d %v", code, out)
	}
	code, out = call(t, ts, "POST", "/v1/open", token, map[string]any{"sealed": sealed, "entity": map[string]any{"id": "agent-us", "attributes": []string{"team/support", "region/us"}}}, nil)
	if code != 403 || out["code"] != "denied" {
		t.Fatalf("deny: %d %v", code, out)
	}
	code, out = call(t, ts, "POST", "/v1/inspect", token, map[string]any{"sealed": sealed}, nil)
	if code != 200 || out["id"] != id {
		t.Fatalf("inspect: %d %v", code, out)
	}
	if code, out = call(t, ts, "POST", "/v1/revoke", token, map[string]any{"id": id, "reason": "customer deletion"}, nil); code != 200 {
		t.Fatalf("revoke: %d %v", code, out)
	}
	code, out = call(t, ts, "POST", "/v1/open", token, map[string]any{"sealed": sealed, "entity": map[string]any{"id": "agent-eu", "attributes": []string{"team/support", "region/eu"}}}, nil)
	if code != 403 || out["code"] != "revoked" {
		t.Fatalf("after revoke: %d %v", code, out)
	}
	if code, _ = call(t, ts, "POST", "/v1/revoke", token, map[string]any{"id": "does-not-exist"}, nil); code != 404 {
		t.Fatalf("revoke unknown: %d", code)
	}

	code, out = call(t, ts, "GET", "/v1/audit?object_id="+id, token, nil, nil)
	if code != 200 {
		t.Fatalf("audit: %d", code)
	}
	evs := out["events"].([]any)
	if len(evs) != 5 {
		t.Fatalf("want 5 events (protect, open, deny, revoke, deny), got %d", len(evs))
	}
	code, out = call(t, ts, "GET", "/v1/audit/verify", token, nil, nil)
	if code != 200 || out["ok"] != true {
		t.Fatalf("verify: %d %v", code, out)
	}
}

func TestBadInput(t *testing.T) {
	ts := newServer(t, nil)
	cases := []struct {
		path string
		body any
	}{
		{"/v1/protect", map[string]any{"data": "not base64!!", "attributes": []string{"a"}}},
		{"/v1/protect", map[string]any{"data": "aGk=", "attributes": []string{}}},
		{"/v1/protect", map[string]any{"data": "aGk=", "attributes": []string{"a"}, "unknown": 1}},
		{"/v1/open", map[string]any{"sealed": "aGk="}},
		{"/v1/open", map[string]any{"sealed": "aGk=", "entity": map[string]any{"id": "e"}}},
		{"/v1/open", map[string]any{"sealed": "aGk=", "entity": map[string]any{"attributes": []string{"a"}}}},
	}
	for _, c := range cases {
		if code, out := call(t, ts, "POST", c.path, token, c.body, nil); code != 400 {
			t.Errorf("%s %v: got %d %v", c.path, c.body, code, out)
		}
	}
	if code, _ := call(t, ts, "GET", "/v1/audit?limit=-1", token, nil, nil); code != 400 {
		t.Errorf("negative limit: %d", code)
	}
	big := map[string]any{"data": base64.StdEncoding.EncodeToString(make([]byte, 2<<20)), "attributes": []string{"a"}}
	if code, _ := call(t, ts, "POST", "/v1/protect", token, big, nil); code != 413 {
		t.Errorf("oversize: %d", code)
	}
}

func TestRegistryModeIgnoresClaimedAttributes(t *testing.T) {
	reg, err := server.NewRegistry([]server.Entry{
		server.NewEntry("legal-agent", "legal-agent-token", "dept/legal"),
		server.NewEntry("intern", "intern-token", "dept/intern"),
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := newServer(t, reg)
	_, out := call(t, ts, "POST", "/v1/protect", token, map[string]any{"data": "c2VjcmV0", "attributes": []string{"dept/legal"}}, nil)
	sealed := out["sealed"].(string)

	if code, _ := call(t, ts, "POST", "/v1/open", token, map[string]any{"sealed": sealed, "entity": map[string]any{"id": "intern", "attributes": []string{"dept/legal"}}}, map[string]string{server.EntityTokenHeader: "intern-token"}); code != 400 {
		t.Fatalf("body entity must be rejected in registry mode, got %d", code)
	}
	if code, _ := call(t, ts, "POST", "/v1/open", token, map[string]any{"sealed": sealed}, nil); code != 401 {
		t.Fatalf("missing entity token: %d", code)
	}
	if code, _ := call(t, ts, "POST", "/v1/open", token, map[string]any{"sealed": sealed}, map[string]string{server.EntityTokenHeader: "nope"}); code != 401 {
		t.Fatalf("unknown entity token: %d", code)
	}
	if code, _ := call(t, ts, "POST", "/v1/open", token, map[string]any{"sealed": sealed}, map[string]string{server.EntityTokenHeader: "intern-token"}); code != 403 {
		t.Fatalf("intern must be denied: %d", code)
	}
	code, out := call(t, ts, "POST", "/v1/open", token, map[string]any{"sealed": sealed}, map[string]string{server.EntityTokenHeader: "legal-agent-token"})
	if code != 200 || out["data"] != "c2VjcmV0" {
		t.Fatalf("legal agent: %d %v", code, out)
	}
}

func TestRegistryValidation(t *testing.T) {
	if _, err := server.NewRegistry([]server.Entry{{ID: "x", TokenSHA256: "short"}}); err == nil {
		t.Fatal("bad hash must fail")
	}
	e := server.NewEntry("a", "same")
	e2 := server.NewEntry("b", "same")
	if _, err := server.NewRegistry([]server.Entry{e, e2}); err == nil {
		t.Fatal("duplicate token must fail")
	}
}
