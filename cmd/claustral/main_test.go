package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

type cli struct {
	t   *testing.T
	env map[string]string
}

func (c *cli) run(stdin []byte, args ...string) (int, []byte, string) {
	var out, errb bytes.Buffer
	code := run(args, func(k string) string { return c.env[k] }, bytes.NewReader(stdin), &out, &errb)
	return code, out.Bytes(), errb.String()
}

func newCLI(t *testing.T) *cli {
	dir := t.TempDir()
	return &cli{t: t, env: map[string]string{"CLAUSTRAL_DATA_DIR": dir, "HOME": dir}}
}

func TestCLIEndToEnd(t *testing.T) {
	c := newCLI(t)
	if code, _, errs := c.run(nil, "protect", "-attr", "a"); code == 0 || !strings.Contains(errs, "keygen") {
		t.Fatalf("protect without key must fail pointing at keygen: %d %s", code, errs)
	}
	if code, _, errs := c.run(nil, "keygen"); code != 0 {
		t.Fatalf("keygen: %s", errs)
	}
	if code, _, _ := c.run(nil, "keygen"); code == 0 {
		t.Fatal("second keygen must refuse to overwrite")
	}

	code, sealed, errs := c.run([]byte("agent memory: user prefers tea"), "protect", "-attr", "user/alice", "-attr", "scope/memory", "-id", "mem-alice-0001")
	if code != 0 || !strings.Contains(errs, "mem-alice-0001") {
		t.Fatalf("protect: %d %s", code, errs)
	}
	if bytes.Contains(sealed, []byte("tea")) {
		t.Fatal("plaintext leaked into sealed output")
	}

	code, plain, errs := c.run(sealed, "open", "-entity", "assistant", "-attr", "user/alice", "-attr", "scope/memory")
	if code != 0 || string(plain) != "agent memory: user prefers tea" {
		t.Fatalf("open: %d %q %s", code, plain, errs)
	}
	if code, _, _ := c.run(sealed, "open", "-entity", "other", "-attr", "user/bob", "-attr", "scope/memory"); code != 3 {
		t.Fatalf("denied open must exit 3, got %d", code)
	}
	if code, _, _ := c.run(nil, "revoke", "-id", "mem-alice-0001", "-reason", "user asked to forget"); code != 0 {
		t.Fatal("revoke failed")
	}
	if code, _, errs := c.run(sealed, "open", "-entity", "assistant", "-attr", "user/alice", "-attr", "scope/memory"); code != 3 || !strings.Contains(errs, "revoked") {
		t.Fatalf("revoked open: %d %s", code, errs)
	}

	code, out, _ := c.run(sealed, "inspect")
	if code != 0 || !strings.Contains(string(out), "revoked_at") {
		t.Fatalf("inspect: %d %s", code, out)
	}

	code, out, _ = c.run(nil, "audit", "-object", "mem-alice-0001")
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if code != 0 || len(lines) != 5 {
		t.Fatalf("audit: %d %d lines\n%s", code, len(lines), out)
	}
	var last map[string]any
	_ = json.Unmarshal([]byte(lines[4]), &last)
	if last["outcome"] != "deny" || last["reason"] != "revoked" {
		t.Fatalf("last event: %v", last)
	}
	if code, out, _ := c.run(nil, "audit", "-verify"); code != 0 || !strings.Contains(string(out), `"ok": true`) {
		t.Fatalf("verify: %d %s", code, out)
	}
}

func TestCLIEnvMasterKey(t *testing.T) {
	c := newCLI(t)
	code, key, _ := c.run(nil, "keygen", "-print")
	if code != 0 {
		t.Fatal("keygen -print")
	}
	c.env["CLAUSTRAL_MASTER_KEY"] = strings.TrimSpace(string(key))
	code, sealed, _ := c.run([]byte("x"), "protect", "-attr", "a")
	if code != 0 {
		t.Fatal("protect with env key")
	}
	c.env["CLAUSTRAL_MASTER_KEY"] = "secret"
	if code, _, _ := c.run(sealed, "open", "-entity", "e", "-attr", "a"); code == 0 {
		t.Fatal("weak master key must be rejected")
	}
}

func TestCLIUsageErrors(t *testing.T) {
	c := newCLI(t)
	for _, args := range [][]string{{}, {"bogus"}, {"protect"}, {"open"}, {"revoke"}} {
		if code, _, _ := c.run(nil, args...); code != 2 {
			t.Errorf("%v: got %d", args, code)
		}
	}
	if code, _, errs := c.run(nil, "serve"); code == 0 || !strings.Contains(errs, "CLAUSTRAL_API_TOKEN") {
		t.Fatalf("serve without token must refuse: %d %s", code, errs)
	}
	c.env["CLAUSTRAL_BACKEND"] = "nope"
	c.env["CLAUSTRAL_MASTER_KEY_FILE"] = filepath.Join(t.TempDir(), "k")
	if code, _, errs := c.run([]byte("x"), "protect", "-attr", "a"); code == 0 || !strings.Contains(errs, "unknown backend") {
		t.Fatalf("unknown backend: %d %s", code, errs)
	}
}
