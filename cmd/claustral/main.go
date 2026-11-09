package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/davidparkercodes/claustral/internal/app"
	"github.com/davidparkercodes/claustral/internal/server"
	"github.com/davidparkercodes/claustral/pkg/audit"
	"github.com/davidparkercodes/claustral/pkg/claustral"
	"github.com/davidparkercodes/claustral/pkg/local"
)

var version = "0.1.0"

const usage = `claustral seals data under attribute policies and audits every access.

Usage:
  claustral keygen  [-out path | -print]
  claustral protect -attr A [-attr B ...] [-in file] [-out file] [-id ID] [-actor NAME]
  claustral open    -entity ID -attr A [-attr B ...] [-entity-token T] [-in file] [-out file]
  claustral inspect [-in file]
  claustral revoke  -id ID [-reason TEXT] [-actor NAME]
  claustral audit   [-object ID] [-entity ID] [-limit N] [-verify]
  claustral serve   [-addr host:port] [-entities file]
  claustral version

Environment:
  CLAUSTRAL_BACKEND           local (default) or opentdf (requires -tags opentdf build)
  CLAUSTRAL_DATA_DIR          data directory (default $XDG_DATA_HOME/claustral or ~/.local/share/claustral)
  CLAUSTRAL_DB                SQLite path (default <data dir>/claustral.db)
  CLAUSTRAL_MASTER_KEY        local master key, hex or base64 (overrides the key file)
  CLAUSTRAL_MASTER_KEY_FILE   local master key file (default <data dir>/master.key)
  CLAUSTRAL_API_TOKEN         bearer token for serve (required, at least 32 characters)
  CLAUSTRAL_OPENTDF_*         ENDPOINT, CLIENT_ID, CLIENT_SECRET, TOKEN_ENDPOINT, KAS_URL, INSECURE=1
`

func main() {
	os.Exit(run(os.Args[1:], os.Getenv, os.Stdin, os.Stdout, os.Stderr))
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func run(args []string, env app.Getenv, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	cmd, rest := args[0], args[1:]
	var err error
	switch cmd {
	case "keygen":
		err = cmdKeygen(rest, env, stdout, stderr)
	case "protect":
		err = cmdProtect(rest, env, stdin, stdout, stderr)
	case "open":
		err = cmdOpen(rest, env, stdin, stdout, stderr)
	case "inspect":
		err = cmdInspect(rest, env, stdin, stdout, stderr)
	case "revoke":
		err = cmdRevoke(rest, env, stdout, stderr)
	case "audit":
		err = cmdAudit(rest, env, stdout, stderr)
	case "serve":
		err = cmdServe(rest, env, stderr)
	case "version", "-v", "--version":
		fmt.Fprintln(stdout, "claustral", version, "backends:", strings.Join(app.Backends(), ","))
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", cmd, usage)
		return 2
	}
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 2
		}
		fmt.Fprintln(stderr, "error:", err)
		switch {
		case errors.Is(err, claustral.ErrDenied), errors.Is(err, claustral.ErrRevoked):
			return 3
		case errors.Is(err, errUsage):
			return 2
		}
		return 1
	}
	return 0
}

var errUsage = errors.New("usage")

func newFlags(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

func cmdKeygen(args []string, env app.Getenv, stdout, stderr io.Writer) error {
	fs := newFlags("keygen", stderr)
	out := fs.String("out", "", "key file to create (default <data dir>/master.key)")
	printKey := fs.Bool("print", false, "print the key to stdout instead of writing a file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	k, err := local.GenerateMasterKey()
	if err != nil {
		return err
	}
	if *printKey {
		fmt.Fprintln(stdout, k.Encode())
		return nil
	}
	path := *out
	if path == "" {
		dir, err := app.DataDir(env)
		if err != nil {
			return err
		}
		path = app.MasterKeyPath(env, dir)
	}
	if err := local.WriteMasterKeyFile(path, k); err != nil {
		return err
	}
	fmt.Fprintf(stderr, "wrote master key %s (id %s). Back it up: losing it makes every object unrecoverable.\n", path, k.ID())
	return nil
}

func cmdProtect(args []string, env app.Getenv, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := newFlags("protect", stderr)
	var attrs multi
	fs.Var(&attrs, "attr", "required attribute (repeatable; entity must hold all)")
	in := fs.String("in", "-", "input file or - for stdin")
	out := fs.String("out", "-", "output file or - for stdout")
	id := fs.String("id", "", "object id (default random)")
	actor := fs.String("actor", "cli", "actor recorded in the audit log")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(attrs) == 0 {
		return fmt.Errorf("%w: at least one -attr is required", errUsage)
	}
	data, err := readInput(*in, stdin)
	if err != nil {
		return err
	}
	a, err := app.Open(env)
	if err != nil {
		return err
	}
	defer a.Close()
	opts := []claustral.ProtectOption{claustral.WithActor(*actor)}
	if *id != "" {
		opts = append(opts, claustral.WithObjectID(*id))
	}
	s, err := a.Client.Protect(context.Background(), data, claustral.Policy{Attributes: attrs}, opts...)
	if err != nil {
		return err
	}
	if err := writeOutput(*out, stdout, s.Blob); err != nil {
		return err
	}
	fmt.Fprintln(stderr, "id:", s.ID)
	return nil
}

func cmdOpen(args []string, env app.Getenv, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := newFlags("open", stderr)
	var attrs multi
	fs.Var(&attrs, "attr", "attribute held by the entity (repeatable)")
	entityID := fs.String("entity", "", "entity id recorded in the audit log (required)")
	token := fs.String("entity-token", "", "entity access token (opentdf backend)")
	in := fs.String("in", "-", "sealed input file or - for stdin")
	out := fs.String("out", "-", "output file or - for stdout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *entityID == "" {
		return fmt.Errorf("%w: -entity is required", errUsage)
	}
	blob, err := readInput(*in, stdin)
	if err != nil {
		return err
	}
	a, err := app.Open(env)
	if err != nil {
		return err
	}
	defer a.Close()
	data, err := a.Client.Open(context.Background(), blob, claustral.Entity{ID: *entityID, Attributes: attrs, Token: *token})
	if err != nil {
		return err
	}
	return writeOutput(*out, stdout, data)
}

func cmdInspect(args []string, env app.Getenv, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := newFlags("inspect", stderr)
	in := fs.String("in", "-", "sealed input file or - for stdin")
	if err := fs.Parse(args); err != nil {
		return err
	}
	blob, err := readInput(*in, stdin)
	if err != nil {
		return err
	}
	a, err := app.Open(env)
	if err != nil {
		return err
	}
	defer a.Close()
	meta, err := a.Client.Inspect(blob)
	if err != nil {
		return err
	}
	out := map[string]any{"meta": meta}
	if a.Local != nil {
		if st, err := a.Local.Status(context.Background(), meta.ID); err == nil {
			out["status"] = st
		}
	}
	return printJSON(stdout, out)
}

func cmdRevoke(args []string, env app.Getenv, stdout, stderr io.Writer) error {
	fs := newFlags("revoke", stderr)
	id := fs.String("id", "", "object id to revoke (required)")
	reason := fs.String("reason", "", "reason recorded in the audit log")
	actor := fs.String("actor", "cli", "actor recorded in the audit log")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == "" {
		return fmt.Errorf("%w: -id is required", errUsage)
	}
	a, err := app.Open(env)
	if err != nil {
		return err
	}
	defer a.Close()
	if err := a.Client.Revoke(context.Background(), *id, *actor, *reason); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "revoked", *id)
	return nil
}

func cmdAudit(args []string, env app.Getenv, stdout, stderr io.Writer) error {
	fs := newFlags("audit", stderr)
	object := fs.String("object", "", "filter by object id")
	entity := fs.String("entity", "", "filter by entity id")
	after := fs.Int64("after", 0, "only events with seq greater than this")
	limit := fs.Int("limit", 100, "maximum events")
	verify := fs.Bool("verify", false, "verify the hash chain instead of listing")
	if err := fs.Parse(args); err != nil {
		return err
	}
	a, err := app.Open(env)
	if err != nil {
		return err
	}
	defer a.Close()
	ctx := context.Background()
	if *verify {
		res, err := a.Audit.Verify(ctx)
		if err != nil {
			return err
		}
		if err := printJSON(stdout, res); err != nil {
			return err
		}
		if !res.OK {
			return fmt.Errorf("audit chain broken at seq %d: %s", res.BrokenAt, res.Problem)
		}
		return nil
	}
	events, err := a.Audit.Query(ctx, audit.Filter{ObjectID: *object, EntityID: *entity, AfterSeq: *after, Limit: *limit})
	if err != nil {
		return err
	}
	enc := json.NewEncoder(stdout)
	for _, e := range events {
		if err := enc.Encode(e); err != nil {
			return err
		}
	}
	return nil
}

func cmdServe(args []string, env app.Getenv, stderr io.Writer) error {
	fs := newFlags("serve", stderr)
	addr := fs.String("addr", "127.0.0.1:8484", "listen address")
	entities := fs.String("entities", "", "entity registry JSON; when set, open resolves the entity from the "+server.EntityTokenHeader+" header")
	maxBody := fs.Int64("max-body", server.DefaultMaxBody, "maximum request body bytes")
	if err := fs.Parse(args); err != nil {
		return err
	}
	token := strings.TrimSpace(env("CLAUSTRAL_API_TOKEN"))
	if len(token) < server.MinTokenLen {
		return fmt.Errorf("CLAUSTRAL_API_TOKEN must be set to at least %d characters; refusing to serve without auth", server.MinTokenLen)
	}
	var reg *server.Registry
	if *entities != "" {
		var err error
		if reg, err = server.LoadRegistry(*entities); err != nil {
			return err
		}
	}
	a, err := app.Open(env)
	if err != nil {
		return err
	}
	defer a.Close()
	logger := slog.New(slog.NewTextHandler(stderr, nil))
	h, err := server.New(server.Config{Client: a.Client, Audit: a.Audit, Token: token, Entities: reg, MaxBody: *maxBody, Logger: logger})
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr:              *addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	mode := "trusted-caller entities"
	if reg != nil {
		mode = "entity registry"
	}
	logger.Info("claustral serving", "addr", *addr, "backend", a.Client.Backend().Name(), "entities", mode)
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

func readInput(path string, stdin io.Reader) ([]byte, error) {
	if path == "-" || path == "" {
		return io.ReadAll(stdin)
	}
	return os.ReadFile(path)
}

func writeOutput(path string, stdout io.Writer, data []byte) error {
	if path == "-" || path == "" {
		_, err := stdout.Write(data)
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func printJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
