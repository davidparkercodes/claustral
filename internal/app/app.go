package app

import (
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/davidparkercodes/claustral/pkg/audit"
	"github.com/davidparkercodes/claustral/pkg/claustral"
	"github.com/davidparkercodes/claustral/pkg/local"
	"github.com/davidparkercodes/claustral/pkg/sqlite"
)

type Getenv func(string) string

type App struct {
	Client  *claustral.Client
	Audit   *audit.Log
	Local   *local.Backend
	DataDir string
	closers []io.Closer
}

func (a *App) Close() error {
	var errs []error
	for i := len(a.closers) - 1; i >= 0; i-- {
		errs = append(errs, a.closers[i].Close())
	}
	return errors.Join(errs...)
}

type BackendFactory func(env Getenv, db *sql.DB, dataDir string) (claustral.Backend, io.Closer, error)

var factories = map[string]BackendFactory{
	local.BackendName: newLocal,
}

func Backends() []string {
	names := make([]string, 0, len(factories))
	for n := range factories {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func DataDir(env Getenv) (string, error) {
	if d := env("CLAUSTRAL_DATA_DIR"); d != "" {
		return d, nil
	}
	if x := env("XDG_DATA_HOME"); x != "" {
		return filepath.Join(x, "claustral"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine data dir; set CLAUSTRAL_DATA_DIR: %w", err)
	}
	return filepath.Join(home, ".local", "share", "claustral"), nil
}

func MasterKeyPath(env Getenv, dataDir string) string {
	if p := env("CLAUSTRAL_MASTER_KEY_FILE"); p != "" {
		return p
	}
	return filepath.Join(dataDir, "master.key")
}

func Open(env Getenv) (*App, error) {
	dataDir, err := DataDir(env)
	if err != nil {
		return nil, err
	}
	name := strings.ToLower(env("CLAUSTRAL_BACKEND"))
	if name == "" {
		name = local.BackendName
	}
	factory, ok := factories[name]
	if !ok {
		return nil, fmt.Errorf("unknown backend %q (available in this build: %s)", name, strings.Join(Backends(), ", "))
	}
	dbPath := env("CLAUSTRAL_DB")
	if dbPath == "" {
		dbPath = filepath.Join(dataDir, "claustral.db")
	}
	db, err := sqlite.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("open database %s: %w", dbPath, err)
	}
	a := &App{DataDir: dataDir, closers: []io.Closer{db}}
	if a.Audit, err = audit.New(db); err != nil {
		a.Close()
		return nil, err
	}
	backend, closer, err := factory(env, db, dataDir)
	if err != nil {
		a.Close()
		return nil, err
	}
	if closer != nil {
		a.closers = append(a.closers, closer)
	}
	if lb, ok := backend.(*local.Backend); ok {
		a.Local = lb
	}
	if a.Client, err = claustral.New(backend, a.Audit); err != nil {
		a.Close()
		return nil, err
	}
	return a, nil
}

func newLocal(env Getenv, db *sql.DB, dataDir string) (claustral.Backend, io.Closer, error) {
	var key *local.MasterKey
	var err error
	if v := env("CLAUSTRAL_MASTER_KEY"); v != "" {
		key, err = local.ParseMasterKey(v)
		if err != nil {
			return nil, nil, fmt.Errorf("CLAUSTRAL_MASTER_KEY: %w", err)
		}
	} else {
		key, err = local.LoadMasterKeyFile(MasterKeyPath(env, dataDir))
		if err != nil {
			return nil, nil, err
		}
	}
	b, err := local.New(db, key)
	return b, nil, err
}
