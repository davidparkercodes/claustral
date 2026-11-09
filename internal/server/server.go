package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/davidparkercodes/claustral/pkg/audit"
	"github.com/davidparkercodes/claustral/pkg/claustral"
)

const (
	MinTokenLen       = 32
	DefaultMaxBody    = 32 << 20
	EntityTokenHeader = "X-Claustral-Entity-Token"
)

type Config struct {
	Client   *claustral.Client
	Audit    *audit.Log
	Token    string
	Entities *Registry
	MaxBody  int64
	Logger   *slog.Logger
}

type Server struct {
	cfg   Config
	token []byte
	mux   *http.ServeMux
}

func New(cfg Config) (*Server, error) {
	if cfg.Client == nil || cfg.Audit == nil {
		return nil, errors.New("server: client and audit log are required")
	}
	if len(strings.TrimSpace(cfg.Token)) < MinTokenLen {
		return nil, fmt.Errorf("server: API token must be at least %d characters", MinTokenLen)
	}
	if cfg.MaxBody <= 0 {
		cfg.MaxBody = DefaultMaxBody
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	s := &Server{cfg: cfg, token: []byte(strings.TrimSpace(cfg.Token)), mux: http.NewServeMux()}
	s.mux.HandleFunc("GET /healthz", s.health)
	s.mux.HandleFunc("POST /v1/protect", s.auth(s.protect))
	s.mux.HandleFunc("POST /v1/open", s.auth(s.open))
	s.mux.HandleFunc("POST /v1/inspect", s.auth(s.inspect))
	s.mux.HandleFunc("POST /v1/revoke", s.auth(s.revoke))
	s.mux.HandleFunc("GET /v1/audit", s.auth(s.auditList))
	s.mux.HandleFunc("GET /v1/audit/verify", s.auth(s.auditVerify))
	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if len(s.token) == 0 {
			writeErr(w, http.StatusServiceUnavailable, "unavailable", "API token not configured")
			return
		}
		scheme, tok, ok := strings.Cut(r.Header.Get("Authorization"), " ")
		if !ok || !strings.EqualFold(scheme, "bearer") || subtle.ConstantTimeCompare([]byte(strings.TrimSpace(tok)), s.token) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="claustral"`)
			writeErr(w, http.StatusUnauthorized, "unauthorized", "missing or invalid bearer token")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxBody)
		next(w, r)
	}
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "backend": s.cfg.Client.Backend().Name()})
}

type protectReq struct {
	Data       string   `json:"data"`
	Attributes []string `json:"attributes"`
	ID         string   `json:"id,omitempty"`
	Actor      string   `json:"actor,omitempty"`
}

type sealedResp struct {
	ID     string `json:"id"`
	Sealed string `json:"sealed"`
}

func (s *Server) protect(w http.ResponseWriter, r *http.Request) {
	var req protectReq
	if !decode(w, r, &req) {
		return
	}
	data, err := b64(req.Data)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "data must be standard base64")
		return
	}
	opts := []claustral.ProtectOption{claustral.WithActor(actorOr(req.Actor))}
	if req.ID != "" {
		opts = append(opts, claustral.WithObjectID(req.ID))
	}
	sealed, err := s.cfg.Client.Protect(r.Context(), data, claustral.Policy{Attributes: req.Attributes}, opts...)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, sealedResp{ID: sealed.ID, Sealed: base64.StdEncoding.EncodeToString(sealed.Blob)})
}

type openReq struct {
	Sealed string            `json:"sealed"`
	Entity *claustral.Entity `json:"entity,omitempty"`
}

func (s *Server) open(w http.ResponseWriter, r *http.Request) {
	var req openReq
	if !decode(w, r, &req) {
		return
	}
	blob, err := b64(req.Sealed)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "sealed must be standard base64")
		return
	}
	var entity claustral.Entity
	if s.cfg.Entities != nil {
		if req.Entity != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", "entity is resolved from "+EntityTokenHeader+"; do not send it in the body")
			return
		}
		e, ok := s.cfg.Entities.Lookup(r.Header.Get(EntityTokenHeader))
		if !ok {
			writeErr(w, http.StatusUnauthorized, "unauthorized", "missing or unknown entity token")
			return
		}
		entity = e
	} else {
		if req.Entity == nil {
			writeErr(w, http.StatusBadRequest, "bad_request", "entity is required")
			return
		}
		entity = *req.Entity
	}
	data, err := s.cfg.Client.Open(r.Context(), blob, entity)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"data": base64.StdEncoding.EncodeToString(data)})
}

func (s *Server) inspect(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Sealed string `json:"sealed"`
	}
	if !decode(w, r, &req) {
		return
	}
	blob, err := b64(req.Sealed)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "sealed must be standard base64")
		return
	}
	meta, err := s.cfg.Client.Inspect(blob)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, meta)
}

func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID     string `json:"id"`
		Reason string `json:"reason"`
		Actor  string `json:"actor"`
	}
	if !decode(w, r, &req) {
		return
	}
	if err := s.cfg.Client.Revoke(r.Context(), req.ID, actorOr(req.Actor), req.Reason); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": req.ID, "revoked": true})
}

func (s *Server) auditList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := audit.Filter{
		ObjectID: q.Get("object_id"),
		EntityID: q.Get("entity_id"),
		Action:   claustral.Action(q.Get("action")),
		Outcome:  claustral.Outcome(q.Get("outcome")),
	}
	var err error
	if f.AfterSeq, err = intParam(q.Get("after"), 0); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "after must be a non-negative integer")
		return
	}
	limit, err := intParam(q.Get("limit"), 100)
	if err != nil || limit > 10000 {
		writeErr(w, http.StatusBadRequest, "bad_request", "limit must be 0-10000")
		return
	}
	f.Limit = int(limit)
	events, err := s.cfg.Audit.Query(r.Context(), f)
	if err != nil {
		s.fail(w, err)
		return
	}
	if events == nil {
		events = []claustral.Event{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}

func (s *Server) auditVerify(w http.ResponseWriter, r *http.Request) {
	res, err := s.cfg.Audit.Verify(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, claustral.ErrAudit):
		s.cfg.Logger.Error("audit failure", "err", err)
		writeErr(w, http.StatusServiceUnavailable, "audit_unavailable", "audit log unavailable; operation refused")
	case errors.Is(err, claustral.ErrRevoked):
		writeErr(w, http.StatusForbidden, "revoked", "object has been revoked")
	case errors.Is(err, claustral.ErrDenied):
		writeErr(w, http.StatusForbidden, "denied", err.Error())
	case errors.Is(err, claustral.ErrNotFound):
		writeErr(w, http.StatusNotFound, "not_found", "unknown object")
	case errors.Is(err, claustral.ErrInvalidPolicy), errors.Is(err, claustral.ErrInvalidEntity), errors.Is(err, claustral.ErrMalformed):
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
	case errors.Is(err, claustral.ErrUnsupported):
		writeErr(w, http.StatusNotImplemented, "unsupported", err.Error())
	default:
		s.cfg.Logger.Error("request failed", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "internal error")
	}
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeErr(w, http.StatusRequestEntityTooLarge, "too_large", "request body too large")
			return false
		}
		writeErr(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return false
	}
	return true
}

func b64(s string) ([]byte, error) {
	return base64.StdEncoding.Strict().DecodeString(s)
}

func actorOr(a string) string {
	if a == "" {
		return "api"
	}
	return a
}

func intParam(s string, def int64) (int64, error) {
	if s == "" {
		return def, nil
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil || v < 0 {
		return 0, errors.New("invalid")
	}
	return v, nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]string{"error": msg, "code": code})
}

type Entry struct {
	ID          string   `json:"id"`
	TokenSHA256 string   `json:"token_sha256"`
	Attributes  []string `json:"attributes"`
	hash        []byte
}

type Registry struct {
	entries []Entry
}

func LoadRegistry(path string) (*Registry, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Entities []Entry `json:"entities"`
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("entities file: %w", err)
	}
	return NewRegistry(doc.Entities)
}

func NewRegistry(entries []Entry) (*Registry, error) {
	seen := map[string]bool{}
	for i := range entries {
		e := &entries[i]
		if strings.TrimSpace(e.ID) == "" {
			return nil, fmt.Errorf("entities file: entry %d has no id", i)
		}
		h, err := hex.DecodeString(e.TokenSHA256)
		if err != nil || len(h) != sha256.Size {
			return nil, fmt.Errorf("entities file: entity %s token_sha256 must be 64 hex chars", e.ID)
		}
		if seen[e.TokenSHA256] {
			return nil, fmt.Errorf("entities file: duplicate token for entity %s", e.ID)
		}
		seen[e.TokenSHA256] = true
		e.hash = h
	}
	return &Registry{entries: entries}, nil
}

func NewEntry(id, token string, attrs ...string) Entry {
	sum := sha256.Sum256([]byte(token))
	return Entry{ID: id, TokenSHA256: hex.EncodeToString(sum[:]), Attributes: attrs}
}

func (r *Registry) Lookup(token string) (claustral.Entity, bool) {
	token = strings.TrimSpace(token)
	if token == "" {
		return claustral.Entity{}, false
	}
	sum := sha256.Sum256([]byte(token))
	var found *Entry
	for i := range r.entries {
		if subtle.ConstantTimeCompare(sum[:], r.entries[i].hash) == 1 {
			found = &r.entries[i]
		}
	}
	if found == nil {
		return claustral.Entity{}, false
	}
	return claustral.Entity{ID: found.ID, Attributes: append([]string(nil), found.Attributes...)}, true
}
