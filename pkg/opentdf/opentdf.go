//go:build opentdf

package opentdf

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/opentdf/platform/sdk"
	"golang.org/x/oauth2"

	"github.com/davidparkercodes/claustral/pkg/claustral"
)

type Config struct {
	PlatformEndpoint string
	ClientID         string
	ClientSecret     string
	TokenEndpoint    string
	KASURL           string
	Insecure         bool
}

func (c Config) validate() error {
	var missing []string
	if c.PlatformEndpoint == "" {
		missing = append(missing, "platform endpoint")
	}
	if c.ClientID == "" {
		missing = append(missing, "client id")
	}
	if c.ClientSecret == "" {
		missing = append(missing, "client secret")
	}
	if len(missing) > 0 {
		return fmt.Errorf("opentdf: missing %s", strings.Join(missing, ", "))
	}
	if !c.Insecure && strings.HasPrefix(c.PlatformEndpoint, "http://") {
		return errors.New("opentdf: plaintext http platform endpoint requires Insecure=true")
	}
	return nil
}

type Backend struct {
	cfg Config
	sdk *sdk.SDK
}

var _ claustral.Backend = (*Backend)(nil)

func New(cfg Config) (*Backend, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if cfg.KASURL == "" {
		cfg.KASURL = strings.TrimRight(cfg.PlatformEndpoint, "/") + "/kas"
	}
	opts := append(baseOptions(cfg), sdk.WithClientCredentials(cfg.ClientID, cfg.ClientSecret, nil))
	s, err := sdk.New(cfg.PlatformEndpoint, opts...)
	if err != nil {
		return nil, fmt.Errorf("opentdf: connect: %w", err)
	}
	return &Backend{cfg: cfg, sdk: s}, nil
}

func baseOptions(cfg Config) []sdk.Option {
	var opts []sdk.Option
	if cfg.Insecure {
		opts = append(opts, sdk.WithInsecurePlaintextConn())
	}
	if cfg.TokenEndpoint != "" {
		opts = append(opts, sdk.WithTokenEndpoint(cfg.TokenEndpoint))
	}
	return opts
}

func (b *Backend) Close() error { return b.sdk.Close() }

func (b *Backend) Name() string { return BackendName }

func (b *Backend) Seal(ctx context.Context, id string, data []byte, p claustral.Policy) ([]byte, error) {
	p = p.Normalize()
	if err := p.Validate(); err != nil {
		return nil, err
	}
	meta, _ := json.Marshal(metadata{ID: id})
	var buf bytes.Buffer
	_, err := b.sdk.CreateTDFContext(ctx, &buf, bytes.NewReader(data),
		sdk.WithDataAttributes(p.Attributes...),
		sdk.WithKasInformation(sdk.KASInfo{URL: b.cfg.KASURL, Default: true}),
		sdk.WithMetaData(string(meta)),
	)
	if err != nil {
		return nil, fmt.Errorf("opentdf: create tdf: %w", err)
	}
	return wrap(id, p, buf.Bytes())
}

func (b *Backend) Inspect(blob []byte) (claustral.Meta, error) {
	h, _, err := unwrap(blob)
	if err != nil {
		return claustral.Meta{}, err
	}
	return claustral.Meta{ID: h.ID, Backend: BackendName, Policy: h.Policy}, nil
}

func (b *Backend) Unseal(ctx context.Context, blob []byte, e claustral.Entity) ([]byte, claustral.Meta, error) {
	h, ztdf, err := unwrap(blob)
	if err != nil {
		return nil, claustral.Meta{}, err
	}
	meta := claustral.Meta{ID: h.ID, Backend: BackendName, Policy: h.Policy}

	client := b.sdk
	if e.Token != "" {
		opts := append(baseOptions(b.cfg), sdk.WithOAuthAccessTokenSource(oauth2.StaticTokenSource(&oauth2.Token{AccessToken: e.Token, TokenType: "Bearer"})))
		client, err = sdk.New(b.cfg.PlatformEndpoint, opts...)
		if err != nil {
			return nil, meta, fmt.Errorf("opentdf: connect as entity: %w", err)
		}
		defer client.Close()
	}

	r, err := client.LoadTDF(bytes.NewReader(ztdf), sdk.WithKasAllowlist([]string{b.cfg.KASURL}))
	if err != nil {
		return nil, meta, fmt.Errorf("%w: %v", claustral.ErrMalformed, err)
	}
	attrs, err := r.DataAttributes()
	if err != nil {
		return nil, meta, fmt.Errorf("%w: %v", claustral.ErrMalformed, err)
	}
	if !h.Policy.Equal(claustral.Policy{Attributes: attrs}) {
		return nil, meta, fmt.Errorf("%w: envelope policy does not match TDF policy", claustral.ErrMalformed)
	}
	if err := r.Init(ctx); err != nil {
		if errors.Is(err, sdk.ErrRewrapForbidden) {
			return nil, meta, fmt.Errorf("%w: platform denied key access", claustral.ErrDenied)
		}
		return nil, meta, fmt.Errorf("opentdf: key access: %w", err)
	}
	var m metadata
	raw, err := r.UnencryptedMetadata()
	if err != nil || json.Unmarshal(raw, &m) != nil || m.ID != h.ID {
		return nil, meta, fmt.Errorf("%w: object id not bound to TDF", claustral.ErrMalformed)
	}
	var out bytes.Buffer
	if _, err := r.WriteTo(&out); err != nil {
		return nil, meta, fmt.Errorf("%w: %v", claustral.ErrMalformed, err)
	}
	return out.Bytes(), meta, nil
}

func (b *Backend) Revoke(context.Context, string) error {
	return fmt.Errorf("%w: OpenTDF revokes access through platform entitlements (subject mappings) and attribute values, not per object", claustral.ErrUnsupported)
}
