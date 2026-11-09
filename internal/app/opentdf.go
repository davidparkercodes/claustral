//go:build opentdf

package app

import (
	"database/sql"
	"io"

	"github.com/davidparkercodes/claustral/pkg/claustral"
	"github.com/davidparkercodes/claustral/pkg/opentdf"
)

func init() {
	factories[opentdf.BackendName] = func(env Getenv, _ *sql.DB, _ string) (claustral.Backend, io.Closer, error) {
		b, err := opentdf.New(opentdf.Config{
			PlatformEndpoint: env("CLAUSTRAL_OPENTDF_ENDPOINT"),
			ClientID:         env("CLAUSTRAL_OPENTDF_CLIENT_ID"),
			ClientSecret:     env("CLAUSTRAL_OPENTDF_CLIENT_SECRET"),
			TokenEndpoint:    env("CLAUSTRAL_OPENTDF_TOKEN_ENDPOINT"),
			KASURL:           env("CLAUSTRAL_OPENTDF_KAS_URL"),
			Insecure:         env("CLAUSTRAL_OPENTDF_INSECURE") == "1",
		})
		if err != nil {
			return nil, nil, err
		}
		return b, b, nil
	}
}
