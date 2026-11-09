package opentdf

import (
	"errors"
	"testing"

	"github.com/davidparkercodes/claustral/pkg/claustral"
)

func TestEnvelopeRoundTrip(t *testing.T) {
	p, _ := claustral.NewPolicy("https://example.com/attr/classification/value/secret")
	blob, err := wrap("obj-00000001", p, []byte("PK\x03\x04ztdf"))
	if err != nil {
		t.Fatal(err)
	}
	h, inner, err := unwrap(blob)
	if err != nil {
		t.Fatal(err)
	}
	if h.ID != "obj-00000001" || !h.Policy.Equal(p) || string(inner) != "PK\x03\x04ztdf" {
		t.Fatalf("%+v %q", h, inner)
	}
	for _, bad := range [][]byte{nil, []byte("CLSO"), []byte("CLST\x01\x00\x00\x00\x02{}"), append([]byte("CLSO\x01\xff\xff\xff\xff"), 'x')} {
		if _, _, err := unwrap(bad); !errors.Is(err, claustral.ErrMalformed) {
			t.Errorf("%q: got %v", bad, err)
		}
	}
}
