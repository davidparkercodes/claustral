package opentdf

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/davidparkercodes/claustral/pkg/claustral"
)

const (
	BackendName   = "opentdf"
	formatVersion = 1
	maxHeaderLen  = 64 << 10
)

var magic = []byte("CLSO")

type header struct {
	Version int              `json:"v"`
	ID      string           `json:"id"`
	Backend string           `json:"backend"`
	Policy  claustral.Policy `json:"policy"`
}

type metadata struct {
	ID string `json:"claustral_id"`
}

func wrap(id string, p claustral.Policy, ztdf []byte) ([]byte, error) {
	hdr, err := json.Marshal(header{Version: formatVersion, ID: id, Backend: BackendName, Policy: p})
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(magic)+5+len(hdr)+len(ztdf))
	out = append(out, magic...)
	out = append(out, formatVersion)
	out = binary.BigEndian.AppendUint32(out, uint32(len(hdr)))
	out = append(out, hdr...)
	return append(out, ztdf...), nil
}

func unwrap(blob []byte) (header, []byte, error) {
	var h header
	fixed := len(magic) + 5
	if len(blob) < fixed || !bytes.Equal(blob[:len(magic)], magic) {
		return h, nil, fmt.Errorf("%w: not a claustral opentdf object", claustral.ErrMalformed)
	}
	if blob[len(magic)] != formatVersion {
		return h, nil, fmt.Errorf("%w: unsupported format version", claustral.ErrMalformed)
	}
	hlen := binary.BigEndian.Uint32(blob[len(magic)+1 : fixed])
	if hlen == 0 || hlen > maxHeaderLen || int(hlen) > len(blob)-fixed {
		return h, nil, fmt.Errorf("%w: bad header length", claustral.ErrMalformed)
	}
	if err := json.Unmarshal(blob[fixed:fixed+int(hlen)], &h); err != nil {
		return h, nil, fmt.Errorf("%w: bad header: %v", claustral.ErrMalformed, err)
	}
	if h.Version != formatVersion || h.Backend != BackendName || claustral.ValidateID(h.ID) != nil {
		return h, nil, fmt.Errorf("%w: bad header fields", claustral.ErrMalformed)
	}
	return h, blob[fixed+int(hlen):], nil
}
