package claustral

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"unicode"
)

const maxAttributeLen = 512

type Policy struct {
	Attributes []string `json:"attributes"`
}

func NewPolicy(attrs ...string) (Policy, error) {
	p := Policy{Attributes: attrs}.Normalize()
	if err := p.Validate(); err != nil {
		return Policy{}, err
	}
	return p, nil
}

func (p Policy) Normalize() Policy {
	out := make([]string, 0, len(p.Attributes))
	for _, a := range p.Attributes {
		a = strings.TrimSpace(a)
		if a != "" {
			out = append(out, a)
		}
	}
	slices.Sort(out)
	return Policy{Attributes: slices.Compact(out)}
}

func (p Policy) Validate() error {
	if len(p.Attributes) == 0 {
		return fmt.Errorf("%w: at least one attribute is required", ErrInvalidPolicy)
	}
	for _, a := range p.Attributes {
		if err := validateAttribute(a); err != nil {
			return err
		}
	}
	return nil
}

func (p Policy) Equal(o Policy) bool {
	return slices.Equal(p.Normalize().Attributes, o.Normalize().Attributes)
}

func (p Policy) Digest() string {
	h := sha256.New()
	for _, a := range p.Normalize().Attributes {
		h.Write([]byte(a))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (p Policy) Allows(e Entity) bool {
	if len(p.Attributes) == 0 {
		return false
	}
	held := make(map[string]struct{}, len(e.Attributes))
	for _, a := range e.Attributes {
		held[strings.TrimSpace(a)] = struct{}{}
	}
	for _, need := range p.Attributes {
		if _, ok := held[need]; !ok {
			return false
		}
	}
	return true
}

func (p Policy) Missing(e Entity) []string {
	held := make(map[string]struct{}, len(e.Attributes))
	for _, a := range e.Attributes {
		held[strings.TrimSpace(a)] = struct{}{}
	}
	var missing []string
	for _, need := range p.Attributes {
		if _, ok := held[need]; !ok {
			missing = append(missing, need)
		}
	}
	return missing
}

func validateAttribute(a string) error {
	if a == "" {
		return fmt.Errorf("%w: empty attribute", ErrInvalidPolicy)
	}
	if len(a) > maxAttributeLen {
		return fmt.Errorf("%w: attribute longer than %d bytes", ErrInvalidPolicy, maxAttributeLen)
	}
	for _, r := range a {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return fmt.Errorf("%w: attribute %q contains whitespace or control characters", ErrInvalidPolicy, a)
		}
	}
	return nil
}

type Entity struct {
	ID         string   `json:"id"`
	Attributes []string `json:"attributes"`
	Token      string   `json:"-"`
}

func (e Entity) Validate() error {
	if strings.TrimSpace(e.ID) == "" {
		return fmt.Errorf("%w: entity id is required", ErrInvalidEntity)
	}
	return nil
}
