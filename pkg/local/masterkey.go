package local

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const KeySize = 32

type MasterKey struct {
	key [KeySize]byte
	id  string
}

func (m *MasterKey) ID() string { return m.id }

func NewMasterKey(raw []byte) (*MasterKey, error) {
	if len(raw) != KeySize {
		return nil, fmt.Errorf("master key must be %d bytes, got %d", KeySize, len(raw))
	}
	allZero := true
	for _, b := range raw {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return nil, errors.New("master key is all zeros")
	}
	m := &MasterKey{}
	copy(m.key[:], raw)
	sum := sha256.Sum256(append([]byte("claustral/local/kek-id\x00"), raw...))
	m.id = hex.EncodeToString(sum[:8])
	return m, nil
}

func GenerateMasterKey() (*MasterKey, error) {
	raw := make([]byte, KeySize)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	return NewMasterKey(raw)
}

func (m *MasterKey) Encode() string {
	return hex.EncodeToString(m.key[:])
}

func ParseMasterKey(s string) (*MasterKey, error) {
	s = strings.TrimSpace(s)
	if raw, err := hex.DecodeString(s); err == nil && len(raw) == KeySize {
		return NewMasterKey(raw)
	}
	if raw, err := base64.StdEncoding.DecodeString(s); err == nil && len(raw) == KeySize {
		return NewMasterKey(raw)
	}
	return nil, fmt.Errorf("master key must be %d bytes encoded as hex (64 chars) or base64", KeySize)
}

func LoadMasterKeyFile(path string) (*MasterKey, error) {
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("master key file %s not found (create one with `claustral keygen`)", path)
		}
		return nil, err
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("master key file %s is accessible by group or others (mode %v); chmod 600 it", path, info.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseMasterKey(string(b))
}

func WriteMasterKeyFile(path string, m *MasterKey) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("refusing to overwrite existing master key %s", path)
		}
		return err
	}
	if _, err := f.WriteString(m.Encode() + "\n"); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
