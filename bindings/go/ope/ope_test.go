package ope_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/ClawBay/OPE/bindings/go/ope"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "../../.."))
}

func TestVector001DevVerify(t *testing.T) {
	root := repoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "spec/vectors/001-valid-plaintext.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Envelope json.RawMessage `json:"envelope"`
	}
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	if err := ope.EnvelopeVerifyDev(vector.Envelope); err != nil {
		t.Fatal(err)
	}
}

func TestSignVerifyRoundtrip(t *testing.T) {
	root := repoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "spec/vectors/001-valid-plaintext.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		SigningKeySeedHex string          `json:"signing_key_seed_hex"`
		VerifyingKeyHex   string          `json:"verifying_key_hex"`
		Envelope          json.RawMessage `json:"envelope"`
	}
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	var env map[string]any
	if err := json.Unmarshal(vector.Envelope, &env); err != nil {
		t.Fatal(err)
	}
	delete(env, "sig")
	env["payload_hash"] = ""
	env["ts"] = time.Now().UTC().Format("2006-01-02T15:04:05Z")

	secretBytes, _ := hex.DecodeString(vector.SigningKeySeedHex)
	publicBytes, _ := hex.DecodeString(vector.VerifyingKeyHex)
	var secret, public [ope.KeySize]byte
	copy(secret[:], secretBytes)
	copy(public[:], publicBytes)

	signed, err := ope.EnvelopeSignMap(secret, env)
	if err != nil {
		t.Fatal(err)
	}
	if err := ope.EnvelopeVerify(public, []byte(signed), 600); err != nil {
		t.Fatal(err)
	}
}
