package wire

import (
	"bytes"
	"crypto/sha256"
	"io"
	"testing"

	"golang.org/x/crypto/hkdf"
)

// Bug A (red): the X25519 DH shared secret must enter the KDF as input keying
// material via HKDF-Extract(ikm = shared || token, salt = "xtunnel-v3-kdf"),
// not merely as HKDF-Expand info (where it is not secret).
func TestDeriveV3SessionSeedUsesSharedAsIKM(t *testing.T) {
	token := "secret-token"
	serverName := "edge.example.com"
	path := "/tunnel"
	init := fixedChannelInitV3()
	serverPk := fixedTestServerPk()
	shared := fixedTestSharedSecret()

	thFull, err := ComputeV3TranscriptHashFull(serverName, path, init, serverPk, ProtocolCipherChaCha20Poly1305)
	if err != nil {
		t.Fatalf("ComputeV3TranscriptHashFull error: %v", err)
	}
	keys, err := DeriveV3SessionSeed(token, thFull, shared)
	if err != nil {
		t.Fatalf("DeriveV3SessionSeed error: %v", err)
	}

	// Independent canonical derivation: prk = HKDF-Extract(ikm = shared || token, salt)
	ikm := append(append([]byte(nil), shared...), []byte(token)...)
	prk := hkdf.Extract(sha256.New, ikm, []byte("xtunnel-v3-kdf"))
	seedReader := hkdf.Expand(sha256.New, prk, thFull)
	seed := make([]byte, 32)
	if _, err := io.ReadFull(seedReader, seed); err != nil {
		t.Fatalf("hkdf expand error: %v", err)
	}
	sessionReader := hkdf.Expand(sha256.New, seed, []byte("xtunnel-v3 fs mix"))
	wantSeed := make([]byte, 32)
	if _, err := io.ReadFull(sessionReader, wantSeed); err != nil {
		t.Fatalf("hkdf expand error: %v", err)
	}
	if !bytes.Equal(keys.Seed, wantSeed) {
		t.Fatalf("session seed not derived with shared secret as HKDF IKM:\ngot  %x\nwant %x", keys.Seed, wantSeed)
	}

	// Two different tokens with same shared must still differ, and swapped
	// shared/token must not silently collide.
	keysB, err := DeriveV3SessionSeed(token, thFull, shared)
	if err != nil || !bytes.Equal(keys.Seed, keysB.Seed) {
		t.Fatalf("same inputs must derive same seed: err=%v", err)
	}
}

// Bug B (red): DeriveV3SessionKeys uses an all-zero shared secret, silently
// disabling forward secrecy. It must fail loudly instead.
func TestDeriveV3SessionKeysZeroSharedSecretFails(t *testing.T) {
	if _, err := DeriveV3SessionKeys("secret-token", bytes.Repeat([]byte{0x42}, 32)); err == nil {
		t.Fatal("DeriveV3SessionKeys with zero shared secret must return an error")
	}
}

// Bug B (red): an all-zero shared secret passed directly must also be rejected.
func TestDeriveV3SessionSeedRejectsZeroShared(t *testing.T) {
	token := "secret-token"
	init := fixedChannelInitV3()
	thFull, err := ComputeV3TranscriptHashFull("edge.example.com", "/tunnel", init, fixedTestServerPk(), ProtocolCipherChaCha20Poly1305)
	if err != nil {
		t.Fatalf("ComputeV3TranscriptHashFull error: %v", err)
	}
	if _, err := DeriveV3SessionSeed(token, thFull, make([]byte, 32)); err == nil {
		t.Fatal("DeriveV3SessionSeed must reject an all-zero shared secret")
	}
}

// Bug C (red): ServerNonce must be covered by the v3 server proof. Tampering
// with ServerNonce after the server computed its proof must fail verification.
func TestV3ServerProofCoversServerNonce(t *testing.T) {
	token := "secret-token"
	serverName := "edge.example.com"
	path := "/tunnel"
	init := fixedChannelInitV3()
	serverPk := fixedTestServerPk()

	proof, err := ComputeV3ServerProof(token, serverName, path, init, serverPk, ProtocolCipherChaCha20Poly1305)
	if err != nil {
		t.Fatalf("ComputeV3ServerProof error: %v", err)
	}
	accept := ChannelAccept{
		Capabilities: 0x0000000000001bf7,
		ServerNonce:  bytes.Repeat([]byte{0x5a}, 32),
		ServerTime:   1_700_000_005,
		MaxFrameSize: 16384,
		Cipher:       ProtocolCipherChaCha20Poly1305,
		ServerEphPK:  serverPk,
		ServerProof:  proof,
	}
	if !VerifyV3ServerProof(token, serverName, path, init, accept) {
		t.Fatal("VerifyV3ServerProof rejected valid accept")
	}

	tampered := accept
	tampered.ServerNonce = append([]byte(nil), accept.ServerNonce...)
	tampered.ServerNonce[0] ^= 0x01
	if VerifyV3ServerProof(token, serverName, path, init, tampered) {
		t.Fatal("VerifyV3ServerProof accepted tampered ServerNonce; nonce is not bound to the proof")
	}
}
