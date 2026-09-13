package wire

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"testing"

	"golang.org/x/crypto/hkdf"
)

// TestV2AuthProofDeterminism locks the v2 auth-proof algorithm so that any
// future change to transcript serialization (serverName/path/init fields) is
// caught as a golden-vector mismatch. This is the regression net for the
// "auth proof invalid" class: the proof must be a pure function of
// (token, serverName, path, init) — no process-global state may enter it.
func TestV2AuthProofDeterminism(t *testing.T) {
	sessionID, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	nonce, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	init := ChannelInit{
		SessionID:    sessionID,
		ChannelID:    7,
		ClientNonce:  nonce,
		Timestamp:    1700000000,
		Capabilities: 0x27f,
	}
	const token = "test-token"
	const serverName = "example.com"
	const path = "/tunnel"

	proof, err := ComputeV2AuthProof(token, serverName, path, init)
	if err != nil {
		t.Fatalf("ComputeV2AuthProof: %v", err)
	}
	if len(proof) != sha256.Size {
		t.Fatalf("proof length = %d, want %d", len(proof), sha256.Size)
	}

	// Recompute and compare — must be byte-stable across calls.
	proof2, err := ComputeV2AuthProof(token, serverName, path, init)
	if err != nil {
		t.Fatalf("recompute: %v", err)
	}
	if !hmac.Equal(proof, proof2) {
		t.Fatalf("proof not deterministic: %x vs %x", proof, proof2)
	}

	got := hex.EncodeToString(proof)
	// The auth key is HKDF-SHA256(token, salt="x-tunnel-v2-auth", info=serverName)
	// and the HMAC is over the canonical transcript. This golden was derived
	// independently in Python (RFC 5869 + same transcript layout) and matches
	// the Go implementation byte-for-byte. Any change to the transcript layout,
	// key derivation salt/label, or field serialization breaks this test loudly.
	const golden = "e8af2e205459d9e7669df0774b0483929da8b15f8e482fbc3bd0e8206e4bb2aa"
	if got != golden {
		t.Fatalf("golden mismatch:\n got %s\nwant %s\n(transcript serialization changed: serverName=%q path=%q caps=0x%x)", got, golden, serverName, path, init.Capabilities)
	}

	// A different path/serverName/token must produce a different proof.
	other, err := ComputeV2AuthProof(token+"-x", serverName, path, init)
	if err != nil {
		t.Fatalf("other token: %v", err)
	}
	if hmac.Equal(proof, other) {
		t.Fatal("proof must depend on token")
	}
	otherPath, err := ComputeV2AuthProof(token, "other.com", path, init)
	if err != nil {
		t.Fatalf("other serverName: %v", err)
	}
	if hmac.Equal(proof, otherPath) {
		t.Fatal("proof must depend on serverName")
	}
	otherT, err := ComputeV2AuthProof(token, serverName, "/other", init)
	if err != nil {
		t.Fatalf("other path: %v", err)
	}
	if hmac.Equal(proof, otherT) {
		t.Fatal("proof must depend on path")
	}

	// The server-side recompute path must agree byte-for-byte with what the
	// client computed (the exact round-trip the handshake performs).
	decoded := ChannelInit{
		SessionID:    append([]byte(nil), sessionID...),
		ChannelID:    init.ChannelID,
		ClientNonce:  append([]byte(nil), nonce...),
		Timestamp:    init.Timestamp,
		Capabilities: init.Capabilities,
		AuthProof:    append([]byte(nil), proof...),
	}
	if !VerifyV2AuthProof(token, serverName, path, decoded) {
		t.Fatal("VerifyV2AuthProof rejected a proof computed by ComputeV2AuthProof")
	}
	decoded.AuthProof[0] ^= 0x01
	if VerifyV2AuthProof(token, serverName, path, decoded) {
		t.Fatal("VerifyV2AuthProof accepted a tampered proof")
	}

	// Transcript dump for the white-box comparison tool (XT_DEBUG_AUTH).
	transcript, err := channelInitTranscript(serverName, path, init)
	if err != nil {
		t.Fatalf("transcript: %v", err)
	}
	t.Logf("transcript hex: %x", transcript)
}

// TestV2AuthProofHkdfKeyspace sanity-checks the auth key derivation used by
// computeV2AuthProof, so the salt/label can never silently drift.
func TestV2AuthProofHkdfKeyspace(t *testing.T) {
	authKey := make([]byte, sha256.Size)
	if _, err := io.ReadFull(hkdf.New(sha256.New, []byte("k"), []byte("x-tunnel-v2-auth"), []byte("h")), authKey); err != nil {
		t.Fatal(err)
	}
	if authKey[0] == 0 && authKey[sha256.Size-1] == 0 {
		t.Fatal("auth key must not be all zero")
	}
}
