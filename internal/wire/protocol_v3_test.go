package wire

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

func fixedChannelInitV3() ChannelInit {
	sessionID := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	nonce := bytes.Repeat([]byte{0xa5}, 32)
	return ChannelInit{
		SessionID:    sessionID,
		ChannelID:    7,
		ClientNonce:  nonce,
		Timestamp:    1_700_000_000,
		Capabilities: 0x0000000000000bf7,
		CipherPref:   []byte{1, 2, 3},
	}
}

// 1. RFC 5869 HKDF Test Vectors (A.1 and A.2)
func TestRFC5869HKDF(t *testing.T) {
	// A.1 Test Case 1
	ikm1 := bytes.Repeat([]byte{0x0b}, 22)
	salt1, _ := hex.DecodeString("000102030405060708090a0b0c")
	info1, _ := hex.DecodeString("f0f1f2f3f4f5f6f7f8f9")
	wantPrk1, _ := hex.DecodeString("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
	wantOkm1, _ := hex.DecodeString("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")

	prk1 := hkdf.Extract(sha256.New, ikm1, salt1)
	if !bytes.Equal(prk1, wantPrk1) {
		t.Fatalf("RFC 5869 A.1 PRK mismatch: got %x, want %x", prk1, wantPrk1)
	}
	r1 := hkdf.Expand(sha256.New, prk1, info1)
	okm1 := make([]byte, 42)
	if _, err := io.ReadFull(r1, okm1); err != nil {
		t.Fatalf("RFC 5869 A.1 Expand failed: %v", err)
	}
	if !bytes.Equal(okm1, wantOkm1) {
		t.Fatalf("RFC 5869 A.1 OKM mismatch: got %x, want %x", okm1, wantOkm1)
	}

	// A.2 Test Case 2
	ikm2 := make([]byte, 80)
	for i := 0; i < 80; i++ {
		ikm2[i] = byte(i)
	}
	salt2 := make([]byte, 80)
	for i := 0; i < 80; i++ {
		salt2[i] = byte(0x60 + i)
	}
	info2 := make([]byte, 80)
	for i := 0; i < 80; i++ {
		info2[i] = byte(0xb0 + i)
	}
	wantPrk2, _ := hex.DecodeString("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244")
	wantOkm2, _ := hex.DecodeString("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87")

	prk2 := hkdf.Extract(sha256.New, ikm2, salt2)
	if !bytes.Equal(prk2, wantPrk2) {
		t.Fatalf("RFC 5869 A.2 PRK mismatch: got %x, want %x", prk2, wantPrk2)
	}
	r2 := hkdf.Expand(sha256.New, prk2, info2)
	okm2 := make([]byte, 82)
	if _, err := io.ReadFull(r2, okm2); err != nil {
		t.Fatalf("RFC 5869 A.2 Expand failed: %v", err)
	}
	if !bytes.Equal(okm2, wantOkm2) {
		t.Fatalf("RFC 5869 A.2 OKM mismatch: got %x, want %x", okm2, wantOkm2)
	}
}

// 2. Cipher Table and Negotiation Tests
func TestV3CipherTableAndNegotiation(t *testing.T) {
	ciphers := V3SupportedCiphers()
	if len(ciphers) != 3 {
		t.Fatalf("supported ciphers length = %d, want 3", len(ciphers))
	}
	if ciphers[0] != ProtocolCipherChaCha20Poly1305 || ciphers[1] != ProtocolCipherAES256GCM || ciphers[2] != ProtocolCipherAES128GCM {
		t.Fatalf("supported ciphers = %v, want [1, 2, 3]", ciphers)
	}

	// Verify key lengths
	if V3CipherKeyLen(ProtocolCipherChaCha20Poly1305) != 32 {
		t.Fatalf("ChaCha20Poly1305 key len = %d, want 32", V3CipherKeyLen(ProtocolCipherChaCha20Poly1305))
	}
	if V3CipherKeyLen(ProtocolCipherAES256GCM) != 32 {
		t.Fatalf("AES256GCM key len = %d, want 32", V3CipherKeyLen(ProtocolCipherAES256GCM))
	}
	if V3CipherKeyLen(ProtocolCipherAES128GCM) != 16 {
		t.Fatalf("AES128GCM key len = %d, want 16", V3CipherKeyLen(ProtocolCipherAES128GCM))
	}
	if V3CipherKeyLen(0) != 0 || V3CipherKeyLen(4) != 0 || V3CipherKeyLen(255) != 0 {
		t.Fatal("unknown cipher key len should be 0")
	}

	// Verify cipher names
	if V3CipherName(ProtocolCipherChaCha20Poly1305) != "ChaCha20-Poly1305" {
		t.Fatalf("ChaCha20Poly1305 name = %s", V3CipherName(ProtocolCipherChaCha20Poly1305))
	}
	if V3CipherName(ProtocolCipherAES256GCM) != "AES-256-GCM" {
		t.Fatalf("AES256GCM name = %s", V3CipherName(ProtocolCipherAES256GCM))
	}
	if V3CipherName(ProtocolCipherAES128GCM) != "AES-128-GCM" {
		t.Fatalf("AES128GCM name = %s", V3CipherName(ProtocolCipherAES128GCM))
	}
	if V3CipherName(0) != "Unknown" || V3CipherName(99) != "Unknown" {
		t.Fatal("unknown cipher name should be Unknown")
	}

	// Verify absence of XOR or bare ChaCha20
	for id := 0; id <= 255; id++ {
		b := byte(id)
		name := V3CipherName(b)
		if strings.Contains(strings.ToLower(name), "xor") {
			t.Fatalf("XOR cipher found in table: id=%d name=%s", id, name)
		}
		if name == "ChaCha20" {
			t.Fatalf("bare ChaCha20 cipher found in table: id=%d", id)
		}
	}

	// Negotiation tests
	// Empty preference -> reject
	chosen, rejectCode, msg := NegotiateCipherV3(nil)
	if chosen != 0 || rejectCode != V3RejectUnsupportedCipher || msg == "" {
		t.Fatalf("negotiate nil returned (%d, %d, %s)", chosen, rejectCode, msg)
	}

	chosen, rejectCode, msg = NegotiateCipherV3([]byte{})
	if chosen != 0 || rejectCode != V3RejectUnsupportedCipher {
		t.Fatalf("negotiate empty returned (%d, %d, %s)", chosen, rejectCode, msg)
	}

	// All unsupported -> reject
	chosen, rejectCode, msg = NegotiateCipherV3([]byte{0, 4, 99})
	if chosen != 0 || rejectCode != V3RejectUnsupportedCipher {
		t.Fatalf("negotiate unsupported returned (%d, %d, %s)", chosen, rejectCode, msg)
	}

	// First supported selected: [9, 2] -> 2
	chosen, rejectCode, msg = NegotiateCipherV3([]byte{9, 2})
	if chosen != ProtocolCipherAES256GCM || rejectCode != 0 {
		t.Fatalf("negotiate [9, 2] returned (%d, %d, %s), want (2, 0, '')", chosen, rejectCode, msg)
	}

	// Normal list [1, 2, 3] -> 1
	chosen, rejectCode, msg = NegotiateCipherV3([]byte{1, 2, 3})
	if chosen != ProtocolCipherChaCha20Poly1305 || rejectCode != 0 {
		t.Fatalf("negotiate [1, 2, 3] returned (%d, %d, %s), want (1, 0, '')", chosen, rejectCode, msg)
	}

	// Preference order [3, 1] -> 3
	chosen, rejectCode, msg = NegotiateCipherV3([]byte{3, 1})
	if chosen != ProtocolCipherAES128GCM || rejectCode != 0 {
		t.Fatalf("negotiate [3, 1] returned (%d, %d, %s), want (3, 0, '')", chosen, rejectCode, msg)
	}
}

// 3. Golden Vectors Test (Hardcoded Hex Vectors)
func TestV3GoldenVectors(t *testing.T) {
	token := "secret-token"
	serverName := "edge.example.com"
	path := "/tunnel"

	init := fixedChannelInitV3()

	// Compute and verify transcript hash
	th, err := ComputeV3TranscriptHash(serverName, path, init)
	if err != nil {
		t.Fatalf("ComputeV3TranscriptHash error: %v", err)
	}
	const wantTranscriptHashHex = "fe00ee176c3908d7bea55fe87ff719b9f9894b5d780e530583af600e3f6ccd70"
	if hex.EncodeToString(th) != wantTranscriptHashHex {
		t.Fatalf("TranscriptHash golden mismatch:\ngot  %s\nwant %s", hex.EncodeToString(th), wantTranscriptHashHex)
	}

	// Compute and verify auth proof
	proof, err := ComputeV3AuthProof(token, serverName, path, init)
	if err != nil {
		t.Fatalf("ComputeV3AuthProof error: %v", err)
	}
	const wantAuthProofHex = "01073e88fba970bc70d743c222c99fba2d3d9a6931c34de8d556e344e6452a1c"
	if hex.EncodeToString(proof) != wantAuthProofHex {
		t.Fatalf("AuthProof golden mismatch:\ngot  %s\nwant %s", hex.EncodeToString(proof), wantAuthProofHex)
	}

	init.AuthProof = proof

	// Verify ChannelInit full frame wire bytes
	var frameBuf bytes.Buffer
	if err := WriteChannelInitV3(&frameBuf, init); err != nil {
		t.Fatalf("WriteChannelInitV3 error: %v", err)
	}
	frameHex := hex.EncodeToString(frameBuf.Bytes())
	const wantFrameHex = "010300000000008380010010000102030405060708090a0b0c0d0e0f800200040000000780030020a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a580040008000000006553f100800500080000000000000bf78006002001073e88fba970bc70d743c222c99fba2d3d9a6931c34de8d556e344e6452a1c80300003010203"
	if frameHex != wantFrameHex {
		t.Fatalf("ChannelInit frame mismatch:\ngot  %s\nwant %s", frameHex, wantFrameHex)
	}

	// Derive session keys
	keys, err := DeriveV3SessionKeys(token, th)
	if err != nil {
		t.Fatalf("DeriveV3SessionKeys error: %v", err)
	}

	const wantSeedHex = "dafc2a12e54589de22b0d16dd8b54de162b47360fca1d3f1f5e541eee972a2c8"
	if hex.EncodeToString(keys.Seed) != wantSeedHex {
		t.Fatalf("Seed golden mismatch:\ngot  %s\nwant %s", hex.EncodeToString(keys.Seed), wantSeedHex)
	}

	const wantC2SNoncePrefixHex = "8b36b1ca"
	if hex.EncodeToString(keys.C2SNoncePrefix) != wantC2SNoncePrefixHex {
		t.Fatalf("C2SNoncePrefix golden mismatch:\ngot  %s\nwant %s", hex.EncodeToString(keys.C2SNoncePrefix), wantC2SNoncePrefixHex)
	}

	const wantS2CNoncePrefixHex = "6b4b606a"
	if hex.EncodeToString(keys.S2CNoncePrefix) != wantS2CNoncePrefixHex {
		t.Fatalf("S2CNoncePrefix golden mismatch:\ngot  %s\nwant %s", hex.EncodeToString(keys.S2CNoncePrefix), wantS2CNoncePrefixHex)
	}

	// Stream keys
	c2sChaChaKey, err := keys.StreamKey(ProtocolCipherChaCha20Poly1305, true, 1, 0)
	if err != nil {
		t.Fatalf("StreamKey ChaCha error: %v", err)
	}
	const wantC2SChaChaKeyHex = "11848cc0673cb26b66540ae86278cafe84c9ba80850280dda55f1541be32d256"
	if hex.EncodeToString(c2sChaChaKey) != wantC2SChaChaKeyHex {
		t.Fatalf("C2SChaChaKey golden mismatch:\ngot  %s\nwant %s", hex.EncodeToString(c2sChaChaKey), wantC2SChaChaKeyHex)
	}

	s2cAES256Key, err := keys.StreamKey(ProtocolCipherAES256GCM, false, 1, 0)
	if err != nil {
		t.Fatalf("StreamKey AES256 error: %v", err)
	}
	const wantS2CAES256KeyHex = "d9d06a5f7d7aba354f566a3aa6ea75da0aa94b3c489384ca283186ed79e17b47"
	if hex.EncodeToString(s2cAES256Key) != wantS2CAES256KeyHex {
		t.Fatalf("S2CAES256Key golden mismatch:\ngot  %s\nwant %s", hex.EncodeToString(s2cAES256Key), wantS2CAES256KeyHex)
	}

	c2sAES128Key, err := keys.StreamKey(ProtocolCipherAES128GCM, true, 2, 0)
	if err != nil {
		t.Fatalf("StreamKey AES128 error: %v", err)
	}
	const wantC2SAES128KeyHex = "84266ed0562756526c792d63049d1a7a"
	if hex.EncodeToString(c2sAES128Key) != wantC2SAES128KeyHex {
		t.Fatalf("C2SAES128Key golden mismatch:\ngot  %s\nwant %s", hex.EncodeToString(c2sAES128Key), wantC2SAES128KeyHex)
	}

	// AEAD Record Golden: ChaCha20-Poly1305
	{
		plain := []byte("hello-chacha20poly1305")
		counter := uint64(1)
		var nonceArr [12]byte
		copy(nonceArr[0:4], keys.C2SNoncePrefix)
		binary.BigEndian.PutUint64(nonceArr[4:12], counter)
		var ad [8]byte
		binary.BigEndian.PutUint64(ad[0:8], counter)

		aead, err := chacha20poly1305.New(c2sChaChaKey)
		if err != nil {
			t.Fatalf("chacha20poly1305.New error: %v", err)
		}
		rec := make([]byte, 10)
		binary.BigEndian.PutUint64(rec[0:8], counter)
		binary.BigEndian.PutUint16(rec[8:10], uint16(len(plain)))
		rec = aead.Seal(rec, nonceArr[:], plain, ad[:])

		const wantChaChaRecordHex = "00000000000000010016e048487e163ae62527d8c64e66e71d15ad1387e28208d5dd6c788e44069d1be9cccbab57192e"
		if hex.EncodeToString(rec) != wantChaChaRecordHex {
			t.Fatalf("ChaCha record golden mismatch:\ngot  %s\nwant %s", hex.EncodeToString(rec), wantChaChaRecordHex)
		}
	}

	// AEAD Record Golden: AES-256-GCM
	{
		plain := []byte("hello-aes256gcm")
		counter := uint64(1)
		var nonceArr [12]byte
		copy(nonceArr[0:4], keys.S2CNoncePrefix)
		binary.BigEndian.PutUint64(nonceArr[4:12], counter)
		var ad [8]byte
		binary.BigEndian.PutUint64(ad[0:8], counter)

		block, err := aes.NewCipher(s2cAES256Key)
		if err != nil {
			t.Fatalf("aes.NewCipher error: %v", err)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			t.Fatalf("cipher.NewGCM error: %v", err)
		}
		rec := make([]byte, 10)
		binary.BigEndian.PutUint64(rec[0:8], counter)
		binary.BigEndian.PutUint16(rec[8:10], uint16(len(plain)))
		rec = aead.Seal(rec, nonceArr[:], plain, ad[:])

		const wantAES256RecordHex = "0000000000000001000f13943087807938ff9f4c1b34dd1d9fb793ae5fd8e04efd07deea47895e9ebb"
		if hex.EncodeToString(rec) != wantAES256RecordHex {
			t.Fatalf("AES256 record golden mismatch:\ngot  %s\nwant %s", hex.EncodeToString(rec), wantAES256RecordHex)
		}
	}
}

// 4. Handshake Round-trip, Validation, and Anti-Downgrade Tests
func TestV3HandshakeRoundTripAndAntiDowngrade(t *testing.T) {
	token := "secret-token"
	serverName := "edge.example.com"
	path := "/tunnel"

	init := fixedChannelInitV3()
	proof, err := ComputeV3AuthProof(token, serverName, path, init)
	if err != nil {
		t.Fatalf("compute proof failed: %v", err)
	}
	init.AuthProof = proof

	// Verify valid proof
	if !VerifyV3AuthProof(token, serverName, path, init) {
		t.Fatal("VerifyV3AuthProof rejected valid ChannelInit")
	}

	// Write and Read ChannelInit
	var buf bytes.Buffer
	if err := WriteChannelInitV3(&buf, init); err != nil {
		t.Fatalf("WriteChannelInitV3 failed: %v", err)
	}
	decodedInit, err := ReadChannelInitV3(&buf, 0)
	if err != nil {
		t.Fatalf("ReadChannelInitV3 failed: %v", err)
	}
	if !bytes.Equal(decodedInit.SessionID, init.SessionID) ||
		decodedInit.ChannelID != init.ChannelID ||
		!bytes.Equal(decodedInit.ClientNonce, init.ClientNonce) ||
		decodedInit.Timestamp != init.Timestamp ||
		decodedInit.Capabilities != init.Capabilities ||
		!bytes.Equal(decodedInit.AuthProof, init.AuthProof) ||
		!bytes.Equal(decodedInit.CipherPref, init.CipherPref) {
		t.Fatal("decoded ChannelInit does not match original")
	}

	// Anti-downgrade / Anti-tamper tests
	// 1. Tamper Capabilities
	tamperedInit := init
	tamperedInit.Capabilities ^= 1
	if VerifyV3AuthProof(token, serverName, path, tamperedInit) {
		t.Fatal("VerifyV3AuthProof accepted tampered capabilities")
	}

	// 2. Tamper CipherPref (e.g. swap or change algorithm)
	tamperedInit = init
	tamperedInit.CipherPref = []byte{2, 1, 3}
	if VerifyV3AuthProof(token, serverName, path, tamperedInit) {
		t.Fatal("VerifyV3AuthProof accepted tampered cipher preference")
	}

	// 3. Tamper SessionID
	tamperedInit = init
	tamperedInit.SessionID = append([]byte(nil), init.SessionID...)
	tamperedInit.SessionID[0] ^= 0xff
	if VerifyV3AuthProof(token, serverName, path, tamperedInit) {
		t.Fatal("VerifyV3AuthProof accepted tampered session id")
	}

	// 4. Tamper ServerName or Path
	if VerifyV3AuthProof(token, "evil.example.com", path, init) {
		t.Fatal("VerifyV3AuthProof accepted wrong server name")
	}
	if VerifyV3AuthProof(token, serverName, "/other", init) {
		t.Fatal("VerifyV3AuthProof accepted wrong path")
	}

	// 5. Tamper Token
	if VerifyV3AuthProof("wrong-token", serverName, path, init) {
		t.Fatal("VerifyV3AuthProof accepted wrong token")
	}

	// 6. Tamper AuthProof itself
	tamperedInit = init
	tamperedInit.AuthProof = append([]byte(nil), init.AuthProof...)
	tamperedInit.AuthProof[0] ^= 0x01
	if VerifyV3AuthProof(token, serverName, path, tamperedInit) {
		t.Fatal("VerifyV3AuthProof accepted tampered auth proof")
	}

	// ChannelAccept round trip
	accept := ChannelAccept{
		Capabilities: 0x0000000000000bf7,
		ServerNonce:  bytes.Repeat([]byte{0x5a}, 32),
		ServerTime:   1_700_000_001,
		MaxFrameSize: 16384,
		MaxStreams:   100,
		Message:      "welcome-v3",
		Cipher:       ProtocolCipherChaCha20Poly1305,
	}
	var acceptBuf bytes.Buffer
	if err := WriteChannelAcceptV3(&acceptBuf, accept); err != nil {
		t.Fatalf("WriteChannelAcceptV3 failed: %v", err)
	}
	decodedAccept, reject, err := ReadChannelAcceptOrRejectV3(&acceptBuf, 0)
	if err != nil {
		t.Fatalf("ReadChannelAcceptOrRejectV3 failed: %v", err)
	}
	if reject.Code != 0 {
		t.Fatalf("unexpected reject: %v", reject)
	}
	if decodedAccept.Cipher != accept.Cipher ||
		decodedAccept.Capabilities != accept.Capabilities ||
		!bytes.Equal(decodedAccept.ServerNonce, accept.ServerNonce) ||
		decodedAccept.ServerTime != accept.ServerTime ||
		decodedAccept.MaxFrameSize != accept.MaxFrameSize ||
		decodedAccept.MaxStreams != accept.MaxStreams ||
		decodedAccept.Message != accept.Message {
		t.Fatalf("decoded ChannelAccept mismatch: %+v", decodedAccept)
	}

	// ChannelReject round trip
	rejectOut := ChannelReject{
		Code:    V3RejectUnsupportedCipher,
		Message: "unsupported cipher preference",
	}
	var rejectBuf bytes.Buffer
	if err := WriteChannelRejectV3(&rejectBuf, rejectOut); err != nil {
		t.Fatalf("WriteChannelRejectV3 failed: %v", err)
	}
	_, decodedReject, err := ReadChannelAcceptOrRejectV3(&rejectBuf, 0)
	if err != nil {
		t.Fatalf("ReadChannelAcceptOrRejectV3 failed: %v", err)
	}
	if decodedReject.Code != V3RejectUnsupportedCipher || decodedReject.Message != rejectOut.Message {
		t.Fatalf("decoded ChannelReject mismatch: %+v", decodedReject)
	}
}

// 5. Fail Closed and Validation Tests
func TestV3FailClosedAndValidations(t *testing.T) {
	// Unknown cipher ID in ChannelInit
	badInit := fixedChannelInitV3()
	badInit.CipherPref = []byte{99}
	badInit.AuthProof = bytes.Repeat([]byte{0x01}, 32)
	var buf bytes.Buffer
	if err := WriteChannelInitV3(&buf, badInit); err == nil {
		t.Fatal("WriteChannelInitV3 should fail on unsupported cipher in pref")
	}

	// Empty CipherPref
	badInit = fixedChannelInitV3()
	badInit.CipherPref = nil
	if err := WriteChannelInitV3(&buf, badInit); err == nil {
		t.Fatal("WriteChannelInitV3 should fail on nil cipher pref")
	}

	// CipherPref > 8
	badInit = fixedChannelInitV3()
	badInit.CipherPref = []byte{1, 2, 3, 1, 2, 3, 1, 2, 3} // 9 bytes
	if err := WriteChannelInitV3(&buf, badInit); err == nil {
		t.Fatal("WriteChannelInitV3 should fail on cipher pref > 8")
	}

	// Unknown cipher in ChannelAccept
	badAccept := ChannelAccept{
		Capabilities: 0x01,
		ServerNonce:  bytes.Repeat([]byte{0x02}, 32),
		ServerTime:   100,
		Cipher:       99,
	}
	if err := WriteChannelAcceptV3(&buf, badAccept); err == nil {
		t.Fatal("WriteChannelAcceptV3 should fail on unsupported cipher")
	}

	// Wrong frame version
	badFrame := V3Frame{
		Type:    v3FrameTypeChannelInit,
		Version: 2, // wrong version for v3
		Body:    []byte("test"),
	}
	if err := WriteV3Frame(&buf, badFrame); err == nil {
		t.Fatal("WriteV3Frame should fail on version != 3")
	}

	// Unknown critical TLV rejection in decodeChannelInitV3
	validInit := fixedChannelInitV3()
	validInit.AuthProof = bytes.Repeat([]byte{0x01}, 32)
	enc, err := encodeChannelInitV3(validInit)
	if err != nil {
		t.Fatalf("encodeChannelInitV3 error: %v", err)
	}
	// Append an unknown critical TLV (0x8099)
	tlvBytes, _ := encodeV2TLVs([]V2TLV{{Type: 0x8099, Value: []byte("critical")}})
	tamperedBody := append(enc, tlvBytes...)
	if _, err := decodeChannelInitV3(tamperedBody); err == nil {
		t.Fatal("decodeChannelInitV3 should reject unknown critical TLV")
	}
}

// 6. Cipher Stream Bit Flip and Integrity Tests
func TestV3CipherStreamBitFlipAndIntegrity(t *testing.T) {
	token := "secret-token"
	serverName := "edge.example.com"
	path := "/tunnel"
	init := fixedChannelInitV3()
	th, _ := ComputeV3TranscriptHash(serverName, path, init)
	keys, _ := DeriveV3SessionKeys(token, th)

	for _, cipherID := range []byte{ProtocolCipherChaCha20Poly1305, ProtocolCipherAES256GCM, ProtocolCipherAES128GCM} {
		t.Run(V3CipherName(cipherID), func(t *testing.T) {
			var pipeBuf bytes.Buffer
			clientStream, err := NewV3CipherStream(&nopCloser{Buffer: &pipeBuf}, keys, cipherID, 1, true)
			if err != nil {
				t.Fatalf("NewV3CipherStream error: %v", err)
			}

			payload := []byte("confidential-payload-data-to-protect")
			if _, err := clientStream.Write(payload); err != nil {
				t.Fatalf("Write error: %v", err)
			}

			rawRecord := append([]byte(nil), pipeBuf.Bytes()...)
			if len(rawRecord) != 10+len(payload)+16 {
				t.Fatalf("record len = %d, want %d", len(rawRecord), 10+len(payload)+16)
			}

			// Verify normal read works
			{
				buf := bytes.NewBuffer(append([]byte(nil), rawRecord...))
				serverStream, err := NewV3CipherStream(&nopCloser{Buffer: buf}, keys, cipherID, 1, false)
				if err != nil {
					t.Fatalf("NewV3CipherStream error: %v", err)
				}
				readBuf := make([]byte, len(payload))
				if _, err := io.ReadFull(serverStream, readBuf); err != nil {
					t.Fatalf("normal ReadFull failed: %v", err)
				}
				if !bytes.Equal(readBuf, payload) {
					t.Fatalf("decrypted payload mismatch: got %s, want %s", string(readBuf), string(payload))
				}
			}

			// Bit flip tests at counter, length, ciphertext, and tag
			testPositions := []struct {
				name string
				idx  int
			}{
				{"counter byte 0", 0},
				{"counter byte 7", 7},
				{"length byte 8", 8},
				{"length byte 9", 9},
				{"ciphertext start", 10},
				{"ciphertext mid", 10 + len(payload)/2},
				{"tag byte", len(rawRecord) - 1},
			}

			for _, pos := range testPositions {
				t.Run("bitflip-"+pos.name, func(t *testing.T) {
					tampered := append([]byte(nil), rawRecord...)
					tampered[pos.idx] ^= 0x01

					buf := bytes.NewBuffer(tampered)
					serverStream, _ := NewV3CipherStream(&nopCloser{Buffer: buf}, keys, cipherID, 1, false)
					readBuf := make([]byte, len(payload))
					_, err := io.ReadFull(serverStream, readBuf)
					if err == nil {
						t.Fatalf("ReadFull succeeded despite bit flip at %s", pos.name)
					}
				})
			}

			// Truncation tests
			t.Run("truncated-header", func(t *testing.T) {
				buf := bytes.NewBuffer(rawRecord[:5])
				serverStream, _ := NewV3CipherStream(&nopCloser{Buffer: buf}, keys, cipherID, 1, false)
				readBuf := make([]byte, len(payload))
				if _, err := io.ReadFull(serverStream, readBuf); err == nil {
					t.Fatal("ReadFull succeeded on truncated header")
				}
			})

			t.Run("truncated-ciphertext", func(t *testing.T) {
				buf := bytes.NewBuffer(rawRecord[:len(rawRecord)-5])
				serverStream, _ := NewV3CipherStream(&nopCloser{Buffer: buf}, keys, cipherID, 1, false)
				readBuf := make([]byte, len(payload))
				if _, err := io.ReadFull(serverStream, readBuf); err == nil {
					t.Fatal("ReadFull succeeded on truncated ciphertext")
				}
			})
		})
	}
}

// 7. Cipher Stream Replay and Out-of-Order Tests
func TestV3CipherStreamReplayAndOutOfOrder(t *testing.T) {
	token := "secret-token"
	serverName := "edge.example.com"
	path := "/tunnel"
	init := fixedChannelInitV3()
	th, _ := ComputeV3TranscriptHash(serverName, path, init)
	keys, _ := DeriveV3SessionKeys(token, th)

	// End-to-end pipe communication test
	cConn, sConn := net.Pipe()
	defer cConn.Close()
	defer sConn.Close()

	clientStream, err := NewV3CipherStream(cConn, keys, ProtocolCipherChaCha20Poly1305, 1, true)
	if err != nil {
		t.Fatalf("client NewV3CipherStream error: %v", err)
	}
	serverStream, err := NewV3CipherStream(sConn, keys, ProtocolCipherChaCha20Poly1305, 1, false)
	if err != nil {
		t.Fatalf("server NewV3CipherStream error: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		for i := 0; i < 5; i++ {
			msg := fmt.Sprintf("message-%d", i)
			if _, err := clientStream.Write([]byte(msg)); err != nil {
				errCh <- err
				return
			}
		}
		errCh <- nil
	}()

	for i := 0; i < 5; i++ {
		wantMsg := fmt.Sprintf("message-%d", i)
		buf := make([]byte, len(wantMsg))
		if _, err := io.ReadFull(serverStream, buf); err != nil {
			t.Fatalf("server read msg %d failed: %v", i, err)
		}
		if string(buf) != wantMsg {
			t.Fatalf("server read msg %d got %s, want %s", i, string(buf), wantMsg)
		}
	}

	if err := <-errCh; err != nil {
		t.Fatalf("client write failed: %v", err)
	}

	// Sliding window unit test
	var window replayWindow
	// Normal in order
	if !window.checkAndAdd(1) {
		t.Fatal("seq 1 rejected")
	}
	if window.checkAndAdd(1) {
		t.Fatal("seq 1 replay accepted")
	}
	if !window.checkAndAdd(3) {
		t.Fatal("seq 3 rejected")
	}
	// Out of order within window
	if !window.checkAndAdd(2) {
		t.Fatal("seq 2 (out-of-order) rejected")
	}
	if window.checkAndAdd(2) {
		t.Fatal("seq 2 replay accepted")
	}
	if window.checkAndAdd(3) {
		t.Fatal("seq 3 replay accepted")
	}
	if window.checkAndAdd(0) {
		t.Fatal("seq 0 accepted")
	}

	// Jump forward to seq 2050 (window covers 2050 - 2048 + 1 = 3 to 2050)
	if !window.checkAndAdd(2050) {
		t.Fatal("seq 2050 rejected")
	}
	// Below window lower bound (2050 - 2048 = 2, so <= 2 is too old)
	if window.checkAndAdd(1) {
		t.Fatal("seq 1 below window accepted")
	}
	if window.checkAndAdd(2) {
		t.Fatal("seq 2 below window accepted")
	}
	// Unseen packet within window (e.g. 2049)
	if !window.checkAndAdd(2049) {
		t.Fatal("seq 2049 within window rejected")
	}
	if window.checkAndAdd(2049) {
		t.Fatal("seq 2049 replay accepted")
	}
}

// 8. Rekeying across Generation Boundaries Test
func TestV3CipherStreamRekey(t *testing.T) {
	token := "secret-token"
	serverName := "edge.example.com"
	path := "/tunnel"
	init := fixedChannelInitV3()
	th, _ := ComputeV3TranscriptHash(serverName, path, init)
	keys, _ := DeriveV3SessionKeys(token, th)

	// Verify that StreamKey produces distinct keys for different generations
	k0, _ := keys.StreamKey(ProtocolCipherChaCha20Poly1305, true, 1, 0)
	k1, _ := keys.StreamKey(ProtocolCipherChaCha20Poly1305, true, 1, 1)
	k2, _ := keys.StreamKey(ProtocolCipherChaCha20Poly1305, true, 1, 2)
	if bytes.Equal(k0, k1) || bytes.Equal(k1, k2) || bytes.Equal(k0, k2) {
		t.Fatalf("generation keys must be distinct: gen0=%x gen1=%x gen2=%x", k0, k1, k2)
	}

	cConn, sConn := net.Pipe()
	defer cConn.Close()
	defer sConn.Close()

	clientStream, err := NewV3CipherStream(cConn, keys, ProtocolCipherChaCha20Poly1305, 1, true)
	if err != nil {
		t.Fatalf("NewV3CipherStream client error: %v", err)
	}
	serverStream, err := NewV3CipherStream(sConn, keys, ProtocolCipherChaCha20Poly1305, 1, false)
	if err != nil {
		t.Fatalf("NewV3CipherStream server error: %v", err)
	}

	// Set RekeyInterval to 4 records for testing
	clientStream.RekeyInterval = 4
	serverStream.RekeyInterval = 4

	totalRecords := 12
	errCh := make(chan error, 1)
	go func() {
		for i := 1; i <= totalRecords; i++ {
			msg := fmt.Sprintf("rekey-msg-%03d", i)
			if _, err := clientStream.Write([]byte(msg)); err != nil {
				errCh <- err
				return
			}
		}
		errCh <- nil
	}()

	for i := 1; i <= totalRecords; i++ {
		wantMsg := fmt.Sprintf("rekey-msg-%03d", i)
		buf := make([]byte, len(wantMsg))
		if _, err := io.ReadFull(serverStream, buf); err != nil {
			t.Fatalf("server read record %d failed: %v", i, err)
		}
		if string(buf) != wantMsg {
			t.Fatalf("server read record %d got %s, want %s", i, string(buf), wantMsg)
		}
	}

	if err := <-errCh; err != nil {
		t.Fatalf("client write error during rekey: %v", err)
	}
}

// 9. Deadline and Unsupported Operations Test
func TestV3Deadlines(t *testing.T) {
	token := "secret-token"
	serverName := "edge.example.com"
	path := "/tunnel"
	init := fixedChannelInitV3()
	th, _ := ComputeV3TranscriptHash(serverName, path, init)
	keys, _ := DeriveV3SessionKeys(token, th)

	// Case 1: inner implements deadlines (net.Pipe)
	cConn, sConn := net.Pipe()
	defer cConn.Close()
	defer sConn.Close()

	stream, err := NewV3CipherStream(cConn, keys, ProtocolCipherChaCha20Poly1305, 1, true)
	if err != nil {
		t.Fatalf("NewV3CipherStream error: %v", err)
	}

	now := time.Now().Add(time.Hour)
	if err := stream.SetDeadline(now); err != nil {
		t.Fatalf("SetDeadline failed: %v", err)
	}
	if err := stream.SetReadDeadline(now); err != nil {
		t.Fatalf("SetReadDeadline failed: %v", err)
	}
	if err := stream.SetWriteDeadline(now); err != nil {
		t.Fatalf("SetWriteDeadline failed: %v", err)
	}

	// Case 2: inner does not implement deadlines (bytes.Buffer)
	bufStream, err := NewV3CipherStream(&nopCloser{Buffer: &bytes.Buffer{}}, keys, ProtocolCipherChaCha20Poly1305, 1, true)
	if err != nil {
		t.Fatalf("NewV3CipherStream error: %v", err)
	}
	if err := bufStream.SetDeadline(now); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("expected ErrUnsupported, got %v", err)
	}
	if err := bufStream.SetReadDeadline(now); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("expected ErrUnsupported, got %v", err)
	}
	if err := bufStream.SetWriteDeadline(now); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("expected ErrUnsupported, got %v", err)
	}
}

type nopCloser struct {
	*bytes.Buffer
}

func (n *nopCloser) Close() error {
	return nil
}
