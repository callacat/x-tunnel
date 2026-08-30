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
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

var (
	fixedTestClientSk = bytes.Repeat([]byte{0xc1}, 32)
	fixedTestServerSk = bytes.Repeat([]byte{0x5e}, 32)
)

func fixedTestClientPk() []byte {
	pk, err := curve25519.X25519(fixedTestClientSk, curve25519.Basepoint)
	if err != nil {
		panic(err)
	}
	return pk
}

func fixedTestServerPk() []byte {
	pk, err := curve25519.X25519(fixedTestServerSk, curve25519.Basepoint)
	if err != nil {
		panic(err)
	}
	return pk
}

func fixedTestSharedSecret() []byte {
	shared, err := curve25519.X25519(fixedTestClientSk, fixedTestServerPk())
	if err != nil {
		panic(err)
	}
	return shared
}

func fixedChannelInitV3() ChannelInit {
	sessionID := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	nonce := bytes.Repeat([]byte{0xa5}, 32)
	return ChannelInit{
		SessionID:    sessionID,
		ChannelID:    7,
		ClientNonce:  nonce,
		Timestamp:    1_700_000_000,
		Capabilities: 0x0000000000001bf7,
		CipherPref:   []byte{1, 2, 3},
		ClientEphPK:  fixedTestClientPk(),
		TAI64N:       EncodeTAI64N(time.Unix(1_700_000_000, 500_000_000).UTC()),
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

// 2. RFC 7748 X25519 Test Vectors
func TestRFC7748X25519(t *testing.T) {
	// RFC 7748 §5.2 Test Vector 1
	aliceSk, _ := hex.DecodeString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	alicePk, _ := hex.DecodeString("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
	bobSk, _ := hex.DecodeString("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
	bobPk, _ := hex.DecodeString("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
	wantShared, _ := hex.DecodeString("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

	calcAlicePk, err := curve25519.X25519(aliceSk, curve25519.Basepoint)
	if err != nil || !bytes.Equal(calcAlicePk, alicePk) {
		t.Fatalf("Alice PK mismatch: got %x, want %x, err: %v", calcAlicePk, alicePk, err)
	}

	calcBobPk, err := curve25519.X25519(bobSk, curve25519.Basepoint)
	if err != nil || !bytes.Equal(calcBobPk, bobPk) {
		t.Fatalf("Bob PK mismatch: got %x, want %x, err: %v", calcBobPk, bobPk, err)
	}

	sharedAlice, err := ComputeV3SharedSecret(aliceSk, bobPk)
	if err != nil || !bytes.Equal(sharedAlice, wantShared) {
		t.Fatalf("Shared secret Alice mismatch: got %x, want %x, err: %v", sharedAlice, wantShared, err)
	}

	sharedBob, err := ComputeV3SharedSecret(bobSk, alicePk)
	if err != nil || !bytes.Equal(sharedBob, wantShared) {
		t.Fatalf("Shared secret Bob mismatch: got %x, want %x, err: %v", sharedBob, wantShared, err)
	}

	// Key generation test
	ephSk, ephPk, err := NewV3ClientEphemeralKey()
	if err != nil {
		t.Fatalf("NewV3ClientEphemeralKey error: %v", err)
	}
	if len(ephSk) != 32 || len(ephPk) != 32 {
		t.Fatalf("NewV3ClientEphemeralKey length mismatch: sk=%d pk=%d", len(ephSk), len(ephPk))
	}
}

// 3. Cipher Table and Negotiation Tests
func TestV3CipherTableAndNegotiation(t *testing.T) {
	ciphers := V3SupportedCiphers()
	if len(ciphers) != 3 {
		t.Fatalf("expected 3 ciphers, got %d", len(ciphers))
	}
	if ciphers[0] != ProtocolCipherChaCha20Poly1305 ||
		ciphers[1] != ProtocolCipherAES256GCM ||
		ciphers[2] != ProtocolCipherAES128GCM {
		t.Fatalf("unexpected cipher table: %v", ciphers)
	}

	if V3CipherKeyLen(ProtocolCipherChaCha20Poly1305) != 32 {
		t.Fatal("ChaCha20 key len != 32")
	}
	if V3CipherKeyLen(ProtocolCipherAES256GCM) != 32 {
		t.Fatal("AES256 key len != 32")
	}
	if V3CipherKeyLen(ProtocolCipherAES128GCM) != 16 {
		t.Fatal("AES128 key len != 16")
	}
	if V3CipherKeyLen(99) != 0 {
		t.Fatal("unknown cipher key len != 0")
	}

	if V3CipherName(ProtocolCipherChaCha20Poly1305) != "ChaCha20-Poly1305" {
		t.Fatal("ChaCha20 name mismatch")
	}
	if V3CipherName(ProtocolCipherAES256GCM) != "AES-256-GCM" {
		t.Fatal("AES256 name mismatch")
	}
	if V3CipherName(ProtocolCipherAES128GCM) != "AES-128-GCM" {
		t.Fatal("AES128 name mismatch")
	}
	if V3CipherName(99) != "Unknown" {
		t.Fatal("unknown cipher name mismatch")
	}

	// Cipher negotiation: first matching
	chosen, rejectCode, _ := NegotiateCipherV3([]byte{2, 1, 3})
	if chosen != 2 || rejectCode != 0 {
		t.Fatalf("negotiate [2,1,3] got chosen=%d code=%d", chosen, rejectCode)
	}

	chosen, rejectCode, _ = NegotiateCipherV3([]byte{99, 3})
	if chosen != 3 || rejectCode != 0 {
		t.Fatalf("negotiate [99,3] got chosen=%d code=%d", chosen, rejectCode)
	}

	// Empty preference -> reject code 9
	chosen, rejectCode, _ = NegotiateCipherV3([]byte{})
	if chosen != 0 || rejectCode != V3RejectUnsupportedCipher {
		t.Fatalf("empty preference got chosen=%d code=%d", chosen, rejectCode)
	}

	// No supported ciphers -> reject code 9
	chosen, rejectCode, _ = NegotiateCipherV3([]byte{99, 100})
	if chosen != 0 || rejectCode != V3RejectUnsupportedCipher {
		t.Fatalf("no supported cipher got chosen=%d code=%d", chosen, rejectCode)
	}
}

// 4. Golden Vector Tests with Deterministic Ephemeral Scalars
func TestV3GoldenVectors(t *testing.T) {
	token := "secret-token"
	serverName := "edge.example.com"
	path := "/tunnel"

	init := fixedChannelInitV3()
	serverPk := fixedTestServerPk()
	shared := fixedTestSharedSecret()

	// 1. Compute and verify transcript_hash_init
	thInit, err := ComputeV3TranscriptHashInit(serverName, path, init)
	if err != nil {
		t.Fatalf("ComputeV3TranscriptHashInit error: %v", err)
	}
	const wantTranscriptHashInitHex = "332c281028fdd29c27390ccd94c070a5342ee14b34cbb3c4f154096e60d2647e"
	if hex.EncodeToString(thInit) != wantTranscriptHashInitHex {
		t.Fatalf("TranscriptHashInit golden mismatch:\ngot  %s\nwant %s", hex.EncodeToString(thInit), wantTranscriptHashInitHex)
	}

	// 2. Compute and verify auth_proof
	proof, err := ComputeV3AuthProof(token, serverName, path, init)
	if err != nil {
		t.Fatalf("ComputeV3AuthProof error: %v", err)
	}
	const wantAuthProofHex = "bcf4710d28e00db93de679f71e2bc7ad2f109ff3f62a6258600c4ad66e194cba"
	if hex.EncodeToString(proof) != wantAuthProofHex {
		t.Fatalf("AuthProof golden mismatch:\ngot  %s\nwant %s", hex.EncodeToString(proof), wantAuthProofHex)
	}

	// 3. ChannelInit Frame Serialization with 0x8032 and 0x8035 TLVs
	init.AuthProof = proof
	var frameBuf bytes.Buffer
	if err := WriteChannelInitV3(&frameBuf, init); err != nil {
		t.Fatalf("WriteChannelInitV3 error: %v", err)
	}
	frameHex := hex.EncodeToString(frameBuf.Bytes())
	const wantFrameHex = "01030000000000b780010010000102030405060708090a0b0c0d0e0f800200040000000780030020a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a580040008000000006553f100800500080000000000001bf780060020bcf4710d28e00db93de679f71e2bc7ad2f109ff3f62a6258600c4ad66e194cba803000030102038032002042575d5c8a93833255e09f04054a4f6246d36ed163c1c7f80c1fc9a58a0e912d8035000c400000006553f1001dcd6500"
	if frameHex != wantFrameHex {
		t.Fatalf("ChannelInit frame mismatch:\ngot  %s\nwant %s", frameHex, wantFrameHex)
	}

	// 4. Full transcript hash with ServerEphPK and negotiated cipher
	chosenCipher := ProtocolCipherChaCha20Poly1305
	thFull, err := ComputeV3TranscriptHashFull(serverName, path, init, serverPk, chosenCipher)
	if err != nil {
		t.Fatalf("ComputeV3TranscriptHashFull error: %v", err)
	}
	const wantTranscriptHashFullHex = "bc87b5a665d9e1d78f57970e12ad16ab5758b079f59da6ed87ae02473bb386f3"
	if hex.EncodeToString(thFull) != wantTranscriptHashFullHex {
		t.Fatalf("TranscriptHashFull golden mismatch:\ngot  %s\nwant %s", hex.EncodeToString(thFull), wantTranscriptHashFullHex)
	}

	// 5. Server proof
	serverProof, err := ComputeV3ServerProof(token, serverName, path, init, serverPk, chosenCipher)
	if err != nil {
		t.Fatalf("ComputeV3ServerProof error: %v", err)
	}
	const wantServerProofHex = "063ba411332a0ceb692f5bcbcb00da5754f00ee818200e7d9a02c2e2e4c3505e"
	if hex.EncodeToString(serverProof) != wantServerProofHex {
		t.Fatalf("ServerProof golden mismatch:\ngot  %s\nwant %s", hex.EncodeToString(serverProof), wantServerProofHex)
	}

	// 6. Derive session keys
	keys, err := DeriveV3SessionSeed(token, thFull, shared)
	if err != nil {
		t.Fatalf("DeriveV3SessionSeed error: %v", err)
	}

	const wantSeedHex = "3398ca29d0e2ed9dadc17ed9cbdeb2274c617abeee81600329a602ce8f90dbec"
	if hex.EncodeToString(keys.Seed) != wantSeedHex {
		t.Fatalf("Seed golden mismatch:\ngot  %s\nwant %s", hex.EncodeToString(keys.Seed), wantSeedHex)
	}

	const wantC2SNoncePrefixHex = "c21441aa"
	if hex.EncodeToString(keys.C2SNoncePrefix) != wantC2SNoncePrefixHex {
		t.Fatalf("C2SNoncePrefix golden mismatch:\ngot  %s\nwant %s", hex.EncodeToString(keys.C2SNoncePrefix), wantC2SNoncePrefixHex)
	}

	const wantS2CNoncePrefixHex = "0813b710"
	if hex.EncodeToString(keys.S2CNoncePrefix) != wantS2CNoncePrefixHex {
		t.Fatalf("S2CNoncePrefix golden mismatch:\ngot  %s\nwant %s", hex.EncodeToString(keys.S2CNoncePrefix), wantS2CNoncePrefixHex)
	}

	// 7. Stream keys
	c2sChaChaKey, err := keys.StreamKey(ProtocolCipherChaCha20Poly1305, true, 1, 0)
	if err != nil {
		t.Fatalf("StreamKey ChaCha error: %v", err)
	}
	const wantC2SChaChaKeyHex = "634c3cc971ac503b5dd995469b8e99fe7f14edea4d0b8955c28834cc1bbf9a87"
	if hex.EncodeToString(c2sChaChaKey) != wantC2SChaChaKeyHex {
		t.Fatalf("C2SChaChaKey golden mismatch:\ngot  %s\nwant %s", hex.EncodeToString(c2sChaChaKey), wantC2SChaChaKeyHex)
	}

	s2cAES256Key, err := keys.StreamKey(ProtocolCipherAES256GCM, false, 1, 0)
	if err != nil {
		t.Fatalf("StreamKey AES256 error: %v", err)
	}
	const wantS2CAES256KeyHex = "6684fbbce120ad0c3d609f3132cddf26d03fcbf2317da2e49f6a7dd808a827e9"
	if hex.EncodeToString(s2cAES256Key) != wantS2CAES256KeyHex {
		t.Fatalf("S2CAES256Key golden mismatch:\ngot  %s\nwant %s", hex.EncodeToString(s2cAES256Key), wantS2CAES256KeyHex)
	}

	c2sAES128Key, err := keys.StreamKey(ProtocolCipherAES128GCM, true, 2, 0)
	if err != nil {
		t.Fatalf("StreamKey AES128 error: %v", err)
	}
	const wantC2SAES128KeyHex = "a5e3887216afd9aa70c25e167ab8e242"
	if hex.EncodeToString(c2sAES128Key) != wantC2SAES128KeyHex {
		t.Fatalf("C2SAES128Key golden mismatch:\ngot  %s\nwant %s", hex.EncodeToString(c2sAES128Key), wantC2SAES128KeyHex)
	}

	// 8. AEAD Record Golden: ChaCha20-Poly1305 (pad_len = 0)
	plain := []byte("hello xtunnel v3 frame")
	{
		counter := uint64(1)
		var nonceArr [12]byte
		copy(nonceArr[0:4], keys.C2SNoncePrefix)
		binary.BigEndian.PutUint64(nonceArr[4:12], counter)
		aead, err := chacha20poly1305.New(c2sChaChaKey)
		if err != nil {
			t.Fatalf("chacha20poly1305.New error: %v", err)
		}
		rec := make([]byte, 12)
		env := make([]byte, 0, 2+len(plain))
		env = binary.BigEndian.AppendUint16(env, uint16(len(plain)))
		env = append(env, plain...)
		binary.BigEndian.PutUint64(rec[0:8], counter)
		binary.BigEndian.PutUint16(rec[8:10], uint16(len(env)))
		binary.BigEndian.PutUint16(rec[10:12], 0) // reserved
		rec = aead.Seal(rec, nonceArr[:], env, rec[:12])

		const wantChaChaRecordHex = "000000000000000100180000a3b9257d6b9e4b70ae9a62995d4b4105254b679992883455adcce49c4254a0e430b1bdfaae2d4fbe"
		if hex.EncodeToString(rec) != wantChaChaRecordHex {
			t.Fatalf("ChaCha record golden mismatch:\ngot  %s\nwant %s", hex.EncodeToString(rec), wantChaChaRecordHex)
		}
	}

	// 9. AEAD Record Golden: AES-256-GCM (pad_len = 0)
	{
		counter := uint64(1)
		var nonceArr [12]byte
		copy(nonceArr[0:4], keys.S2CNoncePrefix)
		binary.BigEndian.PutUint64(nonceArr[4:12], counter)
		block, err := aes.NewCipher(s2cAES256Key)
		if err != nil {
			t.Fatalf("aes.NewCipher error: %v", err)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			t.Fatalf("cipher.NewGCM error: %v", err)
		}
		rec := make([]byte, 12)
		env := make([]byte, 0, 2+len(plain))
		env = binary.BigEndian.AppendUint16(env, uint16(len(plain)))
		env = append(env, plain...)
		binary.BigEndian.PutUint64(rec[0:8], counter)
		binary.BigEndian.PutUint16(rec[8:10], uint16(len(env)))
		binary.BigEndian.PutUint16(rec[10:12], 0) // reserved
		rec = aead.Seal(rec, nonceArr[:], env, rec[:12])

		const wantAES256RecordHex = "000000000000000100180000d8a460db281b3083ea2bbd3f2967b61b39b8a676f7344d311d49f0460a110e3bc3733e183f87a293"
		if hex.EncodeToString(rec) != wantAES256RecordHex {
			t.Fatalf("AES256 record golden mismatch:\ngot  %s\nwant %s", hex.EncodeToString(rec), wantAES256RecordHex)
		}
	}

	// 10. AEAD Record Golden: AES-128-GCM (pad_len = 0)
	{
		counter := uint64(1)
		var nonceArr [12]byte
		copy(nonceArr[0:4], keys.C2SNoncePrefix)
		binary.BigEndian.PutUint64(nonceArr[4:12], counter)
		block, err := aes.NewCipher(c2sAES128Key)
		if err != nil {
			t.Fatalf("aes.NewCipher error: %v", err)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			t.Fatalf("cipher.NewGCM error: %v", err)
		}
		rec := make([]byte, 12)
		env := make([]byte, 0, 2+len(plain))
		env = binary.BigEndian.AppendUint16(env, uint16(len(plain)))
		env = append(env, plain...)
		binary.BigEndian.PutUint64(rec[0:8], counter)
		binary.BigEndian.PutUint16(rec[8:10], uint16(len(env)))
		binary.BigEndian.PutUint16(rec[10:12], 0) // reserved
		rec = aead.Seal(rec, nonceArr[:], env, rec[:12])

		const wantAES128RecordHex = "00000000000000010018000007c3af75beaf30da6b1e6281fd1a2e5e79570a76b3ea2223139bc7633e3d4cc3d50f9c95603467c5"
		if hex.EncodeToString(rec) != wantAES128RecordHex {
			t.Fatalf("AES128 record golden mismatch:\ngot  %s\nwant %s", hex.EncodeToString(rec), wantAES128RecordHex)
		}
	}

	// 11. AEAD Record Golden: ChaCha20-Poly1305 with fixed pad = 5
	{
		counter := uint64(1)
		var nonceArr [12]byte
		copy(nonceArr[0:4], keys.C2SNoncePrefix)
		binary.BigEndian.PutUint64(nonceArr[4:12], counter)
		pad := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
		// Envelope: plain_len (2B BE) | plain | pad.
		payload := make([]byte, 0, 2+len(plain)+len(pad))
		payload = binary.BigEndian.AppendUint16(payload, uint16(len(plain)))
		payload = append(payload, plain...)
		payload = append(payload, pad...)

		aead, err := chacha20poly1305.New(c2sChaChaKey)
		if err != nil {
			t.Fatalf("chacha20poly1305.New error: %v", err)
		}
		rec := make([]byte, 12)
		binary.BigEndian.PutUint64(rec[0:8], counter)
		binary.BigEndian.PutUint16(rec[8:10], uint16(len(payload)))
		binary.BigEndian.PutUint16(rec[10:12], 0) // reserved
		rec = aead.Seal(rec, nonceArr[:], payload, rec[:12])

		const wantChaChaPaddedRecordHex = "0000000000000001001d0000a3b9257d6b9e4b70ae9a62995d4b4105254b679992883455aeb790a5f8f62ee115df09a5ae5a4e622e9398efe3"
		if hex.EncodeToString(rec) != wantChaChaPaddedRecordHex {
			t.Fatalf("ChaCha padded record golden mismatch:\ngot  %s\nwant %s", hex.EncodeToString(rec), wantChaChaPaddedRecordHex)
		}

		// Verify decoding discards pad and recovers plaintext
		serverStream, err := NewV3CipherStream(&nopCloser{Buffer: bytes.NewBuffer(rec)}, keys, ProtocolCipherChaCha20Poly1305, 1, false)
		if err != nil {
			t.Fatalf("NewV3CipherStream error: %v", err)
		}
		readBuf := make([]byte, len(plain))
		if _, err := io.ReadFull(serverStream, readBuf); err != nil {
			t.Fatalf("ReadFull padded record error: %v", err)
		}
		if !bytes.Equal(readBuf, plain) {
			t.Fatalf("decrypted padded payload mismatch: got %q, want %q", string(readBuf), string(plain))
		}
	}
}

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
		!bytes.Equal(decodedInit.CipherPref, init.CipherPref) ||
		!bytes.Equal(decodedInit.ClientEphPK, init.ClientEphPK) {
		t.Fatalf("decoded ChannelInit mismatch: %+v vs %+v", decodedInit, init)
	}

	// Tampering tests for auth_proof:
	// 1. Tamper Capabilities
	tamperedInit := init
	tamperedInit.Capabilities ^= 1
	if VerifyV3AuthProof(token, serverName, path, tamperedInit) {
		t.Fatal("VerifyV3AuthProof accepted tampered capabilities")
	}

	// 2. Tamper CipherPref
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

	// 4. Tamper ClientEphPK
	tamperedInit = init
	tamperedInit.ClientEphPK = append([]byte(nil), init.ClientEphPK...)
	tamperedInit.ClientEphPK[0] ^= 0x01
	if VerifyV3AuthProof(token, serverName, path, tamperedInit) {
		t.Fatal("VerifyV3AuthProof accepted tampered client eph pk")
	}

	// 5. Tamper ServerName or Path
	if VerifyV3AuthProof(token, "evil.example.com", path, init) {
		t.Fatal("VerifyV3AuthProof accepted wrong server name")
	}
	if VerifyV3AuthProof(token, serverName, "/other", init) {
		t.Fatal("VerifyV3AuthProof accepted wrong path")
	}

	// 6. Tamper Token
	if VerifyV3AuthProof("wrong-token", serverName, path, init) {
		t.Fatal("VerifyV3AuthProof accepted wrong token")
	}

	// 7. Tamper AuthProof itself
	tamperedInit = init
	tamperedInit.AuthProof = append([]byte(nil), init.AuthProof...)
	tamperedInit.AuthProof[0] ^= 0x01
	if VerifyV3AuthProof(token, serverName, path, tamperedInit) {
		t.Fatal("VerifyV3AuthProof accepted tampered auth proof")
	}

	// ChannelAccept round trip & server_proof verification
	serverPk := fixedTestServerPk()
	serverProof, err := ComputeV3ServerProof(token, serverName, path, init, serverPk, ProtocolCipherChaCha20Poly1305)
	if err != nil {
		t.Fatalf("ComputeV3ServerProof failed: %v", err)
	}

	accept := ChannelAccept{
		Capabilities: 0x0000000000001bf7,
		ServerNonce:  bytes.Repeat([]byte{0x5a}, 32),
		ServerTime:   1_700_000_005,
		MaxFrameSize: 16384,
		MaxStreams:   100,
		Message:      "welcome v3",
		Cipher:       ProtocolCipherChaCha20Poly1305,
		ServerEphPK:  serverPk,
		ServerProof:  serverProof,
	}

	if !VerifyV3ServerProof(token, serverName, path, init, accept) {
		t.Fatal("VerifyV3ServerProof rejected valid ChannelAccept")
	}

	var acceptBuf bytes.Buffer
	if err := WriteChannelAcceptV3(&acceptBuf, accept); err != nil {
		t.Fatalf("WriteChannelAcceptV3 failed: %v", err)
	}
	decodedAccept, _, err := ReadChannelAcceptOrRejectV3(&acceptBuf, 0)
	if err != nil {
		t.Fatalf("ReadChannelAcceptOrRejectV3 failed: %v", err)
	}
	if decodedAccept.Capabilities != accept.Capabilities ||
		!bytes.Equal(decodedAccept.ServerNonce, accept.ServerNonce) ||
		decodedAccept.ServerTime != accept.ServerTime ||
		decodedAccept.MaxFrameSize != accept.MaxFrameSize ||
		decodedAccept.MaxStreams != accept.MaxStreams ||
		decodedAccept.Message != accept.Message ||
		decodedAccept.Cipher != accept.Cipher ||
		!bytes.Equal(decodedAccept.ServerEphPK, accept.ServerEphPK) ||
		!bytes.Equal(decodedAccept.ServerProof, accept.ServerProof) {
		t.Fatalf("decoded ChannelAccept mismatch: %+v vs %+v", decodedAccept, accept)
	}

	// Tamper tests for server_proof:
	// Tamper ServerEphPK
	tamperedAccept := accept
	tamperedAccept.ServerEphPK = append([]byte(nil), accept.ServerEphPK...)
	tamperedAccept.ServerEphPK[0] ^= 0x01
	if VerifyV3ServerProof(token, serverName, path, init, tamperedAccept) {
		t.Fatal("VerifyV3ServerProof accepted tampered server eph pk")
	}

	// Tamper ServerProof
	tamperedAccept = accept
	tamperedAccept.ServerProof = append([]byte(nil), accept.ServerProof...)
	tamperedAccept.ServerProof[0] ^= 0x01
	if VerifyV3ServerProof(token, serverName, path, init, tamperedAccept) {
		t.Fatal("VerifyV3ServerProof accepted tampered server proof")
	}

	// Tamper Cipher in Accept
	tamperedAccept = accept
	tamperedAccept.Cipher = ProtocolCipherAES256GCM
	if VerifyV3ServerProof(token, serverName, path, init, tamperedAccept) {
		t.Fatal("VerifyV3ServerProof accepted tampered cipher in accept")
	}

	// ChannelReject round trip
	rejectOut := ChannelReject{
		Code:    V3RejectUnsupportedCipher,
		Message: "no common cipher",
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

// 6. Forward Secrecy Property Tests
func TestV3ForwardSecrecyProperties(t *testing.T) {
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

	// Legitimate session keys
	legitKeys, err := DeriveV3SessionSeed(token, thFull, shared)
	if err != nil {
		t.Fatalf("DeriveV3SessionSeed legit error: %v", err)
	}

	// Attacker with known token and intercepted transcript, but without client ephemeral SK
	attackerShared := bytes.Repeat([]byte{0x77}, 32)
	attackerKeys, err := DeriveV3SessionSeed(token, thFull, attackerShared)
	if err != nil {
		t.Fatalf("DeriveV3SessionSeed attacker error: %v", err)
	}

	if bytes.Equal(legitKeys.Seed, attackerKeys.Seed) {
		t.Fatal("attacker derived same seed without client ephemeral SK")
	}

	// Encrypt sample payload with legitimate key
	var pipeBuf bytes.Buffer
	legitStream, err := NewV3CipherStream(&nopCloser{Buffer: &pipeBuf}, legitKeys, ProtocolCipherChaCha20Poly1305, 1, true)
	if err != nil {
		t.Fatalf("NewV3CipherStream error: %v", err)
	}
	payload := []byte("highly-confidential-traffic")
	if _, err := legitStream.Write(payload); err != nil {
		t.Fatalf("Write error: %v", err)
	}
	ciphertextRecord := append([]byte(nil), pipeBuf.Bytes()...)

	// Attacker tries to decrypt with attackerKeys -> MUST fail
	attackerBuf := bytes.NewBuffer(append([]byte(nil), ciphertextRecord...))
	attackerStream, err := NewV3CipherStream(&nopCloser{Buffer: attackerBuf}, attackerKeys, ProtocolCipherChaCha20Poly1305, 1, false)
	if err != nil {
		t.Fatalf("NewV3CipherStream attacker error: %v", err)
	}
	outBuf := make([]byte, len(payload))
	_, err = io.ReadFull(attackerStream, outBuf)
	if err == nil {
		t.Fatal("attacker successfully decrypted ciphertext with incorrect shared secret")
	}

	// Low-order point check: all zeros shared secret must be rejected
	zeroPoint := make([]byte, 32)
	_, err = ComputeV3SharedSecret(fixedTestClientSk, zeroPoint)
	if err == nil {
		t.Fatal("ComputeV3SharedSecret should reject all-zero peer public key")
	}
}

// 7. Fail Closed and Validation Tests
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
	badInit.CipherPref = []byte{}
	if err := WriteChannelInitV3(&buf, badInit); err == nil {
		t.Fatal("WriteChannelInitV3 should fail on empty cipher pref")
	}

	// Cipher preference count > 8
	badInit.CipherPref = []byte{1, 2, 3, 1, 2, 3, 1, 2, 3}
	if err := WriteChannelInitV3(&buf, badInit); err == nil {
		t.Fatal("WriteChannelInitV3 should fail on >8 cipher pref")
	}

	// Invalid ClientEphPK length
	badInit = fixedChannelInitV3()
	badInit.ClientEphPK = make([]byte, 31)
	if err := WriteChannelInitV3(&buf, badInit); err == nil {
		t.Fatal("WriteChannelInitV3 should fail on 31-byte ClientEphPK")
	}

	// Invalid ServerEphPK length in ChannelAccept
	badAccept := ChannelAccept{
		Capabilities: 0x0000000000001bf7,
		ServerNonce:  bytes.Repeat([]byte{0x5a}, 32),
		ServerTime:   1_700_000_005,
		Cipher:       ProtocolCipherChaCha20Poly1305,
		ServerEphPK:  make([]byte, 31),
		ServerProof:  bytes.Repeat([]byte{0x01}, 32),
	}
	if err := WriteChannelAcceptV3(&buf, badAccept); err == nil {
		t.Fatal("WriteChannelAcceptV3 should fail on 31-byte ServerEphPK")
	}

	// Invalid ServerProof length in ChannelAccept
	badAccept.ServerEphPK = bytes.Repeat([]byte{0x01}, 32)
	badAccept.ServerProof = make([]byte, 31)
	if err := WriteChannelAcceptV3(&buf, badAccept); err == nil {
		t.Fatal("WriteChannelAcceptV3 should fail on 31-byte ServerProof")
	}

	// DeriveV3SessionSeed validations
	if _, err := DeriveV3SessionSeed("", make([]byte, 32), make([]byte, 32)); err == nil {
		t.Fatal("DeriveV3SessionSeed should fail on empty token")
	}
	if _, err := DeriveV3SessionSeed("token", make([]byte, 31), make([]byte, 32)); err == nil {
		t.Fatal("DeriveV3SessionSeed should fail on 31-byte transcript hash")
	}
	if _, err := DeriveV3SessionSeed("token", make([]byte, 32), make([]byte, 31)); err == nil {
		t.Fatal("DeriveV3SessionSeed should fail on 31-byte shared secret")
	}
}

// 8. Cipher Stream Bit Flip and Integrity Tests
func TestV3CipherStreamBitFlipAndIntegrity(t *testing.T) {
	token := "secret-token"
	serverName := "edge.example.com"
	path := "/tunnel"
	init := fixedChannelInitV3()
	serverPk := fixedTestServerPk()
	shared := fixedTestSharedSecret()

	for _, cipherID := range []byte{ProtocolCipherChaCha20Poly1305, ProtocolCipherAES256GCM, ProtocolCipherAES128GCM} {
		t.Run(V3CipherName(cipherID), func(t *testing.T) {
			thFull, _ := ComputeV3TranscriptHashFull(serverName, path, init, serverPk, cipherID)
			keys, _ := DeriveV3SessionSeed(token, thFull, shared)

			// Subtest A: unpadded record (PadRecords = false)
			{
				var pipeBuf bytes.Buffer
				clientStream, err := NewV3CipherStream(&nopCloser{Buffer: &pipeBuf}, keys, cipherID, 1, true)
				if err != nil {
					t.Fatalf("NewV3CipherStream error: %v", err)
				}
				clientStream.PadRecords = false

				payload := []byte("confidential-payload-data-to-protect")
				if _, err := clientStream.Write(payload); err != nil {
					t.Fatalf("Write error: %v", err)
				}

				rawRecord := append([]byte(nil), pipeBuf.Bytes()...)
				// envelope = plain_len(2) + plain; no pad
				if len(rawRecord) != 12+2+len(payload)+16 {
					t.Fatalf("raw record len = %d, want %d", len(rawRecord), 12+2+len(payload)+16)
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

				// Bit flip tests at counter, header fields (authenticated as AD), ciphertext, and tag
				testPositions := []struct {
					name string
					idx  int
				}{
					{"counter byte 0", 0},
					{"counter byte 7", 7},
					{"payload_len byte 8", 8},
					{"payload_len byte 9", 9},
					{"reserved byte 10", 10},
					{"reserved byte 11", 11},
					{"ciphertext byte 12", 12},
					{"ciphertext byte 20", 20},
					{"tag byte first", 12 + 2 + len(payload)},
					{"tag byte last", len(rawRecord) - 1},
				}

				for _, tp := range testPositions {
					t.Run("unpadded/"+tp.name, func(t *testing.T) {
						corrupted := append([]byte(nil), rawRecord...)
						corrupted[tp.idx] ^= 0x01

						buf := bytes.NewBuffer(corrupted)
						serverStream, err := NewV3CipherStream(&nopCloser{Buffer: buf}, keys, cipherID, 1, false)
						if err != nil {
							t.Fatalf("NewV3CipherStream error: %v", err)
						}
						readBuf := make([]byte, len(payload))
						n, err := serverStream.Read(readBuf)
						if err == nil {
							t.Fatalf("corrupted %s decrypted without error, read %d bytes", tp.name, n)
						}
						_, err2 := serverStream.Read(readBuf)
						if err2 == nil {
							t.Fatal("stream remained readable after authentication failure")
						}
					})
				}
			}

			// Subtest B: padded record with fixed 50B pad
			{
				counter := uint64(1)
				plain := []byte("confidential-payload-data-to-protect")
				pad := bytes.Repeat([]byte{0xaa}, 50)
				// Envelope: plain_len(2B BE) | plain | pad.
				payload := make([]byte, 0, 2+len(plain)+len(pad))
				payload = binary.BigEndian.AppendUint16(payload, uint16(len(plain)))
				payload = append(payload, plain...)
				payload = append(payload, pad...)

				key, _ := keys.StreamKey(cipherID, true, 1, 0)
				var nonceArr [12]byte
				copy(nonceArr[0:4], keys.C2SNoncePrefix)
				binary.BigEndian.PutUint64(nonceArr[4:12], counter)

				aead, err := newAEAD(cipherID, key)
				if err != nil {
					t.Fatalf("newAEAD error: %v", err)
				}

				rec := make([]byte, 12)
				binary.BigEndian.PutUint64(rec[0:8], counter)
				binary.BigEndian.PutUint16(rec[8:10], uint16(len(payload)))
				binary.BigEndian.PutUint16(rec[10:12], 0) // reserved
				rec = aead.Seal(rec, nonceArr[:], payload, rec[:12])

				// Normal read must succeed and discard pad
				{
					buf := bytes.NewBuffer(append([]byte(nil), rec...))
					serverStream, err := NewV3CipherStream(&nopCloser{Buffer: buf}, keys, cipherID, 1, false)
					if err != nil {
						t.Fatalf("NewV3CipherStream error: %v", err)
					}
					readBuf := make([]byte, len(plain))
					if _, err := io.ReadFull(serverStream, readBuf); err != nil {
						t.Fatalf("normal ReadFull padded failed: %v", err)
					}
					if !bytes.Equal(readBuf, plain) {
						t.Fatalf("padded decrypted payload mismatch: got %s, want %s", string(readBuf), string(plain))
					}
				}

				// Bit flip tests covering header, plain area, pad area, and tag
				paddedPositions := []struct {
					name string
					idx  int
				}{
					{"payload_len byte 9", 9},
					{"reserved byte 10", 10},
					{"ciphertext plain byte", 12 + 2 + 5},
					{"ciphertext pad byte", 12 + 2 + len(plain) + 10},
					{"tag byte", 12 + len(payload) + 5},
				}

				for _, tp := range paddedPositions {
					t.Run("padded/"+tp.name, func(t *testing.T) {
						corrupted := append([]byte(nil), rec...)
						corrupted[tp.idx] ^= 0x01

						buf := bytes.NewBuffer(corrupted)
						serverStream, err := NewV3CipherStream(&nopCloser{Buffer: buf}, keys, cipherID, 1, false)
						if err != nil {
							t.Fatalf("NewV3CipherStream error: %v", err)
						}
						readBuf := make([]byte, len(plain))
						n, err := serverStream.Read(readBuf)
						if err == nil {
							t.Fatalf("corrupted %s decrypted without error, read %d bytes", tp.name, n)
						}
						_, err2 := serverStream.Read(readBuf)
						if err2 == nil {
							t.Fatal("stream remained readable after authentication failure")
						}
					})
				}
			}
		})
	}
}

// 9. Replay and Out-of-Order Tests
func TestV3CipherStreamReplayAndOutOfOrder(t *testing.T) {
	token := "secret-token"
	serverName := "edge.example.com"
	path := "/tunnel"
	init := fixedChannelInitV3()
	serverPk := fixedTestServerPk()
	shared := fixedTestSharedSecret()
	thFull, _ := ComputeV3TranscriptHashFull(serverName, path, init, serverPk, ProtocolCipherChaCha20Poly1305)
	keys, _ := DeriveV3SessionSeed(token, thFull, shared)

	// Generate 10 records from client
	var pipeBuf bytes.Buffer
	clientStream, err := NewV3CipherStream(&nopCloser{Buffer: &pipeBuf}, keys, ProtocolCipherChaCha20Poly1305, 1, true)
	if err != nil {
		t.Fatalf("NewV3CipherStream error: %v", err)
	}

	var records [][]byte
	for i := 1; i <= 10; i++ {
		pipeBuf.Reset()
		msg := fmt.Sprintf("message-packet-%02d", i)
		if _, err := clientStream.Write([]byte(msg)); err != nil {
			t.Fatalf("write msg %d failed: %v", i, err)
		}
		rec := append([]byte(nil), pipeBuf.Bytes()...)
		records = append(records, rec)
	}

	// Case 1: Exact replay of record 1 -> rejected
	{
		var testBuf bytes.Buffer
		testBuf.Write(records[0])
		testBuf.Write(records[0]) // replay

		serverStream, err := NewV3CipherStream(&nopCloser{Buffer: &testBuf}, keys, ProtocolCipherChaCha20Poly1305, 1, false)
		if err != nil {
			t.Fatalf("NewV3CipherStream error: %v", err)
		}
		buf := make([]byte, len("message-packet-01"))
		if _, err := io.ReadFull(serverStream, buf); err != nil {
			t.Fatalf("first read failed: %v", err)
		}
		// Second read must fail due to replay
		_, err = io.ReadFull(serverStream, buf)
		if err == nil {
			t.Fatal("replayed record 1 was accepted")
		}
	}

	// Case 2: Out of order within window: 1, 3, 2 -> accepted
	{
		var testBuf bytes.Buffer
		testBuf.Write(records[0]) // seq 1
		testBuf.Write(records[2]) // seq 3
		testBuf.Write(records[1]) // seq 2

		serverStream, err := NewV3CipherStream(&nopCloser{Buffer: &testBuf}, keys, ProtocolCipherChaCha20Poly1305, 1, false)
		if err != nil {
			t.Fatalf("NewV3CipherStream error: %v", err)
		}
		buf := make([]byte, len("message-packet-01"))
		// read 1
		if _, err := io.ReadFull(serverStream, buf); err != nil || string(buf) != "message-packet-01" {
			t.Fatalf("read 1 failed: %v", err)
		}
		// read 3
		if _, err := io.ReadFull(serverStream, buf); err != nil || string(buf) != "message-packet-03" {
			t.Fatalf("read 3 failed: %v", err)
		}
		// read 2
		if _, err := io.ReadFull(serverStream, buf); err != nil || string(buf) != "message-packet-02" {
			t.Fatalf("read 2 failed: %v", err)
		}
	}

	// Case 3: Replay after advance: 1, 2, 3, 2 (replay 2) -> rejected
	{
		var testBuf bytes.Buffer
		testBuf.Write(records[0]) // 1
		testBuf.Write(records[1]) // 2
		testBuf.Write(records[2]) // 3
		testBuf.Write(records[1]) // 2 (replay)

		serverStream, err := NewV3CipherStream(&nopCloser{Buffer: &testBuf}, keys, ProtocolCipherChaCha20Poly1305, 1, false)
		if err != nil {
			t.Fatalf("NewV3CipherStream error: %v", err)
		}
		buf := make([]byte, len("message-packet-01"))
		for i := 1; i <= 3; i++ {
			if _, err := io.ReadFull(serverStream, buf); err != nil {
				t.Fatalf("read %d failed: %v", i, err)
			}
		}
		_, err = io.ReadFull(serverStream, buf)
		if err == nil {
			t.Fatal("replayed record 2 was accepted")
		}
	}
}

// 10. Generation Rekey Tests
func TestV3CipherStreamRekey(t *testing.T) {
	token := "secret-token"
	serverName := "edge.example.com"
	path := "/tunnel"
	init := fixedChannelInitV3()
	serverPk := fixedTestServerPk()
	shared := fixedTestSharedSecret()
	thFull, _ := ComputeV3TranscriptHashFull(serverName, path, init, serverPk, ProtocolCipherChaCha20Poly1305)
	keys, _ := DeriveV3SessionSeed(token, thFull, shared)

	var pipeBuf bytes.Buffer
	clientStream, err := NewV3CipherStream(&nopCloser{Buffer: &pipeBuf}, keys, ProtocolCipherChaCha20Poly1305, 1, true)
	if err != nil {
		t.Fatalf("NewV3CipherStream error: %v", err)
	}

	// Set client write counter right before boundary 2^32
	clientStream.writeCounter = defaultRekeyInterval - 1 // 4294967295

	// Write record at gen 0 (counter 4294967295)
	if _, err := clientStream.Write([]byte("before-rekey")); err != nil {
		t.Fatalf("write before rekey failed: %v", err)
	}
	if clientStream.writeGen != 0 {
		t.Fatalf("writeGen before rekey = %d, want 0", clientStream.writeGen)
	}

	// Next write crosses boundary to gen 1 (counter 4294967296)
	if _, err := clientStream.Write([]byte("after-rekey")); err != nil {
		t.Fatalf("write after rekey failed: %v", err)
	}
	if clientStream.writeGen != 1 {
		t.Fatalf("writeGen after rekey = %d, want 1", clientStream.writeGen)
	}

	// Verify server reads both correctly crossing rekey boundary
	serverStream, err := NewV3CipherStream(&nopCloser{Buffer: &pipeBuf}, keys, ProtocolCipherChaCha20Poly1305, 1, false)
	if err != nil {
		t.Fatalf("NewV3CipherStream error: %v", err)
	}

	buf1 := make([]byte, len("before-rekey"))
	if _, err := io.ReadFull(serverStream, buf1); err != nil {
		t.Fatalf("read before-rekey failed: %v", err)
	}
	if string(buf1) != "before-rekey" {
		t.Fatalf("read mismatch: %s", string(buf1))
	}
	if serverStream.readGen != 0 {
		t.Fatalf("server readGen = %d, want 0", serverStream.readGen)
	}

	buf2 := make([]byte, len("after-rekey"))
	if _, err := io.ReadFull(serverStream, buf2); err != nil {
		t.Fatalf("read after-rekey failed: %v", err)
	}
	if string(buf2) != "after-rekey" {
		t.Fatalf("read mismatch: %s", string(buf2))
	}
	if serverStream.readGen != 1 {
		t.Fatalf("server readGen = %d, want 1", serverStream.readGen)
	}
}

// 11. Deadline and Unsupported Operations Test
func TestV3Deadlines(t *testing.T) {
	token := "secret-token"
	serverName := "edge.example.com"
	path := "/tunnel"
	init := fixedChannelInitV3()
	serverPk := fixedTestServerPk()
	shared := fixedTestSharedSecret()
	thFull, _ := ComputeV3TranscriptHashFull(serverName, path, init, serverPk, ProtocolCipherChaCha20Poly1305)
	keys, _ := DeriveV3SessionSeed(token, thFull, shared)

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

// 12. Payload limit & validation tests
func TestV3CipherStreamPayloadLimit(t *testing.T) {
	token := "secret-token"
	serverName := "edge.example.com"
	path := "/tunnel"
	init := fixedChannelInitV3()
	serverPk := fixedTestServerPk()
	shared := fixedTestSharedSecret()
	thFull, _ := ComputeV3TranscriptHashFull(serverName, path, init, serverPk, ProtocolCipherChaCha20Poly1305)
	keys, _ := DeriveV3SessionSeed(token, thFull, shared)

	// Case 1: payload_len > 1400 -> Read rejects
	{
		var raw [12 + 1401 + 16]byte
		binary.BigEndian.PutUint64(raw[0:8], 1)
		binary.BigEndian.PutUint16(raw[8:10], 1401) // payload_len = 1401 > 1400

		serverStream, err := NewV3CipherStream(&nopCloser{Buffer: bytes.NewBuffer(raw[:])}, keys, ProtocolCipherChaCha20Poly1305, 1, false)
		if err != nil {
			t.Fatalf("NewV3CipherStream error: %v", err)
		}
		buf := make([]byte, 1000)
		if _, err := serverStream.Read(buf); err == nil {
			t.Fatal("expected Read error for payload_len > 1400, got nil")
		}
	}

	// Case 2: payload_len too small for inner length field + 1B plaintext -> Read rejects
	{
		var raw [12 + 2 + 16]byte
		binary.BigEndian.PutUint64(raw[0:8], 1)
		binary.BigEndian.PutUint16(raw[8:10], 2) // room for length field only

		serverStream, err := NewV3CipherStream(&nopCloser{Buffer: bytes.NewBuffer(raw[:])}, keys, ProtocolCipherChaCha20Poly1305, 1, false)
		if err != nil {
			t.Fatalf("NewV3CipherStream error: %v", err)
		}
		buf := make([]byte, 100)
		if _, err := serverStream.Read(buf); err == nil {
			t.Fatal("expected Read error for undersized payload_len, got nil")
		}
	}

	// Case 3: counter == 0 -> Read rejects
	{
		var raw [12 + 100]byte
		binary.BigEndian.PutUint64(raw[0:8], 0) // counter = 0
		binary.BigEndian.PutUint16(raw[8:10], 10)
		binary.BigEndian.PutUint16(raw[10:12], 0) // reserved

		serverStream, err := NewV3CipherStream(&nopCloser{Buffer: bytes.NewBuffer(raw[:])}, keys, ProtocolCipherChaCha20Poly1305, 1, false)
		if err != nil {
			t.Fatalf("NewV3CipherStream error: %v", err)
		}
		buf := make([]byte, 100)
		if _, err := serverStream.Read(buf); err == nil {
			t.Fatal("expected Read error for counter == 0, got nil")
		}
	}
}

// 13. Padding sampling statistical tests
func TestV3CipherStreamPaddingSamplingStats(t *testing.T) {
	token := "secret-token"
	serverName := "edge.example.com"
	path := "/tunnel"
	init := fixedChannelInitV3()
	serverPk := fixedTestServerPk()
	shared := fixedTestSharedSecret()
	thFull, _ := ComputeV3TranscriptHashFull(serverName, path, init, serverPk, ProtocolCipherChaCha20Poly1305)
	keys, _ := DeriveV3SessionSeed(token, thFull, shared)

	var pipeBuf bytes.Buffer
	clientStream, err := NewV3CipherStream(&nopCloser{Buffer: &pipeBuf}, keys, ProtocolCipherChaCha20Poly1305, 1, true)
	if err != nil {
		t.Fatalf("NewV3CipherStream error: %v", err)
	}
	clientStream.PadRecords = true
	clientStream.CoalesceDelay = 0

	uniquePadLens := make(map[int]bool)
	payload := []byte("0123456789") // 10 bytes

	for i := 0; i < 100; i++ {
		pipeBuf.Reset()
		if _, err := clientStream.Write(payload); err != nil {
			t.Fatalf("Write error on record %d: %v", i, err)
		}
		raw := pipeBuf.Bytes()
		if len(raw) < 12+len(payload)+16 {
			t.Fatalf("record %d too short: %d", i, len(raw))
		}
		payloadLen := int(binary.BigEndian.Uint16(raw[8:10]))
		padLen := payloadLen - v3PlainLenSize - len(payload)
		if padLen < 0 || payloadLen > maxV3RecordPayload {
			t.Fatalf("record %d payload_len %d out of bounds for 10-byte plaintext", i, payloadLen)
		}
		uniquePadLens[padLen] = true

		// Verify receiver can decode each record correctly
		serverStream, err := NewV3CipherStream(&nopCloser{Buffer: bytes.NewBuffer(raw)}, keys, ProtocolCipherChaCha20Poly1305, 1, false)
		if err != nil {
			t.Fatalf("NewV3CipherStream server error: %v", err)
		}
		out := make([]byte, len(payload))
		if _, err := io.ReadFull(serverStream, out); err != nil {
			t.Fatalf("server ReadFull error on record %d: %v", i, err)
		}
		if !bytes.Equal(out, payload) {
			t.Fatalf("server payload mismatch on record %d", i)
		}
	}

	if len(uniquePadLens) <= 5 {
		t.Fatalf("padding distribution degenerate: only %d unique pad_len values across 100 records (want >5)", len(uniquePadLens))
	}
}

// 14. Transcript hash independence from padding
func TestV3TranscriptPaddingIndependent(t *testing.T) {
	token := "secret-token"
	serverName := "edge.example.com"
	path := "/tunnel"
	serverPk := fixedTestServerPk()
	chosenCipher := ProtocolCipherChaCha20Poly1305

	initWithoutPad := fixedChannelInitV3()
	initWithPad := fixedChannelInitV3()
	initWithPad.Padding = []byte("random-padding-bytes-0123456789")

	// Transcript Hash Init
	thInit1, err := ComputeV3TranscriptHashInit(serverName, path, initWithoutPad)
	if err != nil {
		t.Fatalf("ComputeV3TranscriptHashInit 1 error: %v", err)
	}
	thInit2, err := ComputeV3TranscriptHashInit(serverName, path, initWithPad)
	if err != nil {
		t.Fatalf("ComputeV3TranscriptHashInit 2 error: %v", err)
	}
	if !bytes.Equal(thInit1, thInit2) {
		t.Fatalf("transcript_hash_init changed when padding added:\nno pad: %x\nw/ pad: %x", thInit1, thInit2)
	}

	// Transcript Hash Full
	thFull1, err := ComputeV3TranscriptHashFull(serverName, path, initWithoutPad, serverPk, chosenCipher)
	if err != nil {
		t.Fatalf("ComputeV3TranscriptHashFull 1 error: %v", err)
	}
	thFull2, err := ComputeV3TranscriptHashFull(serverName, path, initWithPad, serverPk, chosenCipher)
	if err != nil {
		t.Fatalf("ComputeV3TranscriptHashFull 2 error: %v", err)
	}
	if !bytes.Equal(thFull1, thFull2) {
		t.Fatalf("transcript_hash_full changed when padding added:\nno pad: %x\nw/ pad: %x", thFull1, thFull2)
	}

	// AuthProof
	proof1, err := ComputeV3AuthProof(token, serverName, path, initWithoutPad)
	if err != nil {
		t.Fatalf("ComputeV3AuthProof 1 error: %v", err)
	}
	proof2, err := ComputeV3AuthProof(token, serverName, path, initWithPad)
	if err != nil {
		t.Fatalf("ComputeV3AuthProof 2 error: %v", err)
	}
	if !bytes.Equal(proof1, proof2) {
		t.Fatalf("auth_proof changed when padding added:\nno pad: %x\nw/ pad: %x", proof1, proof2)
	}

	// ServerProof
	sProof1, err := ComputeV3ServerProof(token, serverName, path, initWithoutPad, serverPk, chosenCipher)
	if err != nil {
		t.Fatalf("ComputeV3ServerProof 1 error: %v", err)
	}
	sProof2, err := ComputeV3ServerProof(token, serverName, path, initWithPad, serverPk, chosenCipher)
	if err != nil {
		t.Fatalf("ComputeV3ServerProof 2 error: %v", err)
	}
	if !bytes.Equal(sProof1, sProof2) {
		t.Fatalf("server_proof changed when padding added:\nno pad: %x\nw/ pad: %x", sProof1, sProof2)
	}
}

// 15. Segment coalescing tests
func TestV3CipherStreamCoalesce(t *testing.T) {
	token := "secret-token"
	serverName := "edge.example.com"
	path := "/tunnel"
	init := fixedChannelInitV3()
	serverPk := fixedTestServerPk()
	shared := fixedTestSharedSecret()
	thFull, _ := ComputeV3TranscriptHashFull(serverName, path, init, serverPk, ProtocolCipherChaCha20Poly1305)
	keys, _ := DeriveV3SessionSeed(token, thFull, shared)

	// Part A: CoalesceDelay = 20ms, write 3x 100B, flushed after delay
	{
		r, w := net.Pipe()
		clientStream, err := NewV3CipherStream(w, keys, ProtocolCipherChaCha20Poly1305, 1, true)
		if err != nil {
			t.Fatalf("NewV3CipherStream client error: %v", err)
		}
		clientStream.CoalesceDelay = 20 * time.Millisecond
		clientStream.PadRecords = false

		serverStream, err := NewV3CipherStream(r, keys, ProtocolCipherChaCha20Poly1305, 1, false)
		if err != nil {
			t.Fatalf("NewV3CipherStream server error: %v", err)
		}

		p1 := bytes.Repeat([]byte("A"), 100)
		p2 := bytes.Repeat([]byte("B"), 100)
		p3 := bytes.Repeat([]byte("C"), 100)
		expected := append(append(append([]byte(nil), p1...), p2...), p3...)

		if _, err := clientStream.Write(p1); err != nil {
			t.Fatalf("Write p1 error: %v", err)
		}
		if _, err := clientStream.Write(p2); err != nil {
			t.Fatalf("Write p2 error: %v", err)
		}
		if _, err := clientStream.Write(p3); err != nil {
			t.Fatalf("Write p3 error: %v", err)
		}

		// Immediate check: data should NOT be flushed yet (coalescing in flight)
		_ = r.SetReadDeadline(time.Now().Add(5 * time.Millisecond))
		immediateBuf := make([]byte, 300)
		_, err = serverStream.Read(immediateBuf)
		if err == nil {
			t.Fatal("expected read timeout before CoalesceDelay elapsed, but read succeeded")
		}

		// Wait for timer to flush
		_ = r.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		outBuf := make([]byte, 300)
		if _, err := io.ReadFull(serverStream, outBuf); err != nil {
			t.Fatalf("ReadFull after coalesce delay error: %v", err)
		}
		if !bytes.Equal(outBuf, expected) {
			t.Fatalf("coalesced payload mismatch: got %q, want %q", string(outBuf), string(expected))
		}

		clientStream.Close()
		serverStream.Close()
	}

	// Part B: Close() flushes remaining buffered data
	{
		r, w := net.Pipe()
		clientStream, err := NewV3CipherStream(w, keys, ProtocolCipherChaCha20Poly1305, 1, true)
		if err != nil {
			t.Fatalf("NewV3CipherStream client error: %v", err)
		}
		clientStream.CoalesceDelay = 1000 * time.Millisecond // long delay
		clientStream.PadRecords = false

		serverStream, err := NewV3CipherStream(r, keys, ProtocolCipherChaCha20Poly1305, 1, false)
		if err != nil {
			t.Fatalf("NewV3CipherStream server error: %v", err)
		}

		p := bytes.Repeat([]byte("X"), 100)
		if _, err := clientStream.Write(p); err != nil {
			t.Fatalf("Write error: %v", err)
		}

		// Close clientStream -> must flush p immediately
		go func() {
			clientStream.Close()
		}()

		_ = r.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		outBuf := make([]byte, 100)
		if _, err := io.ReadFull(serverStream, outBuf); err != nil {
			t.Fatalf("ReadFull on Close() flush error: %v", err)
		}
		if !bytes.Equal(outBuf, p) {
			t.Fatalf("payload on Close flush mismatch")
		}
		serverStream.Close()
	}

	// Part C: Write > 1024B immediately forms records without waiting for timer
	{
		r, w := net.Pipe()
		clientStream, err := NewV3CipherStream(w, keys, ProtocolCipherChaCha20Poly1305, 1, true)
		if err != nil {
			t.Fatalf("NewV3CipherStream client error: %v", err)
		}
		clientStream.CoalesceDelay = 1000 * time.Millisecond // long delay
		clientStream.PadRecords = false

		serverStream, err := NewV3CipherStream(r, keys, ProtocolCipherChaCha20Poly1305, 1, false)
		if err != nil {
			t.Fatalf("NewV3CipherStream server error: %v", err)
		}

		p := bytes.Repeat([]byte("Z"), 1050) // > 1024
		go func() {
			if _, err := clientStream.Write(p); err != nil {
				t.Errorf("Write >1024 error: %v", err)
			}
		}()

		// Should be readable immediately without waiting for the 1000ms delay
		_ = r.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		outBuf := make([]byte, 1050)
		if _, err := io.ReadFull(serverStream, outBuf); err != nil {
			t.Fatalf("ReadFull on >1024B write error: %v", err)
		}
		if !bytes.Equal(outBuf, p) {
			t.Fatalf("payload mismatch on >1024B write")
		}

		clientStream.Close()
		serverStream.Close()
	}
}

type nopCloser struct {
	*bytes.Buffer
}

func (n *nopCloser) Close() error {
	return nil
}
