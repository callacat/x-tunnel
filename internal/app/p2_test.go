package app

import (
	"bytes"
	"math/rand"
	"testing"
	"time"

	"github.com/xtaci/smux"
)

// ======================== 1. Keepalive Jitter Tests ========================

func TestJitterKeepAliveBaseNonPositive(t *testing.T) {
	if got := jitterKeepAlive(0); got != 0 {
		t.Fatalf("jitterKeepAlive(0) = %v, want 0", got)
	}
	if got := jitterKeepAlive(-5 * time.Second); got != -5*time.Second {
		t.Fatalf("jitterKeepAlive(-5s) = %v, want -5s", got)
	}
	if got := jitterKeepAliveWith(rand.New(rand.NewSource(42)), -10*time.Second); got != -10*time.Second {
		t.Fatalf("jitterKeepAliveWith(-10s) = %v, want -10s", got)
	}
}

// deterministicRandSource provides a fixed Float64 sequence.
type deterministicRandSource struct {
	val float64
}

func (s *deterministicRandSource) Int63() int64 {
	return int64(s.val * float64(1<<63-1))
}
func (s *deterministicRandSource) Seed(seed int64) {}

func TestJitterKeepAliveDeterministicBounds(t *testing.T) {
	base := 10 * time.Second

	// Minimum bound: rand = 0.0 -> base * (0.8 + 0.4*0.0) = 8.0s
	rMin := rand.New(&deterministicRandSource{val: 0.0})
	gotMin := jitterKeepAliveWith(rMin, base)
	if gotMin != 8*time.Second {
		t.Fatalf("jitterKeepAliveWith(0.0, 10s) = %v, want 8s", gotMin)
	}

	// Midpoint: rand = 0.5 -> base * (0.8 + 0.4*0.5) = 10.0s
	rMid := rand.New(&deterministicRandSource{val: 0.5})
	gotMid := jitterKeepAliveWith(rMid, base)
	if gotMid != 10*time.Second {
		t.Fatalf("jitterKeepAliveWith(0.5, 10s) = %v, want 10s", gotMid)
	}

	// Maximum bound: rand = 0.999999 -> base * (0.8 + 0.4*1.0) = ~12.0s
	rMax := rand.New(&deterministicRandSource{val: 0.9999999})
	gotMax := jitterKeepAliveWith(rMax, base)
	if gotMax < 11999*time.Millisecond || gotMax > 12*time.Second {
		t.Fatalf("jitterKeepAliveWith(~1.0, 10s) = %v, want ~12s", gotMax)
	}
}

func TestJitterKeepAliveDistribution(t *testing.T) {
	base := 10 * time.Second
	minExpected := 8 * time.Second
	maxExpected := 12 * time.Second

	for i := 0; i < 1000; i++ {
		got := jitterKeepAlive(base)
		if got < minExpected || got > maxExpected {
			t.Fatalf("iteration %d: jitterKeepAlive(10s) = %v out of range [%v, %v]", i, got, minExpected, maxExpected)
		}
	}
}

func TestNewSmuxConfig(t *testing.T) {
	defCfg := smux.DefaultConfig()
	cfg := newSmuxConfig()

	if cfg == nil {
		t.Fatal("newSmuxConfig returned nil")
	}
	if cfg.Version != defCfg.Version {
		t.Fatalf("Version = %d, want %d", cfg.Version, defCfg.Version)
	}
	if cfg.KeepAliveDisabled != defCfg.KeepAliveDisabled {
		t.Fatalf("KeepAliveDisabled = %v, want %v", cfg.KeepAliveDisabled, defCfg.KeepAliveDisabled)
	}
	if cfg.KeepAliveTimeout != defCfg.KeepAliveTimeout {
		t.Fatalf("KeepAliveTimeout = %v, want %v", cfg.KeepAliveTimeout, defCfg.KeepAliveTimeout)
	}
	if cfg.MaxFrameSize != defCfg.MaxFrameSize {
		t.Fatalf("MaxFrameSize = %d, want %d", cfg.MaxFrameSize, defCfg.MaxFrameSize)
	}
	if cfg.MaxReceiveBuffer != defCfg.MaxReceiveBuffer {
		t.Fatalf("MaxReceiveBuffer = %d, want %d", cfg.MaxReceiveBuffer, defCfg.MaxReceiveBuffer)
	}
	if cfg.MaxStreamBuffer != defCfg.MaxStreamBuffer {
		t.Fatalf("MaxStreamBuffer = %d, want %d", cfg.MaxStreamBuffer, defCfg.MaxStreamBuffer)
	}
	if cfg.KeepAliveInterval < 8*time.Second || cfg.KeepAliveInterval > 12*time.Second {
		t.Fatalf("KeepAliveInterval = %v, want in [8s, 12s]", cfg.KeepAliveInterval)
	}
}

// ======================== 2. Pacer Tests ========================

func TestPacerWriterDisabledRate(t *testing.T) {
	var buf bytes.Buffer
	pw := newPacerWriterMbps(&buf, 0)
	if _, ok := pw.(*pacerWriter); ok {
		t.Fatalf("newPacerWriterMbps(0) returned *pacerWriter, expected raw writer")
	}

	data := []byte("hello world")
	n, err := pw.Write(data)
	if err != nil || n != len(data) {
		t.Fatalf("Write returned (%d, %v), want (%d, nil)", n, err, len(data))
	}
	if buf.String() != "hello world" {
		t.Fatalf("buf = %q, want hello world", buf.String())
	}
}

func TestPacerWriterRateLowerBound(t *testing.T) {
	// 5 MB/s = 5,000,000 B/s (equivalent to 40 Mbps)
	// Write 200 KB = 204,800 B.
	// Burst is 64 KB = 65,536 B.
	// Deficit to throttle = 204,800 - 65,536 = 139,264 B.
	// Expected sleep = 139,264 / 5,000,000 = ~27.85 ms.
	// Assertion: duration >= 20ms (relaxed to prevent CI flakiness).
	var buf bytes.Buffer
	bytesPerSec := 5.0 * 1000 * 1000 // 5 MB/s
	burst := 64.0 * 1024             // 64 KB

	pw := newPacerWriter(&buf, bytesPerSec, burst)
	data := make([]byte, 200*1024)
	for i := range data {
		data[i] = byte(i % 256)
	}

	start := time.Now()
	// Write in chunks (similar to io.Copy with 32KB buffer)
	chunkSize := 32 * 1024
	for offset := 0; offset < len(data); offset += chunkSize {
		end := offset + chunkSize
		if end > len(data) {
			end = len(data)
		}
		n, err := pw.Write(data[offset:end])
		if err != nil {
			t.Fatalf("Write chunk error: %v", err)
		}
		if n != end-offset {
			t.Fatalf("Write chunk returned %d, want %d", n, end-offset)
		}
	}
	elapsed := time.Since(start)

	if elapsed < 20*time.Millisecond {
		t.Fatalf("Pacing 200KB at 5MB/s took %v, want >= 20ms", elapsed)
	}
	if buf.Len() != 200*1024 {
		t.Fatalf("buf length = %d, want %d", buf.Len(), 200*1024)
	}
}

func TestPacerWriterSleepInjection(t *testing.T) {
	var buf bytes.Buffer
	bytesPerSec := 1000.0 // 1000 B/s
	burst := 100.0        // 100 B burst

	pw := newPacerWriter(&buf, bytesPerSec, burst)
	var totalSlept time.Duration
	pw.sleepFn = func(d time.Duration) {
		totalSlept += d
	}

	// First write 100 B (uses burst, 0 sleep)
	_, err := pw.Write(make([]byte, 100))
	if err != nil {
		t.Fatalf("Write 1: %v", err)
	}
	if totalSlept != 0 {
		t.Fatalf("totalSlept after burst = %v, want 0", totalSlept)
	}

	// Second write 500 B (500 B deficit / 1000 B/s = 500ms sleep)
	_, err = pw.Write(make([]byte, 500))
	if err != nil {
		t.Fatalf("Write 2: %v", err)
	}
	if totalSlept < 490*time.Millisecond || totalSlept > 510*time.Millisecond {
		t.Fatalf("totalSlept = %v, want 500ms", totalSlept)
	}
}

// ======================== 3. Cipher Preference Tests ========================

func TestParseCipherPreferenceValid(t *testing.T) {
	tests := []struct {
		input string
		want  []byte
	}{
		{"1,2,3", []byte{1, 2, 3}},
		{"1", []byte{1}},
		{"2,1", []byte{2, 1}},
		{" 1 , 2 , 3 ", []byte{1, 2, 3}},
		{"3,2,1", []byte{3, 2, 1}},
	}
	for _, tt := range tests {
		got, err := parseCipherPreference(tt.input)
		if err != nil {
			t.Fatalf("parseCipherPreference(%q) unexpected error: %v", tt.input, err)
		}
		if !bytes.Equal(got, tt.want) {
			t.Fatalf("parseCipherPreference(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestParseCipherPreferenceInvalid(t *testing.T) {
	invalid := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"whitespace only", "   "},
		{"empty part", "1,,3"},
		{"unknown cipher ID 99", "1,99,3"},
		{"unknown cipher ID 0", "0,1,2"},
		{"non-numeric ID", "1,aes,3"},
		{"negative number", "1,-2,3"},
		{"overflow number", "1,256,3"},
		{"too long 9 elements", "1,2,3,1,2,3,1,2,3"},
	}
	for _, tt := range invalid {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseCipherPreference(tt.input)
			if err == nil {
				t.Fatalf("parseCipherPreference(%q) accepted invalid input, got %v", tt.input, got)
			}
		})
	}
}

func TestClientCipherPreferenceFallback(t *testing.T) {
	oldPref := configuredCipherPref
	oldStr := cipherPrefStr
	defer func() {
		configuredCipherPref = oldPref
		cipherPrefStr = oldStr
	}()

	// When configuredCipherPref is set, use it
	configuredCipherPref = []byte{2, 1}
	if got := clientCipherPreference(); !bytes.Equal(got, []byte{2, 1}) {
		t.Fatalf("clientCipherPreference() = %v, want [2 1]", got)
	}

	// When configuredCipherPref is nil, parse cipherPrefStr
	configuredCipherPref = nil
	cipherPrefStr = "3,1"
	if got := clientCipherPreference(); !bytes.Equal(got, []byte{3, 1}) {
		t.Fatalf("clientCipherPreference() = %v, want [3 1]", got)
	}

	// When cipherPrefStr is invalid, fallback to defaultCipherPreference
	cipherPrefStr = "invalid"
	if got := clientCipherPreference(); !bytes.Equal(got, defaultCipherPreference) {
		t.Fatalf("clientCipherPreference() = %v, want defaultCipherPreference", got)
	}
}

// ======================== 4. ECH Default Off Tests ========================

func TestECHDefaultOffInStartupConfig(t *testing.T) {
	restore := withValidStartupGlobals(t)
	defer restore()

	// Default runtime values: enableECH is false, fallback is false
	values := defaultRuntimeValues()
	if values.EnableECH != false {
		t.Fatalf("defaultRuntimeValues().EnableECH = %v, want false", values.EnableECH)
	}
	if values.Fallback != false {
		t.Fatalf("defaultRuntimeValues().Fallback = %v, want false", values.Fallback)
	}

	// Validate client config for wss when ECH is off: Fallback should be true (standard TLS 1.3)
	clientCfg, err := validateClientStartupConfig("wss://example.com:443/tunnel", 1, "", "", false, false, false, "443")
	if err != nil {
		t.Fatalf("validateClientStartupConfig error: %v", err)
	}
	if !clientCfg.Fallback {
		t.Fatalf("clientCfg.Fallback = %v, want true (ECH default disabled)", clientCfg.Fallback)
	}
	if clientCfg.EnableECH {
		t.Fatalf("clientCfg.EnableECH = %v, want false", clientCfg.EnableECH)
	}

	// When -ech (enableECHMode = true) is explicitly set: Fallback should be false
	clientCfgECH, err := validateClientStartupConfig("wss://example.com:443/tunnel", 1, "", "", false, false, true, "443")
	if err != nil {
		t.Fatalf("validateClientStartupConfig with ECH error: %v", err)
	}
	if clientCfgECH.Fallback {
		t.Fatalf("clientCfgECH.Fallback = %v, want false (ECH enabled)", clientCfgECH.Fallback)
	}
	if !clientCfgECH.EnableECH {
		t.Fatalf("clientCfgECH.EnableECH = %v, want true", clientCfgECH.EnableECH)
	}
}

func TestWSSStartupWithDefaultECHOffDoesNotRequireDNSValidation(t *testing.T) {
	restore := withValidStartupGlobals(t)
	defer restore()

	forwardAddr = "wss://example.com:443/tunnel"
	enableECH = false
	fallback = false
	// Invalid DNS server that would fail if ECH was on:
	dnsServer = "ftp://invalid-dns"
	echDomain = "bad host.example"

	// Since ECH is default off, DNS lookup config is not validated and startup succeeds
	startup, err := validateStartupConfig()
	if err != nil {
		t.Fatalf("validateStartupConfig returned error when ECH is off: %v", err)
	}
	if !startup.Client.Fallback {
		t.Fatal("startup.Client.Fallback = false, want true when ECH is off")
	}
}

// ======================== 5. Shaping Coalesce Tests ========================

func TestShapingCoalesceFlagValidation(t *testing.T) {
	restore := withValidStartupGlobals(t)
	defer restore()

	shapingCoalesceMs = -5
	if _, err := validateStartupConfig(); err == nil {
		t.Fatal("validateStartupConfig accepted negative shapingCoalesceMs")
	}

	pacingRateMbps = -1.0
	shapingCoalesceMs = 0
	if _, err := validateStartupConfig(); err == nil {
		t.Fatal("validateStartupConfig accepted negative pacingRateMbps")
	}
}

// ======================== 6. JSON Config Aliases Tests ========================

func TestLoadConfigFileAppliesP2Fields(t *testing.T) {
	restore := withValidStartupGlobals(t)
	defer restore()

	jsonContent := `{
		"listen": "socks5://127.0.0.1:11080",
		"forward": "wss://127.0.0.1:18080/tunnel",
		"token": "local-test-token",
		"ech": true,
		"ech_domain": "custom-ech.example.com",
		"cipher_pref": "2,1",
		"pacing_rate_mbps": 10.5,
		"shaping_coalesce_ms": 20
	}`

	if err := CheckConfigJSON([]byte(jsonContent)); err != nil {
		t.Fatalf("CheckConfigJSON error: %v", err)
	}

	var values runtimeValues = defaultRuntimeValues()
	if err := applyConfigJSONToValues([]byte(jsonContent), nil, &values); err != nil {
		t.Fatalf("applyConfigJSONToValues error: %v", err)
	}

	if values.EnableECH != true {
		t.Fatalf("values.EnableECH = %v, want true", values.EnableECH)
	}
	if values.ECHDomain != "custom-ech.example.com" {
		t.Fatalf("values.ECHDomain = %q, want custom-ech.example.com", values.ECHDomain)
	}
	if values.CipherPref != "2,1" {
		t.Fatalf("values.CipherPref = %q, want 2,1", values.CipherPref)
	}
	if values.PacingRateMbps != 10.5 {
		t.Fatalf("values.PacingRateMbps = %v, want 10.5", values.PacingRateMbps)
	}
	if values.ShapingCoalesceMs != 20 {
		t.Fatalf("values.ShapingCoalesceMs = %v, want 20", values.ShapingCoalesceMs)
	}
}

func TestLoadConfigFileRejectsDuplicateP2Aliases(t *testing.T) {
	duplicates := []struct {
		name string
		json string
	}{
		{
			name: "duplicate ech-domain",
			json: `{"listen":"socks5://127.0.0.1:1080","forward":"ws://127.0.0.1:8080","ech_domain":"a.com","ech-domain":"b.com"}`,
		},
		{
			name: "duplicate cipher-pref",
			json: `{"listen":"socks5://127.0.0.1:1080","forward":"ws://127.0.0.1:8080","cipher_pref":"1,2","cipher-pref":"2,1"}`,
		},
		{
			name: "duplicate pacing-rate-mbps",
			json: `{"listen":"socks5://127.0.0.1:1080","forward":"ws://127.0.0.1:8080","pacing_rate_mbps":10,"pacing-rate-mbps":20}`,
		},
		{
			name: "duplicate shaping-coalesce-ms",
			json: `{"listen":"socks5://127.0.0.1:1080","forward":"ws://127.0.0.1:8080","shaping_coalesce_ms":10,"shaping-coalesce-ms":20}`,
		},
	}
	for _, tt := range duplicates {
		t.Run(tt.name, func(t *testing.T) {
			var values runtimeValues = defaultRuntimeValues()
			if err := applyConfigJSONToValues([]byte(tt.json), nil, &values); err == nil {
				t.Fatalf("applyConfigJSONToValues accepted duplicate alias in %s", tt.name)
			}
		})
	}
}
