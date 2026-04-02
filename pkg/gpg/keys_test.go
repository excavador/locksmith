package gpg

import (
	"os"
	"testing"
	"time"
)

func TestParseColonsOutput(t *testing.T) {
	data, err := os.ReadFile("../../testdata/list-keys-colons.txt")
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}

	keys, err := parseColonsOutput(string(data))
	if err != nil {
		t.Fatalf("parseColonsOutput() error: %v", err)
	}

	if len(keys) != 4 {
		t.Fatalf("expected 4 keys, got %d", len(keys))
	}

	// Primary key
	master := keys[0]
	if master.KeyID != "6E1FD854CD2D225D" {
		t.Errorf("master KeyID = %q, want %q", master.KeyID, "6E1FD854CD2D225D")
	}
	if master.Fingerprint != "6E1FD854CD2D225DDAED8EB7822B3952F976544E" {
		t.Errorf("master Fingerprint = %q, want %q", master.Fingerprint, "6E1FD854CD2D225DDAED8EB7822B3952F976544E")
	}
	if master.Algorithm != "rsa" {
		t.Errorf("master Algorithm = %q, want %q", master.Algorithm, "rsa")
	}
	if master.Usage != "SC" {
		t.Errorf("master Usage = %q, want %q", master.Usage, "SC")
	}

	wantCreated := time.Date(2023, 12, 31, 0, 0, 0, 0, time.UTC)
	if !master.Created.Equal(wantCreated) {
		t.Errorf("master Created = %v, want %v", master.Created, wantCreated)
	}

	// Sign subkey
	signKey := keys[1]
	if signKey.KeyID != "886F425C412784FD" {
		t.Errorf("sign subkey KeyID = %q, want %q", signKey.KeyID, "886F425C412784FD")
	}
	if signKey.Usage != "s" {
		t.Errorf("sign subkey Usage = %q, want %q", signKey.Usage, "s")
	}
	if signKey.Fingerprint != "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555" {
		t.Errorf("sign subkey Fingerprint = %q, want %q", signKey.Fingerprint, "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555")
	}

	// Encrypt subkey
	encKey := keys[2]
	if encKey.KeyID != "79584112B688AB89" {
		t.Errorf("encrypt subkey KeyID = %q, want %q", encKey.KeyID, "79584112B688AB89")
	}
	if encKey.Usage != "e" {
		t.Errorf("encrypt subkey Usage = %q, want %q", encKey.Usage, "e")
	}

	// Auth subkey
	authKey := keys[3]
	if authKey.KeyID != "571151F0CB6B35FF" {
		t.Errorf("auth subkey KeyID = %q, want %q", authKey.KeyID, "571151F0CB6B35FF")
	}
	if authKey.Usage != "a" {
		t.Errorf("auth subkey Usage = %q, want %q", authKey.Usage, "a")
	}
}

func TestParseColonsOutputEmpty(t *testing.T) {
	keys, err := parseColonsOutput("")
	if err != nil {
		t.Fatalf("parseColonsOutput() error: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("expected 0 keys, got %d", len(keys))
	}
}

func TestParseColonsOutputSecretKeys(t *testing.T) {
	// sec/ssb records use the same format as pub/sub
	input := `sec:u:4096:1:6E1FD854CD2D225D:1703980800:1767139200::u:::scESC::::::23::0:
fpr:::::::::6E1FD854CD2D225DDAED8EB7822B3952F976544E:
ssb:u:4096:1:886F425C412784FD:1703980800:1767139200:::::s::::::23:
fpr:::::::::AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555:
`
	keys, err := parseColonsOutput(input)
	if err != nil {
		t.Fatalf("parseColonsOutput() error: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}
	if keys[0].KeyID != "6E1FD854CD2D225D" {
		t.Errorf("sec key ID = %q, want %q", keys[0].KeyID, "6E1FD854CD2D225D")
	}
	if keys[1].KeyID != "886F425C412784FD" {
		t.Errorf("ssb key ID = %q, want %q", keys[1].KeyID, "886F425C412784FD")
	}
}

func TestParseCardStatus(t *testing.T) {
	data, err := os.ReadFile("../../testdata/card-status-colons.txt")
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}

	info, err := parseCardStatus(string(data))
	if err != nil {
		t.Fatalf("parseCardStatus() error: %v", err)
	}

	if info.Serial != "12345678" {
		t.Errorf("Serial = %q, want %q", info.Serial, "12345678")
	}
	if info.Model != "YubiKey 5 NFC" {
		t.Errorf("Model = %q, want %q", info.Model, "YubiKey 5 NFC")
	}
	if len(info.KeyIDs) != 3 {
		t.Fatalf("expected 3 key IDs, got %d: %v", len(info.KeyIDs), info.KeyIDs)
	}
}

func TestExtractModelFromReader(t *testing.T) {
	tests := []struct {
		reader string
		want   string
	}{
		{"Yubico YubiKey OTP FIDO CCID 00 00", "Yubico YubiKey"},
		{"Yubico YubiKey OTP CCID 00 00", "Yubico YubiKey"},
		{"Yubico YubiKey FIDO CCID 00", "Yubico YubiKey"},
		{"Yubico YubiKey", "Yubico YubiKey"},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.reader, func(t *testing.T) {
			got := extractModelFromReader(tt.reader)
			if got != tt.want {
				t.Errorf("extractModelFromReader(%q) = %q, want %q", tt.reader, got, tt.want)
			}
		})
	}
}

func TestParseCardStatusReaderFallback(t *testing.T) {
	// Card status without cardtype but with Reader.
	input := `Reader:Yubico YubiKey OTP FIDO CCID 00 00
serial:99887766
fpr:AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555:FFFF6666AAAA7777BBBB8888CCCC9999DDDD0000:1111222233334444555566667777888899990000
`
	info, err := parseCardStatus(input)
	if err != nil {
		t.Fatalf("parseCardStatus() error: %v", err)
	}
	if info.Model != "Yubico YubiKey" {
		t.Errorf("Model = %q, want %q", info.Model, "Yubico YubiKey")
	}
	if info.Serial != "99887766" {
		t.Errorf("Serial = %q, want %q", info.Serial, "99887766")
	}
}

func TestParseCardStatusNoCard(t *testing.T) {
	_, err := parseCardStatus("")
	if err == nil {
		t.Fatal("parseCardStatus() should fail with empty input")
	}
}

func TestAlgoName(t *testing.T) {
	tests := []struct {
		num  string
		want string
	}{
		{"1", "rsa"},
		{"17", "dsa"},
		{"22", "ed25519"},
		{"99", "algo-99"},
	}
	for _, tt := range tests {
		got := algoName(tt.num)
		if got != tt.want {
			t.Errorf("algoName(%q) = %q, want %q", tt.num, got, tt.want)
		}
	}
}

func TestParseEpoch(t *testing.T) {
	got := parseEpoch("1703980800")
	want := time.Date(2023, 12, 31, 0, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("parseEpoch(\"1703980800\") = %v, want %v", got, want)
	}

	zero := parseEpoch("invalid")
	if !zero.IsZero() {
		t.Errorf("parseEpoch(\"invalid\") should be zero, got %v", zero)
	}
}

func TestParseColonsOutputExpiredKeys(t *testing.T) {
	data, err := os.ReadFile("../../testdata/list-keys-expired.txt")
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}

	keys, err := parseColonsOutput(string(data))
	if err != nil {
		t.Fatalf("parseColonsOutput() error: %v", err)
	}

	// Should parse 3 keys: 1 master + 2 subkeys (one expired, one valid).
	if len(keys) != 3 {
		t.Fatalf("expected 3 keys, got %d", len(keys))
	}

	// Expired subkey should have expiry in the past.
	expired := keys[1]
	if expired.KeyID != "886F425C412784FD" {
		t.Errorf("expired key ID = %q, want %q", expired.KeyID, "886F425C412784FD")
	}
	if expired.Expires.IsZero() {
		t.Error("expired key should have an expiry date")
	}
	// Created 2023-01-01, expired 2023-12-31.
	wantExpiry := time.Date(2023, 12, 31, 0, 0, 0, 0, time.UTC)
	if !expired.Expires.Equal(wantExpiry) {
		t.Errorf("expired key Expires = %v, want %v", expired.Expires, wantExpiry)
	}
}

func TestParseColonsOutputRevokedKeys(t *testing.T) {
	data, err := os.ReadFile("../../testdata/list-keys-revoked.txt")
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}

	keys, err := parseColonsOutput(string(data))
	if err != nil {
		t.Fatalf("parseColonsOutput() error: %v", err)
	}

	// Should parse 3 keys: 1 master + 2 subkeys (one revoked).
	if len(keys) != 3 {
		t.Fatalf("expected 3 keys, got %d", len(keys))
	}

	// The revoked subkey still parses -- validity is just a field, not filtered.
	revoked := keys[1]
	if revoked.KeyID != "886F425C412784FD" {
		t.Errorf("revoked key ID = %q, want %q", revoked.KeyID, "886F425C412784FD")
	}
}

func TestParseColonsOutputMultipleUIDs(t *testing.T) {
	data, err := os.ReadFile("../../testdata/list-keys-multiuid.txt")
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}

	keys, err := parseColonsOutput(string(data))
	if err != nil {
		t.Fatalf("parseColonsOutput() error: %v", err)
	}

	// uid records are skipped; should parse 1 master + 1 subkey.
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}
	if keys[0].Fingerprint != "6E1FD854CD2D225DDAED8EB7822B3952F976544E" {
		t.Errorf("master fp = %q", keys[0].Fingerprint)
	}
}

func TestParseColonsOutputKeysOnCard(t *testing.T) {
	data, err := os.ReadFile("../../testdata/list-keys-oncard.txt")
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}

	keys, err := parseColonsOutput(string(data))
	if err != nil {
		t.Fatalf("parseColonsOutput() error: %v", err)
	}

	// 1 master + 2 subkeys on card.
	if len(keys) != 3 {
		t.Fatalf("expected 3 keys, got %d", len(keys))
	}

	// Card serial should be populated for subkeys.
	if keys[1].CardSerial != "12345678" {
		t.Errorf("sign subkey CardSerial = %q, want %q", keys[1].CardSerial, "12345678")
	}
	if keys[2].CardSerial != "12345678" {
		t.Errorf("encrypt subkey CardSerial = %q, want %q", keys[2].CardSerial, "12345678")
	}
}

func TestParseColonsOutputShortFields(t *testing.T) {
	// Lines with fewer than 12 fields should be skipped.
	input := "pub:u:4096:1:AABBCCDD\nsub:short\n"
	keys, err := parseColonsOutput(input)
	if err != nil {
		t.Fatalf("parseColonsOutput() error: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("expected 0 keys from short fields, got %d", len(keys))
	}
}

func TestValidateFingerprint(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
	}{
		{"6E1FD854CD2D225DDAED8EB7822B3952F976544E", false},
		{"aaaa1111bbbb2222cccc3333dddd4444eeee5555", false},
		{"", true},
		{"too-short", true},
		{"6E1FD854CD2D225DDAED8EB7822B3952F976544G", true}, // G not hex
		{"6E1FD854CD2D225DDAED8EB7822B3952F976544", true},  // 39 chars
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			err := ValidateFingerprint(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateFingerprint(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidateKeyID(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
	}{
		{"886F425C412784FD", false},
		{"aabbccdd11223344", false},
		{"", true},
		{"short", true},
		{"886F425C412784F", true},   // 15 chars
		{"886F425C412784FDX", true}, // 17 chars
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			err := ValidateKeyID(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateKeyID(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidateSerial(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
	}{
		{"12345678", false},
		{"0", false},
		{"", true},
		{"abc", true},
		{"123-456", true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			err := ValidateSerial(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateSerial(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		input  string
		maxLen int
		want   string
	}{
		{"hello", 10, "hello"},
		{"hello world", 5, "hello..."},
		{"", 5, ""},
		{"  padded  ", 10, "padded"},
	}
	for _, tt := range tests {
		got := truncate(tt.input, tt.maxLen)
		if got != tt.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.want)
		}
	}
}

func TestSlotForIndex(t *testing.T) {
	c := &Client{}
	tests := []struct {
		idx  int
		want int
	}{
		{1, 1},
		{2, 2},
		{3, 3},
		{0, 1},  // out of range, defaults to 1
		{4, 1},  // out of range
		{-1, 1}, // negative
	}
	for _, tt := range tests {
		got := c.slotForIndex(tt.idx)
		if got != tt.want {
			t.Errorf("slotForIndex(%d) = %d, want %d", tt.idx, got, tt.want)
		}
	}
}

func TestUsageLabel(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"s", "sign"},
		{"e", "encrypt"},
		{"a", "auth"},
		{"S", "sign"},
		{"E", "encrypt"},
		{"A", "auth"},
		{"C", "C"},
		{"SC", "SC"},
		{"unknown", "unknown"},
		{"", ""},
	}
	for _, tt := range tests {
		got := UsageLabel(tt.input)
		if got != tt.want {
			t.Errorf("UsageLabel(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestParseUsage(t *testing.T) {
	tests := []struct {
		recType string
		caps    string
		want    string
	}{
		{"pub", "scESC", "SC"},
		{"sec", "scESC", "SC"},
		{"pub", "cESCA", "C"},
		{"pub", "eESC", "E"},
		{"sub", "s", "s"},
		{"sub", "e", "e"},
		{"ssb", "a", "a"},
		{"pub", "", ""},
		{"sub", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.recType+"_"+tt.caps, func(t *testing.T) {
			got := parseUsage(tt.recType, tt.caps)
			if got != tt.want {
				t.Errorf("parseUsage(%q, %q) = %q, want %q", tt.recType, tt.caps, got, tt.want)
			}
		})
	}
}

func TestNewClientRequiresHomeDir(t *testing.T) {
	_, err := New(Options{})
	if err == nil {
		t.Fatal("New() should fail without HomeDir")
	}
}

func TestNewClientDefaults(t *testing.T) {
	dir := t.TempDir()
	client, err := New(Options{HomeDir: dir})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if client.binary != "gpg" {
		t.Errorf("binary = %q, want %q", client.binary, "gpg")
	}
	if client.homeDir != dir {
		t.Errorf("homeDir = %q, want %q", client.homeDir, dir)
	}
}
