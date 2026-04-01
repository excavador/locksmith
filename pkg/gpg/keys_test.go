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
	if master.Usage != "scESC" {
		t.Errorf("master Usage = %q, want %q", master.Usage, "scESC")
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
