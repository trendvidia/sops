package keypb

import (
	"strings"
	"testing"

	"filippo.io/age"
)

const (
	// Real fixtures so the X25519 / hybrid derivations actually run.
	// mockX25519Identity / mockX25519Recipient correspond to the same
	// pair used in age/keysource_test.go.
	mockX25519Identity  = "AGE-SECRET-KEY-1G0Q5K9TV4REQ3ZSQRMTMG8NSWQGYT0T7TZ33RAZEE0GZYVZN0APSU24RK7"
	mockX25519Recipient = "age1lzd99uklcjnc0e7d860axevet2cz99ce9pq6tzuzd05l5nr28ams36nvun"
	mockOtherIdentity   = "AGE-SECRET-KEY-1432K5YRNSC44GC4986NXMX6GVZ52WTMT9C79CLUVWYY4DKDHD5JSNDP4MC"
	mockHybridIdentity  = "AGE-SECRET-KEY-PQ-1JPDDEMSK6G9MG0VNJRSA0QKZ05CF4H6TK50YZGDKZKTRGC5Z7KEQUDUPG6"
	// Plugin identities can't have their recipient derived without
	// invoking the plugin binary; they should be silently skipped.
	mockPluginIdentity = "AGE-PLUGIN-EXAMPLE-1FAKE0FAKE0FAKE0"
)

func deriveHybridRecipient(t *testing.T) string {
	t.Helper()
	id, err := age.ParseHybridIdentity(mockHybridIdentity)
	if err != nil {
		t.Fatalf("parse hybrid identity fixture: %v", err)
	}
	return id.Recipient().String()
}

func TestRecipients_HappyPath(t *testing.T) {
	k := &AgeKeyFile{
		Keys: map[string]string{
			"x":      mockX25519Identity,
			"hybrid": mockHybridIdentity,
		},
	}
	got, err := k.Recipients()
	if err != nil {
		t.Fatalf("Recipients: %v", err)
	}
	if got["x"] != mockX25519Recipient {
		t.Errorf("x recipient: got %q, want %q", got["x"], mockX25519Recipient)
	}
	if got["hybrid"] != deriveHybridRecipient(t) {
		t.Errorf("hybrid recipient: got %q, want hybrid recipient", got["hybrid"])
	}
}

func TestRecipients_PluginSkipped(t *testing.T) {
	k := &AgeKeyFile{
		Keys: map[string]string{
			"x":       mockX25519Identity,
			"yubikey": mockPluginIdentity,
		},
	}
	got, err := k.Recipients()
	if err != nil {
		t.Fatalf("Recipients: %v", err)
	}
	if _, ok := got["yubikey"]; ok {
		t.Errorf("plugin entry should be skipped, but appeared in result: %q", got["yubikey"])
	}
	if got["x"] != mockX25519Recipient {
		t.Errorf("x recipient: got %q, want %q", got["x"], mockX25519Recipient)
	}
}

func TestRecipients_MalformedSecret(t *testing.T) {
	k := &AgeKeyFile{
		Keys: map[string]string{
			"good": mockX25519Identity,
			"bad":  "AGE-SECRET-KEY-1-not-a-real-bech32",
		},
	}
	_, err := k.Recipients()
	if err == nil {
		t.Fatal("Recipients with malformed entry: want error, got nil")
	}
	if !strings.Contains(err.Error(), "bad") {
		t.Errorf("error should name the bad entry; got: %v", err)
	}
}

func TestRecipientForName_X25519(t *testing.T) {
	k := &AgeKeyFile{
		Keys: map[string]string{"primary": mockX25519Identity},
	}
	got, err := k.RecipientForName("primary")
	if err != nil {
		t.Fatalf("RecipientForName: %v", err)
	}
	if got != mockX25519Recipient {
		t.Errorf("got %q, want %q", got, mockX25519Recipient)
	}
}

func TestRecipientForName_Hybrid(t *testing.T) {
	k := &AgeKeyFile{
		Keys: map[string]string{"primary": mockHybridIdentity},
	}
	got, err := k.RecipientForName("primary")
	if err != nil {
		t.Fatalf("RecipientForName: %v", err)
	}
	want := deriveHybridRecipient(t)
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestRecipientForName_Missing(t *testing.T) {
	k := &AgeKeyFile{
		Keys: map[string]string{"primary": mockX25519Identity},
	}
	got, err := k.RecipientForName("ghost")
	if err != nil {
		t.Fatalf("RecipientForName: %v", err)
	}
	if got != "" {
		t.Errorf("expected empty for missing name, got %q", got)
	}
}

func TestRecipientForName_Plugin(t *testing.T) {
	k := &AgeKeyFile{
		Keys: map[string]string{"yubikey": mockPluginIdentity},
	}
	got, err := k.RecipientForName("yubikey")
	if err != nil {
		t.Fatalf("RecipientForName: %v", err)
	}
	if got != "" {
		t.Errorf("expected empty for plugin identity, got %q", got)
	}
}

func TestNameForRecipient_Match(t *testing.T) {
	k := &AgeKeyFile{
		Keys: map[string]string{
			"a": mockX25519Identity,
			"b": mockOtherIdentity,
		},
	}
	got, err := k.NameForRecipient(mockX25519Recipient)
	if err != nil {
		t.Fatalf("NameForRecipient: %v", err)
	}
	if got != "a" {
		t.Errorf("got %q, want %q", got, "a")
	}
}

func TestNameForRecipient_NoMatch(t *testing.T) {
	k := &AgeKeyFile{
		Keys: map[string]string{"a": mockX25519Identity},
	}
	got, err := k.NameForRecipient("age1zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzs2qd4hu")
	if err != nil {
		t.Fatalf("NameForRecipient: %v", err)
	}
	if got != "" {
		t.Errorf("expected empty for no-match, got %q", got)
	}
}
