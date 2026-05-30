package age

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/getsops/sops/v3/age/keypb"
	"github.com/trendvidia/protowire-go/encoding/pxf"
)

// writePXFKeyFile encodes the given AgeKeyFile and writes it to a
// `keys.pxf` file inside a fresh temp directory; returns the full path.
func writePXFKeyFile(t *testing.T, file *keypb.AgeKeyFile) string {
	t.Helper()
	data, err := pxf.Marshal(file)
	if err != nil {
		t.Fatalf("marshal age key file: %v", err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "keys.pxf")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write age key file: %v", err)
	}
	return path
}

func TestLoadPXFIdentities_LoadsAllKeys(t *testing.T) {
	path := writePXFKeyFile(t, &keypb.AgeKeyFile{
		Default: "primary",
		Keys: map[string]string{
			"primary":   mockIdentity,
			"secondary": mockOtherIdentity,
		},
	})

	ids, err := loadPXFIdentities(path)
	if err != nil {
		t.Fatalf("loadPXFIdentities: %v", err)
	}
	if got, want := len(ids), 2; got != want {
		t.Fatalf("identities count: got %d, want %d", got, want)
	}
}

func TestLoadPXFIdentities_BadSecret(t *testing.T) {
	path := writePXFKeyFile(t, &keypb.AgeKeyFile{
		Keys: map[string]string{
			"bogus": "not-an-age-key",
		},
	})

	_, err := loadPXFIdentities(path)
	if err == nil {
		t.Fatal("loadPXFIdentities with bad secret: want error, got nil")
	}
}

func TestLoadPXFIdentities_MalformedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keys.pxf")
	if err := os.WriteFile(path, []byte("this is not pxf"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	_, err := loadPXFIdentities(path)
	if err == nil {
		t.Fatal("loadPXFIdentities of malformed file: want error, got nil")
	}
}

func TestDefaultRecipientFromKeyFile_Set(t *testing.T) {
	path := writePXFKeyFile(t, &keypb.AgeKeyFile{
		Default: "primary",
		Keys: map[string]string{
			"primary":   mockIdentity,
			"secondary": mockOtherIdentity,
		},
	})
	t.Setenv(SopsAgeKeyFileEnv, path)

	got, err := DefaultRecipientFromKeyFile()
	if err != nil {
		t.Fatalf("DefaultRecipientFromKeyFile: %v", err)
	}
	if got != mockRecipient {
		t.Errorf("default recipient: got %q, want %q", got, mockRecipient)
	}
}

func TestDefaultRecipientFromKeyFile_NoDefault(t *testing.T) {
	path := writePXFKeyFile(t, &keypb.AgeKeyFile{
		Keys: map[string]string{
			"only-one": mockIdentity,
		},
	})
	t.Setenv(SopsAgeKeyFileEnv, path)

	got, err := DefaultRecipientFromKeyFile()
	if err != nil {
		t.Fatalf("DefaultRecipientFromKeyFile: %v", err)
	}
	if got != "" {
		t.Errorf("expected empty recipient when no default set, got %q", got)
	}
}

func TestDefaultRecipientFromKeyFile_NotPXFExtension(t *testing.T) {
	// A path that doesn't end in .pxf must take the legacy line-based
	// parse path; DefaultRecipientFromKeyFile must short-circuit to "".
	dir := t.TempDir()
	path := filepath.Join(dir, "keys.txt")
	if err := os.WriteFile(path, []byte(mockIdentity+"\n"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	t.Setenv(SopsAgeKeyFileEnv, path)

	got, err := DefaultRecipientFromKeyFile()
	if err != nil {
		t.Fatalf("DefaultRecipientFromKeyFile: %v", err)
	}
	if got != "" {
		t.Errorf("expected empty recipient for non-pxf extension, got %q", got)
	}
}

func TestDefaultRecipientFromKeyFile_EnvUnset(t *testing.T) {
	// Make sure no inherited value bleeds into the test.
	os.Unsetenv(SopsAgeKeyFileEnv)

	got, err := DefaultRecipientFromKeyFile()
	if err != nil {
		t.Fatalf("DefaultRecipientFromKeyFile: %v", err)
	}
	if got != "" {
		t.Errorf("expected empty recipient when env unset, got %q", got)
	}
}

func TestDefaultRecipientFromKeyFile_DefaultMissingFromKeys(t *testing.T) {
	path := writePXFKeyFile(t, &keypb.AgeKeyFile{
		Default: "ghost",
		Keys: map[string]string{
			"primary": mockIdentity,
		},
	})
	t.Setenv(SopsAgeKeyFileEnv, path)

	_, err := DefaultRecipientFromKeyFile()
	if err == nil {
		t.Fatal("DefaultRecipientFromKeyFile with missing default: want error, got nil")
	}
	if !strings.Contains(err.Error(), "ghost") {
		t.Errorf("error should mention the missing name; got: %v", err)
	}
}

func TestDefaultRecipientFromKeyFile_Hybrid(t *testing.T) {
	// Refactoring through keypb.RecipientForName gave hybrid support
	// for free. Verify by setting a hybrid identity as the default.
	hybridID, err := age.ParseHybridIdentity(mockHybridIdentity)
	if err != nil {
		t.Fatalf("parse hybrid identity fixture: %v", err)
	}
	want := hybridID.Recipient().String()

	path := writePXFKeyFile(t, &keypb.AgeKeyFile{
		Default: "pq",
		Keys: map[string]string{
			"pq": mockHybridIdentity,
		},
	})
	t.Setenv(SopsAgeKeyFileEnv, path)

	got, err := DefaultRecipientFromKeyFile()
	if err != nil {
		t.Fatalf("DefaultRecipientFromKeyFile: %v", err)
	}
	if got != want {
		t.Errorf("hybrid default recipient: got %q, want %q", got, want)
	}
}

func TestRecipientFromKeyFileByName_Success(t *testing.T) {
	path := writePXFKeyFile(t, &keypb.AgeKeyFile{
		Default: "primary",
		Keys: map[string]string{
			"primary":   mockIdentity,
			"secondary": mockOtherIdentity,
		},
	})
	t.Setenv(SopsAgeKeyFileEnv, path)

	got, err := RecipientFromKeyFileByName("secondary")
	if err != nil {
		t.Fatalf("RecipientFromKeyFileByName: %v", err)
	}
	// `secondary` is mockOtherIdentity; derive its expected recipient
	// at runtime to avoid hard-coding a mirror constant.
	id, err := age.ParseX25519Identity(mockOtherIdentity)
	if err != nil {
		t.Fatalf("parse mockOtherIdentity: %v", err)
	}
	if got != id.Recipient().String() {
		t.Errorf("recipient: got %q, want %q", got, id.Recipient().String())
	}
}

func TestRecipientFromKeyFileByName_NameNotInKeys(t *testing.T) {
	path := writePXFKeyFile(t, &keypb.AgeKeyFile{
		Keys: map[string]string{
			"primary": mockIdentity,
		},
	})
	t.Setenv(SopsAgeKeyFileEnv, path)

	_, err := RecipientFromKeyFileByName("ghost")
	if err == nil {
		t.Fatal("RecipientFromKeyFileByName missing name: want error, got nil")
	}
	if !strings.Contains(err.Error(), "ghost") {
		t.Errorf("error should mention the missing name; got: %v", err)
	}
}

func TestRecipientFromKeyFileByName_EnvUnset(t *testing.T) {
	os.Unsetenv(SopsAgeKeyFileEnv)

	_, err := RecipientFromKeyFileByName("anything")
	if err == nil {
		t.Fatal("RecipientFromKeyFileByName with env unset: want error, got nil")
	}
	if !strings.Contains(err.Error(), SopsAgeKeyFileEnv) {
		t.Errorf("error should mention %s; got: %v", SopsAgeKeyFileEnv, err)
	}
}

func TestRecipientFromKeyFileByName_NoPXFSource(t *testing.T) {
	// SOPS_AGE_KEY_FILE doesn't end in .pxf, and neither SOPS_AGE_KEY
	// nor SOPS_AGE_KEY_CMD is set to PXF content. --age-key-name has
	// nothing to resolve against.
	dir := t.TempDir()
	path := filepath.Join(dir, "keys.txt")
	if err := os.WriteFile(path, []byte(mockIdentity+"\n"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	t.Setenv(SopsAgeKeyFileEnv, path)
	os.Unsetenv(SopsAgeKeyEnv)
	os.Unsetenv(SopsAgeKeyCmdEnv)

	_, err := RecipientFromKeyFileByName("anything")
	if err == nil {
		t.Fatal("RecipientFromKeyFileByName without PXF source: want error, got nil")
	}
	if !strings.Contains(err.Error(), "PXF") {
		t.Errorf("error should mention PXF; got: %v", err)
	}
}

// pxfBytes encodes an AgeKeyFile to its PXF wire form for use as
// SOPS_AGE_KEY content or as SOPS_AGE_KEY_CMD stdout.
func pxfBytes(t *testing.T, file *keypb.AgeKeyFile) []byte {
	t.Helper()
	b, err := pxf.Marshal(file)
	if err != nil {
		t.Fatalf("marshal age key file: %v", err)
	}
	return b
}

func TestIsPXFContent(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"empty", "", false},
		{"only blank and comments", "\n\n# hi\n\n", false},
		{"legacy single key", mockIdentity + "\n", false},
		{"legacy with comments", "# created\n# pubkey\n" + mockIdentity + "\n", false},
		{"armored age", "-----BEGIN AGE ENCRYPTED FILE-----\n...\n", false},
		{"raw age-encryption header", "age-encryption.org/v1\n...\n", false},
		{"garbage single token", "invalid\n", false},
		{"pxf with default", "default = \"prod\"\nkeys = { prod: \"AGE-SECRET-KEY-1XYZ\" }\n", true},
		{"pxf no whitespace", "default=\"prod\"\n", true},
		{"pxf brace form", "keys {\n  prod: \"x\"\n}\n", true},
		{"pxf after comments", "# header\n\ndefault = \"prod\"\n", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isPXFContent([]byte(tc.in)); got != tc.want {
				t.Errorf("isPXFContent(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestLoadIdentities_PXFInSopsAgeKeyEnv(t *testing.T) {
	os.Unsetenv(SopsAgeKeyFileEnv)
	os.Unsetenv(SopsAgeKeyCmdEnv)
	t.Setenv(SopsAgeKeyEnv, string(pxfBytes(t, &keypb.AgeKeyFile{
		Default: "primary",
		Keys: map[string]string{
			"primary":   mockIdentity,
			"secondary": mockOtherIdentity,
		},
	})))

	key := &MasterKey{Recipient: mockRecipient}
	ids, _, errs := key.loadIdentities()
	if len(errs) > 0 {
		t.Fatalf("loadIdentities errs: %v", errs)
	}
	if got, want := len(ids), 2; got < want {
		t.Errorf("identity count: got %d, want >= %d", got, want)
	}
}

func TestLoadIdentities_PXFInSopsAgeKeyCmdEnv(t *testing.T) {
	os.Unsetenv(SopsAgeKeyFileEnv)
	os.Unsetenv(SopsAgeKeyEnv)

	// Stash the PXF content in a temp file and have the command cat it.
	dir := t.TempDir()
	pxfFile := filepath.Join(dir, "keys.pxf")
	if err := os.WriteFile(pxfFile, pxfBytes(t, &keypb.AgeKeyFile{
		Default: "primary",
		Keys:    map[string]string{"primary": mockIdentity},
	}), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	t.Setenv(SopsAgeKeyCmdEnv, "cat "+pxfFile)

	key := &MasterKey{Recipient: mockRecipient}
	ids, _, errs := key.loadIdentities()
	if len(errs) > 0 {
		t.Fatalf("loadIdentities errs: %v", errs)
	}
	if len(ids) < 1 {
		t.Fatal("expected at least one identity from SOPS_AGE_KEY_CMD PXF output")
	}
}

func TestLoadIdentities_PXFMalformedInSopsAgeKey(t *testing.T) {
	os.Unsetenv(SopsAgeKeyFileEnv)
	os.Unsetenv(SopsAgeKeyCmdEnv)
	// Looks like PXF (positive probe match) but the value is broken
	// — surfaces a PXF parse error, not the legacy one.
	t.Setenv(SopsAgeKeyEnv, "default = \n")

	key := &MasterKey{Recipient: mockRecipient}
	_, _, errs := key.loadIdentities()
	if len(errs) == 0 {
		t.Fatal("expected loadIdentities to report a parse error for malformed PXF")
	}
	found := false
	for _, e := range errs {
		if strings.Contains(e.Error(), "parse age key file") && strings.Contains(e.Error(), SopsAgeKeyEnv) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected PXF parse error mentioning %s, got: %v", SopsAgeKeyEnv, errs)
	}
}

func TestDefaultRecipientFromKeyFile_FromSopsAgeKeyEnv(t *testing.T) {
	os.Unsetenv(SopsAgeKeyFileEnv)
	os.Unsetenv(SopsAgeKeyCmdEnv)
	t.Setenv(SopsAgeKeyEnv, string(pxfBytes(t, &keypb.AgeKeyFile{
		Default: "primary",
		Keys:    map[string]string{"primary": mockIdentity},
	})))

	got, err := DefaultRecipientFromKeyFile()
	if err != nil {
		t.Fatalf("DefaultRecipientFromKeyFile: %v", err)
	}
	if got != mockRecipient {
		t.Errorf("default recipient via SOPS_AGE_KEY: got %q, want %q", got, mockRecipient)
	}
}

func TestDefaultRecipientFromKeyFile_FromSopsAgeKeyCmdEnv(t *testing.T) {
	os.Unsetenv(SopsAgeKeyFileEnv)
	os.Unsetenv(SopsAgeKeyEnv)

	dir := t.TempDir()
	pxfFile := filepath.Join(dir, "keys.pxf")
	if err := os.WriteFile(pxfFile, pxfBytes(t, &keypb.AgeKeyFile{
		Default: "primary",
		Keys:    map[string]string{"primary": mockIdentity},
	}), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	t.Setenv(SopsAgeKeyCmdEnv, "cat "+pxfFile)

	got, err := DefaultRecipientFromKeyFile()
	if err != nil {
		t.Fatalf("DefaultRecipientFromKeyFile: %v", err)
	}
	if got != mockRecipient {
		t.Errorf("default recipient via SOPS_AGE_KEY_CMD: got %q, want %q", got, mockRecipient)
	}
}

func TestDefaultRecipientFromKeyFile_FilePrecedenceOverEnv(t *testing.T) {
	// File source must win when both supply a default.
	filePath := writePXFKeyFile(t, &keypb.AgeKeyFile{
		Default: "primary",
		Keys:    map[string]string{"primary": mockIdentity},
	})
	t.Setenv(SopsAgeKeyFileEnv, filePath)
	t.Setenv(SopsAgeKeyEnv, string(pxfBytes(t, &keypb.AgeKeyFile{
		Default: "other",
		Keys:    map[string]string{"other": mockOtherIdentity},
	})))
	os.Unsetenv(SopsAgeKeyCmdEnv)

	got, err := DefaultRecipientFromKeyFile()
	if err != nil {
		t.Fatalf("DefaultRecipientFromKeyFile: %v", err)
	}
	if got != mockRecipient {
		t.Errorf("expected file source to win; got recipient %q (env value would be different)", got)
	}
}

func TestRecipientFromKeyFileByName_FromSopsAgeKeyEnv(t *testing.T) {
	os.Unsetenv(SopsAgeKeyFileEnv)
	os.Unsetenv(SopsAgeKeyCmdEnv)
	t.Setenv(SopsAgeKeyEnv, string(pxfBytes(t, &keypb.AgeKeyFile{
		Keys: map[string]string{
			"primary":   mockIdentity,
			"secondary": mockOtherIdentity,
		},
	})))

	got, err := RecipientFromKeyFileByName("secondary")
	if err != nil {
		t.Fatalf("RecipientFromKeyFileByName: %v", err)
	}
	id, err := age.ParseX25519Identity(mockOtherIdentity)
	if err != nil {
		t.Fatalf("parse mockOtherIdentity: %v", err)
	}
	if got != id.Recipient().String() {
		t.Errorf("recipient: got %q, want %q", got, id.Recipient().String())
	}
}
