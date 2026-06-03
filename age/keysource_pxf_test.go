package age

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/trendvidia/sops/v4/age/keypb"
	"github.com/trendvidia/protowire-go/encoding/pxf"
)

// writePXFKeyFile encodes the given AgeKeyFile and writes it to a
// `keys.pxf` file inside a fresh temp directory; returns the full path.
func writePXFKeyFile(t *testing.T, file *keypb.AgeKeyFile) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "keys.pxf")
	writePXFKeyFileAt(t, path, file)
	return path
}

// writePXFKeyFileAt encodes file and writes it to the given path,
// creating parent directories as needed (0o700 perms on dirs, 0o600
// on the file).
func writePXFKeyFileAt(t *testing.T, path string, file *keypb.AgeKeyFile) {
	t.Helper()
	data, err := pxf.Marshal(file)
	if err != nil {
		t.Fatalf("marshal age key file: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir parents of %q: %v", path, err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write age key file: %v", err)
	}
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
	overwriteUserHomeDir(t, t.TempDir())
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
	overwriteUserHomeDir(t, t.TempDir())
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
	overwriteUserHomeDir(t, t.TempDir())
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
	overwriteUserHomeDir(t, t.TempDir())
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
	overwriteUserHomeDir(t, t.TempDir())
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

func TestLoadIdentities_PXFMalformedInSopsAgeKeyCmd(t *testing.T) {
	overwriteUserHomeDir(t, t.TempDir())
	os.Unsetenv(SopsAgeKeyFileEnv)
	os.Unsetenv(SopsAgeKeyEnv)
	// Command stdout sniffs as PXF (starts with `default =`) but is
	// malformed — must surface a PXF parse error mentioning the
	// command env var, not silently fall through to the legacy parser.
	t.Setenv(SopsAgeKeyCmdEnv, `printf 'default = \n'`)

	key := &MasterKey{Recipient: mockRecipient}
	_, _, errs := key.loadIdentities()
	if len(errs) == 0 {
		t.Fatal("expected loadIdentities to report a parse error for malformed PXF from SOPS_AGE_KEY_CMD")
	}
	found := false
	for _, e := range errs {
		if strings.Contains(e.Error(), "parse age key file") && strings.Contains(e.Error(), SopsAgeKeyCmdEnv) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected PXF parse error mentioning %s, got: %v", SopsAgeKeyCmdEnv, errs)
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

func TestRecipientFromKeyFileByName_NameNotInKeys_FromSopsAgeKeyEnv(t *testing.T) {
	// Existing _NameNotInKeys covers the FILE source. Mirror it for
	// the SOPS_AGE_KEY env source: missing name must surface a "not
	// in keys" error that mentions the lookup name.
	overwriteUserHomeDir(t, t.TempDir())
	os.Unsetenv(SopsAgeKeyFileEnv)
	os.Unsetenv(SopsAgeKeyCmdEnv)
	t.Setenv(SopsAgeKeyEnv, string(pxfBytes(t, &keypb.AgeKeyFile{
		Keys: map[string]string{"primary": mockIdentity},
	})))

	_, err := RecipientFromKeyFileByName("ghost")
	if err == nil {
		t.Fatal("RecipientFromKeyFileByName missing name in SOPS_AGE_KEY: want error, got nil")
	}
	if !strings.Contains(err.Error(), "ghost") {
		t.Errorf("error should mention the missing name; got: %v", err)
	}
	if !strings.Contains(err.Error(), "not in keys") {
		t.Errorf("error should say %q; got: %v", "not in keys", err)
	}
}

func TestRecipientFromKeyFileByName_NameNotInKeys_FromSopsAgeKeyCmdEnv(t *testing.T) {
	// Same as above for the SOPS_AGE_KEY_CMD source.
	overwriteUserHomeDir(t, t.TempDir())
	os.Unsetenv(SopsAgeKeyFileEnv)
	os.Unsetenv(SopsAgeKeyEnv)

	dir := t.TempDir()
	pxfFile := filepath.Join(dir, "keys.pxf")
	if err := os.WriteFile(pxfFile, pxfBytes(t, &keypb.AgeKeyFile{
		Keys: map[string]string{"primary": mockIdentity},
	}), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	t.Setenv(SopsAgeKeyCmdEnv, "cat "+pxfFile)

	_, err := RecipientFromKeyFileByName("ghost")
	if err == nil {
		t.Fatal("RecipientFromKeyFileByName missing name in SOPS_AGE_KEY_CMD: want error, got nil")
	}
	if !strings.Contains(err.Error(), "ghost") {
		t.Errorf("error should mention the missing name; got: %v", err)
	}
	if !strings.Contains(err.Error(), "not in keys") {
		t.Errorf("error should say %q; got: %v", "not in keys", err)
	}
}

func TestRecipientFromKeyFileByName_FromSopsAgeKeyCmdEnv(t *testing.T) {
	overwriteUserHomeDir(t, t.TempDir())
	os.Unsetenv(SopsAgeKeyFileEnv)
	os.Unsetenv(SopsAgeKeyEnv)

	dir := t.TempDir()
	pxfFile := filepath.Join(dir, "keys.pxf")
	if err := os.WriteFile(pxfFile, pxfBytes(t, &keypb.AgeKeyFile{
		Keys: map[string]string{
			"primary":   mockIdentity,
			"secondary": mockOtherIdentity,
		},
	}), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	t.Setenv(SopsAgeKeyCmdEnv, "cat "+pxfFile)

	got, err := RecipientFromKeyFileByName("secondary")
	if err != nil {
		t.Fatalf("RecipientFromKeyFileByName: %v", err)
	}
	id, err := age.ParseX25519Identity(mockOtherIdentity)
	if err != nil {
		t.Fatalf("parse mockOtherIdentity: %v", err)
	}
	if got != id.Recipient().String() {
		t.Errorf("recipient via SOPS_AGE_KEY_CMD: got %q, want %q", got, id.Recipient().String())
	}
}

func TestLoadIdentities_DefaultPath(t *testing.T) {
	// New v4 behavior: $HOME/.config/sops/age/keys.pxf is the
	// standardized default consulted when none of the SOPS_AGE_KEY*
	// env vars resolve. PXF format only.
	tmp := t.TempDir()
	overwriteUserHomeDir(t, tmp)
	os.Unsetenv(SopsAgeKeyFileEnv)
	os.Unsetenv(SopsAgeKeyEnv)
	os.Unsetenv(SopsAgeKeyCmdEnv)

	defaultPath := filepath.Join(tmp, filepath.FromSlash(DefaultAgeKeyFilePath))
	writePXFKeyFileAt(t, defaultPath, &keypb.AgeKeyFile{
		Default: "primary",
		Keys:    map[string]string{"primary": mockIdentity},
	})

	ids, _, errs := (&MasterKey{}).loadIdentities()
	if len(errs) > 0 {
		t.Fatalf("loadIdentities errs: %v", errs)
	}
	if got, want := len(ids), 1; got != want {
		t.Fatalf("identity count: got %d, want %d", got, want)
	}
}

func TestLoadIdentities_LegacyKeysTxtAtDefaultPathNotImplicit(t *testing.T) {
	// v4 contract change: only keys.pxf at the default path is
	// implicit. A line-based keys.txt at the old XDG-style path is
	// silently ignored unless the operator points SOPS_AGE_KEY_FILE
	// at it.
	tmp := t.TempDir()
	overwriteUserHomeDir(t, tmp)
	os.Unsetenv(SopsAgeKeyFileEnv)
	os.Unsetenv(SopsAgeKeyEnv)
	os.Unsetenv(SopsAgeKeyCmdEnv)

	// Drop a line-based keys.txt where pre-v4 sops would have found it.
	legacyDir := filepath.Join(tmp, ".config", "sops", "age")
	if err := os.MkdirAll(legacyDir, 0o700); err != nil {
		t.Fatalf("mkdir legacy dir: %v", err)
	}
	legacyPath := filepath.Join(legacyDir, "keys.txt")
	if err := os.WriteFile(legacyPath, []byte(mockIdentity+"\n"), 0o600); err != nil {
		t.Fatalf("write legacy keys.txt: %v", err)
	}

	ids, _, errs := (&MasterKey{}).loadIdentities()
	if len(errs) > 0 {
		t.Fatalf("loadIdentities errs: %v", errs)
	}
	if got := len(ids); got != 0 {
		t.Errorf("legacy keys.txt at default dir should be ignored; loaded %d identity(ies)", got)
	}
}

func TestDefaultRecipientFromKeyFile_FromDefaultPath(t *testing.T) {
	// Encrypt-side symmetric coverage: no env source set, default
	// $HOME/.config/sops/age/keys.pxf supplies the Default entry.
	tmp := t.TempDir()
	overwriteUserHomeDir(t, tmp)
	os.Unsetenv(SopsAgeKeyFileEnv)
	os.Unsetenv(SopsAgeKeyEnv)
	os.Unsetenv(SopsAgeKeyCmdEnv)

	defaultPath := filepath.Join(tmp, filepath.FromSlash(DefaultAgeKeyFilePath))
	writePXFKeyFileAt(t, defaultPath, &keypb.AgeKeyFile{
		Default: "primary",
		Keys:    map[string]string{"primary": mockIdentity},
	})

	got, err := DefaultRecipientFromKeyFile()
	if err != nil {
		t.Fatalf("DefaultRecipientFromKeyFile: %v", err)
	}
	if got != mockRecipient {
		t.Errorf("recipient: got %q, want %q", got, mockRecipient)
	}
}

func TestRecipientFromKeyFileByName_Hybrid(t *testing.T) {
	// Named lookup of a hybrid (PQ) identity stored alongside X25519
	// identities in a multi-key PXF file must resolve to the hybrid's
	// recipient — verifies keypb.RecipientForName handles the hybrid
	// branch when an arbitrary name (not just the default) selects it.
	hybridID, err := age.ParseHybridIdentity(mockHybridIdentity)
	if err != nil {
		t.Fatalf("parse hybrid identity fixture: %v", err)
	}
	want := hybridID.Recipient().String()

	path := writePXFKeyFile(t, &keypb.AgeKeyFile{
		Keys: map[string]string{
			"primary": mockIdentity,
			"pq":      mockHybridIdentity,
		},
	})
	t.Setenv(SopsAgeKeyFileEnv, path)

	got, err := RecipientFromKeyFileByName("pq")
	if err != nil {
		t.Fatalf("RecipientFromKeyFileByName(pq): %v", err)
	}
	if got != want {
		t.Errorf("hybrid named recipient: got %q, want %q", got, want)
	}
}

func TestDefaultRecipientFromKeyFile_HybridFromSopsAgeKeyEnv(t *testing.T) {
	// Hybrid identity served via SOPS_AGE_KEY (in-memory PXF) must
	// resolve to its hybrid recipient. Covers the env-var branch of
	// the source chain — previously only the FILE path was tested for
	// hybrid identities.
	overwriteUserHomeDir(t, t.TempDir())
	os.Unsetenv(SopsAgeKeyFileEnv)
	os.Unsetenv(SopsAgeKeyCmdEnv)

	hybridID, err := age.ParseHybridIdentity(mockHybridIdentity)
	if err != nil {
		t.Fatalf("parse hybrid identity fixture: %v", err)
	}
	want := hybridID.Recipient().String()

	t.Setenv(SopsAgeKeyEnv, string(pxfBytes(t, &keypb.AgeKeyFile{
		Default: "pq",
		Keys:    map[string]string{"pq": mockHybridIdentity},
	})))

	got, err := DefaultRecipientFromKeyFile()
	if err != nil {
		t.Fatalf("DefaultRecipientFromKeyFile: %v", err)
	}
	if got != want {
		t.Errorf("hybrid default via SOPS_AGE_KEY: got %q, want %q", got, want)
	}
}

func TestDefaultRecipientFromKeyFile_HybridFromSopsAgeKeyCmdEnv(t *testing.T) {
	// Same as above, via SOPS_AGE_KEY_CMD's stdout — covers the cmd
	// branch of the source chain for hybrid identities.
	overwriteUserHomeDir(t, t.TempDir())
	os.Unsetenv(SopsAgeKeyFileEnv)
	os.Unsetenv(SopsAgeKeyEnv)

	hybridID, err := age.ParseHybridIdentity(mockHybridIdentity)
	if err != nil {
		t.Fatalf("parse hybrid identity fixture: %v", err)
	}
	want := hybridID.Recipient().String()

	dir := t.TempDir()
	pxfFile := filepath.Join(dir, "keys.pxf")
	if err := os.WriteFile(pxfFile, pxfBytes(t, &keypb.AgeKeyFile{
		Default: "pq",
		Keys:    map[string]string{"pq": mockHybridIdentity},
	}), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	t.Setenv(SopsAgeKeyCmdEnv, "cat "+pxfFile)

	got, err := DefaultRecipientFromKeyFile()
	if err != nil {
		t.Fatalf("DefaultRecipientFromKeyFile: %v", err)
	}
	if got != want {
		t.Errorf("hybrid default via SOPS_AGE_KEY_CMD: got %q, want %q", got, want)
	}
}

func TestDefaultRecipientFromKeyFile_MalformedFileSourceFailsLoud(t *testing.T) {
	// A malformed higher-priority source must fail loud — the chain
	// MUST NOT silently fall through to a lower-priority source.
	// Misconfiguration debugging depends on the error surfacing
	// instead of being masked by a valid SOPS_AGE_KEY.
	overwriteUserHomeDir(t, t.TempDir())
	os.Unsetenv(SopsAgeKeyCmdEnv)

	// FILE: .pxf path with garbage content — keypb.ReadFile will fail.
	dir := t.TempDir()
	badFile := filepath.Join(dir, "broken.pxf")
	if err := os.WriteFile(badFile, []byte("not pxf at all\n"), 0o600); err != nil {
		t.Fatalf("write broken file: %v", err)
	}
	t.Setenv(SopsAgeKeyFileEnv, badFile)

	// KEY env: valid PXF with a default that WOULD resolve if the
	// chain silently fell through to it.
	t.Setenv(SopsAgeKeyEnv, string(pxfBytes(t, &keypb.AgeKeyFile{
		Default: "fallback",
		Keys:    map[string]string{"fallback": mockIdentity},
	})))

	_, err := DefaultRecipientFromKeyFile()
	if err == nil {
		t.Fatal("expected DefaultRecipientFromKeyFile to fail loud on malformed FILE source, got nil")
	}
	if !strings.Contains(err.Error(), "parse age key file") {
		t.Errorf("error should mention parse failure on the FILE source; got: %v", err)
	}
}

func TestRecipientFromKeyFileByName_MalformedFileSourceFailsLoud(t *testing.T) {
	// Same loud-failure contract for the named-lookup entry point.
	overwriteUserHomeDir(t, t.TempDir())
	os.Unsetenv(SopsAgeKeyCmdEnv)

	dir := t.TempDir()
	badFile := filepath.Join(dir, "broken.pxf")
	if err := os.WriteFile(badFile, []byte("not pxf at all\n"), 0o600); err != nil {
		t.Fatalf("write broken file: %v", err)
	}
	t.Setenv(SopsAgeKeyFileEnv, badFile)

	// KEY env: valid PXF containing the requested name — must NOT be
	// reached because the FILE source's parse error preempts the walk.
	t.Setenv(SopsAgeKeyEnv, string(pxfBytes(t, &keypb.AgeKeyFile{
		Keys: map[string]string{"target": mockIdentity},
	})))

	_, err := RecipientFromKeyFileByName("target")
	if err == nil {
		t.Fatal("expected RecipientFromKeyFileByName to fail loud on malformed FILE source, got nil")
	}
	if !strings.Contains(err.Error(), "parse age key file") {
		t.Errorf("error should mention parse failure on the FILE source; got: %v", err)
	}
}

func TestDefaultRecipientFromKeyFile_CmdExitNonZero(t *testing.T) {
	// Encrypt-side chain only reaches the cmd source after FILE/KEY
	// fall through. When the cmd exits non-zero, the chain must error
	// loud (not swallow and fall through to default-path), so
	// misconfiguration surfaces immediately.
	overwriteUserHomeDir(t, t.TempDir())
	os.Unsetenv(SopsAgeKeyFileEnv)
	os.Unsetenv(SopsAgeKeyEnv)
	t.Setenv(SopsAgeKeyCmdEnv, "false")

	_, err := DefaultRecipientFromKeyFile()
	if err == nil {
		t.Fatal("expected DefaultRecipientFromKeyFile to error on cmd non-zero exit, got nil")
	}
	if !strings.Contains(err.Error(), "failed to execute command") {
		t.Errorf("error should mention command execution failure; got: %v", err)
	}
}

func TestDefaultRecipientFromKeyFile_CmdSpawnFails(t *testing.T) {
	// Spawn-time failure (command binary doesn't exist) must surface
	// as an error from the chain.
	overwriteUserHomeDir(t, t.TempDir())
	os.Unsetenv(SopsAgeKeyFileEnv)
	os.Unsetenv(SopsAgeKeyEnv)
	t.Setenv(SopsAgeKeyCmdEnv, "/nonexistent/sops-test-cmd-that-does-not-exist")

	_, err := DefaultRecipientFromKeyFile()
	if err == nil {
		t.Fatal("expected DefaultRecipientFromKeyFile to error on cmd spawn failure, got nil")
	}
	if !strings.Contains(err.Error(), "failed to execute command") {
		t.Errorf("error should mention command execution failure; got: %v", err)
	}
}

func TestDefaultRecipientFromKeyFile_CmdEmptyStdout(t *testing.T) {
	// Empty stdout doesn't sniff as PXF, so the source must fall
	// through cleanly to the default-path source. No error; if no
	// default-path file exists, returns "" with nil error per the
	// documented contract.
	tmp := t.TempDir()
	overwriteUserHomeDir(t, tmp)
	os.Unsetenv(SopsAgeKeyFileEnv)
	os.Unsetenv(SopsAgeKeyEnv)
	t.Setenv(SopsAgeKeyCmdEnv, "true")

	got, err := DefaultRecipientFromKeyFile()
	if err != nil {
		t.Fatalf("DefaultRecipientFromKeyFile with empty cmd stdout: want nil err, got %v", err)
	}
	if got != "" {
		t.Errorf("recipient: got %q, want %q (empty stdout should not resolve)", got, "")
	}
}

func TestDefaultRecipientFromKeyFile_CmdShlexFails(t *testing.T) {
	// Unbalanced quotes break shlex.Split before the command even runs;
	// the wrapped error mentions "failed to parse command".
	overwriteUserHomeDir(t, t.TempDir())
	os.Unsetenv(SopsAgeKeyFileEnv)
	os.Unsetenv(SopsAgeKeyEnv)
	t.Setenv(SopsAgeKeyCmdEnv, `echo "unclosed`)

	_, err := DefaultRecipientFromKeyFile()
	if err == nil {
		t.Fatal("expected DefaultRecipientFromKeyFile to error on shlex failure, got nil")
	}
	if !strings.Contains(err.Error(), "failed to parse command") {
		t.Errorf("error should mention command parse failure; got: %v", err)
	}
}

func TestLoadIdentities_CmdExitNonZero(t *testing.T) {
	// Decrypt-side: cmd non-zero exit must land in errs rather than
	// be silently swallowed. Other sources still get a chance to
	// resolve, but this source's failure is reported.
	overwriteUserHomeDir(t, t.TempDir())
	os.Unsetenv(SopsAgeKeyFileEnv)
	os.Unsetenv(SopsAgeKeyEnv)
	t.Setenv(SopsAgeKeyCmdEnv, "false")

	key := &MasterKey{Recipient: mockRecipient}
	_, _, errs := key.loadIdentities()
	if len(errs) == 0 {
		t.Fatal("expected loadIdentities to report cmd execution failure, got no errs")
	}
	found := false
	for _, e := range errs {
		if strings.Contains(e.Error(), "failed to execute command") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected an error mentioning cmd execution failure; got: %v", errs)
	}
}

func TestDefaultRecipientFromKeyFile_FullPrecedenceChain(t *testing.T) {
	// All four PXF sources active simultaneously, each supplying a
	// distinct default identity. Walks the chain by progressively
	// unsetting the winner and re-asserting, so the documented
	// precedence (FILE > KEY > CMD > default-path) is empirically
	// validated end-to-end.
	tmp := t.TempDir()
	overwriteUserHomeDir(t, tmp)

	// Fourth identity for the default-path source — the other three
	// reuse the existing mock fixtures so the assertions can pin the
	// expected recipient at known values.
	pathID, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity for default-path source: %v", err)
	}
	pathSecret := pathID.String()
	pathRecipient := pathID.Recipient().String()

	otherRecipient := func() string {
		id, err := age.ParseX25519Identity(mockOtherIdentity)
		if err != nil {
			t.Fatalf("parse mockOtherIdentity: %v", err)
		}
		return id.Recipient().String()
	}()
	hybridRecipient := func() string {
		id, err := age.ParseHybridIdentity(mockHybridIdentity)
		if err != nil {
			t.Fatalf("parse hybrid fixture: %v", err)
		}
		return id.Recipient().String()
	}()

	// FILE source — default resolves to mockRecipient.
	filePath := writePXFKeyFile(t, &keypb.AgeKeyFile{
		Default: "winner",
		Keys:    map[string]string{"winner": mockIdentity},
	})
	t.Setenv(SopsAgeKeyFileEnv, filePath)

	// KEY env source — default resolves to mockOtherIdentity's recipient.
	t.Setenv(SopsAgeKeyEnv, string(pxfBytes(t, &keypb.AgeKeyFile{
		Default: "k",
		Keys:    map[string]string{"k": mockOtherIdentity},
	})))

	// CMD env source — default resolves to hybrid's recipient.
	cmdPxf := filepath.Join(t.TempDir(), "cmd.pxf")
	if err := os.WriteFile(cmdPxf, pxfBytes(t, &keypb.AgeKeyFile{
		Default: "h",
		Keys:    map[string]string{"h": mockHybridIdentity},
	}), 0o600); err != nil {
		t.Fatalf("write cmd fixture: %v", err)
	}
	t.Setenv(SopsAgeKeyCmdEnv, "cat "+cmdPxf)

	// Default-path source — default resolves to the freshly generated
	// X25519 identity above.
	defaultPath := filepath.Join(tmp, filepath.FromSlash(DefaultAgeKeyFilePath))
	writePXFKeyFileAt(t, defaultPath, &keypb.AgeKeyFile{
		Default: "d",
		Keys:    map[string]string{"d": pathSecret},
	})

	steps := []struct {
		name string
		want string
		// unsetBefore: env var to clear before this step, so the
		// previous-step winner stops resolving. Empty on the first
		// step (all four are live then).
		unsetBefore string
	}{
		{name: "FILE wins", want: mockRecipient},
		{name: "KEY env wins after FILE unset", want: otherRecipient, unsetBefore: SopsAgeKeyFileEnv},
		{name: "CMD env wins after KEY unset", want: hybridRecipient, unsetBefore: SopsAgeKeyEnv},
		{name: "default-path wins after CMD unset", want: pathRecipient, unsetBefore: SopsAgeKeyCmdEnv},
	}
	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			if step.unsetBefore != "" {
				os.Unsetenv(step.unsetBefore)
			}
			got, err := DefaultRecipientFromKeyFile()
			if err != nil {
				t.Fatalf("DefaultRecipientFromKeyFile: %v", err)
			}
			if got != step.want {
				t.Errorf("recipient: got %q, want %q", got, step.want)
			}
		})
	}
}

func TestDefaultRecipientFromKeyFile_EnvShadowsDefaultPath(t *testing.T) {
	// Precedence: env source (SOPS_AGE_KEY_FILE) shadows the
	// $HOME/.config/sops/age/keys.pxf default. The default's "ghost"
	// entry must not bleed through.
	tmp := t.TempDir()
	overwriteUserHomeDir(t, tmp)
	os.Unsetenv(SopsAgeKeyEnv)
	os.Unsetenv(SopsAgeKeyCmdEnv)

	// Default file has a default entry that would resolve if consulted.
	defaultPath := filepath.Join(tmp, filepath.FromSlash(DefaultAgeKeyFilePath))
	writePXFKeyFileAt(t, defaultPath, &keypb.AgeKeyFile{
		Default: "ghost",
		Keys:    map[string]string{"ghost": mockOtherIdentity},
	})

	// SOPS_AGE_KEY_FILE points at a higher-precedence file with its
	// own (different) default.
	envPath := writePXFKeyFile(t, &keypb.AgeKeyFile{
		Default: "primary",
		Keys:    map[string]string{"primary": mockIdentity},
	})
	t.Setenv(SopsAgeKeyFileEnv, envPath)

	got, err := DefaultRecipientFromKeyFile()
	if err != nil {
		t.Fatalf("DefaultRecipientFromKeyFile: %v", err)
	}
	if got != mockRecipient {
		t.Errorf("env source should shadow default-path; got %q, want %q (mockRecipient)", got, mockRecipient)
	}
}
