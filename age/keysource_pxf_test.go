package age

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

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
