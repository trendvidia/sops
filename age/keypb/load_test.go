package keypb

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/trendvidia/protowire-go/encoding/pxf"
)

func TestReadFile_RoundTrip(t *testing.T) {
	original := &AgeKeyFile{
		Default: "production",
		Keys: map[string]string{
			"production": "AGE-SECRET-KEY-1XYZ",
			"staging":    "AGE-SECRET-KEY-1ABC",
			"personal":   "AGE-SECRET-KEY-1QQQ",
		},
	}

	encoded, err := pxf.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "keys.pxf")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	got, err := ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if got.Default != original.Default {
		t.Errorf("Default: got %q, want %q", got.Default, original.Default)
	}
	if len(got.Keys) != len(original.Keys) {
		t.Errorf("Keys: got %d entries, want %d", len(got.Keys), len(original.Keys))
	}
	for name, secret := range original.Keys {
		if got.Keys[name] != secret {
			t.Errorf("Keys[%q]: got %q, want %q", name, got.Keys[name], secret)
		}
	}
}

func TestReadFile_MissingFile(t *testing.T) {
	_, err := ReadFile(filepath.Join(t.TempDir(), "does-not-exist.pxf"))
	if err == nil {
		t.Fatal("ReadFile of missing path: want error, got nil")
	}
}

func TestReadFile_Malformed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "garbage.pxf")
	if err := os.WriteFile(path, []byte("this is not pxf"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	_, err := ReadFile(path)
	if err == nil {
		t.Fatal("ReadFile of malformed file: want error, got nil")
	}
}

func TestReadFile_NoDefault(t *testing.T) {
	// A file without a default is valid — sops just won't auto-pick
	// a recipient at encrypt time.
	original := &AgeKeyFile{
		Keys: map[string]string{
			"only-one": "AGE-SECRET-KEY-1XYZ",
		},
	}

	encoded, err := pxf.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "keys.pxf")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	got, err := ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if got.Default != "" {
		t.Errorf("Default: got %q, want empty", got.Default)
	}
	if got.Keys["only-one"] != "AGE-SECRET-KEY-1XYZ" {
		t.Errorf("Keys[only-one]: got %q, want %q", got.Keys["only-one"], "AGE-SECRET-KEY-1XYZ")
	}
}
