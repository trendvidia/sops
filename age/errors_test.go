package age

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"github.com/stretchr/testify/assert"
)

// These tests pin the typed-error contract for embedders that classify
// decrypt failures with errors.Is / errors.As instead of matching
// message text (#41). Every scenario goes through MasterKey.Decrypt so
// the sentinels are proven to survive the errSet/formatError
// aggregation, not just the site that creates them.

// isolateAgeEnv gives the test a pristine age environment: a scratch
// $HOME (hides the default key file and ~/.ssh keys) and none of the
// SopsAge* env vars, so keys configured on the developer's machine
// can't leak into the classification assertions.
func isolateAgeEnv(t *testing.T) {
	overwriteUserHomeDir(t, t.TempDir())
	for _, v := range []string{
		SopsAgeKeyEnv,
		SopsAgeKeyFileEnv,
		SopsAgeKeyCmdEnv,
		SopsAgeSshPrivateKeyCmdEnv,
		SopsAgeSshPrivateKeyFileEnv,
	} {
		t.Setenv(v, "") // register cleanup restore
		os.Unsetenv(v)
	}
}

func TestTypedErrors_NoIdentities(t *testing.T) {
	isolateAgeEnv(t)

	key := &MasterKey{EncryptedKey: mockEncryptedKey}
	got, err := key.Decrypt()
	assert.Nil(t, got)
	assert.ErrorIs(t, err, ErrNoIdentities)
	assert.NotErrorIs(t, err, ErrNoIdentityMatched)
	assert.ErrorContains(t, err, "failed to load age identities")
}

func TestTypedErrors_NoIdentityMatched(t *testing.T) {
	isolateAgeEnv(t)
	t.Setenv(SopsAgeKeyEnv, mockOtherIdentity)

	key := &MasterKey{EncryptedKey: mockEncryptedKey}
	got, err := key.Decrypt()
	assert.Nil(t, got)
	assert.ErrorIs(t, err, ErrNoIdentityMatched)
	assert.NotErrorIs(t, err, ErrNoIdentities)
	// age's own typed error stays reachable as well.
	noMatch := new(age.NoIdentityMatchError)
	assert.ErrorAs(t, err, &noMatch)
}

func TestTypedErrors_EmptyKeyCommand(t *testing.T) {
	for name, cmd := range map[string]string{
		"empty cmd":           "",
		"whitespace-only cmd": "   ",
	} {
		t.Run(name, func(t *testing.T) {
			isolateAgeEnv(t)
			t.Setenv(SopsAgeKeyCmdEnv, cmd)

			key := &MasterKey{EncryptedKey: mockEncryptedKey}
			_, err := key.Decrypt()
			assert.ErrorIs(t, err, ErrEmptyKeyCommand)
			// The goed#31 misclassification: a set-but-empty command
			// must read as "no key material configured", not "the
			// configured command is broken".
			assert.NotErrorIs(t, err, ErrKeyCommandFailed)
			assert.ErrorIs(t, err, ErrNoIdentities)

			var srcErr *KeySourceError
			assert.ErrorAs(t, err, &srcErr)
			assert.Equal(t, SopsAgeKeyCmdEnv, srcErr.Source)
		})
	}
}

func TestTypedErrors_KeyCommandFailed(t *testing.T) {
	isolateAgeEnv(t)
	t.Setenv(SopsAgeKeyCmdEnv, "meow")

	key := &MasterKey{EncryptedKey: mockEncryptedKey}
	_, err := key.Decrypt()
	assert.ErrorIs(t, err, ErrKeyCommandFailed)
	assert.NotErrorIs(t, err, ErrEmptyKeyCommand)
	assert.ErrorIs(t, err, ErrNoIdentities)

	var srcErr *KeySourceError
	assert.ErrorAs(t, err, &srcErr)
	assert.Equal(t, SopsAgeKeyCmdEnv, srcErr.Source)
}

func TestTypedErrors_KeyFileParse(t *testing.T) {
	t.Run("line-based key file", func(t *testing.T) {
		isolateAgeEnv(t)

		keyPath := filepath.Join(t.TempDir(), "keys.txt")
		assert.NoError(t, os.WriteFile(keyPath, []byte("not-an-age-key"), 0o600))
		t.Setenv(SopsAgeKeyFileEnv, keyPath)

		key := &MasterKey{EncryptedKey: mockEncryptedKey}
		_, err := key.Decrypt()
		assert.ErrorIs(t, err, ErrKeyFileParse)

		var srcErr *KeySourceError
		assert.ErrorAs(t, err, &srcErr)
		assert.Equal(t, SopsAgeKeyFileEnv, srcErr.Source)
	})

	t.Run("PXF key file", func(t *testing.T) {
		isolateAgeEnv(t)

		keyPath := filepath.Join(t.TempDir(), "keys.pxf")
		assert.NoError(t, os.WriteFile(keyPath, []byte("{{{{ not pxf"), 0o600))
		t.Setenv(SopsAgeKeyFileEnv, keyPath)

		key := &MasterKey{EncryptedKey: mockEncryptedKey}
		_, err := key.Decrypt()
		assert.ErrorIs(t, err, ErrKeyFileParse)

		var srcErr *KeySourceError
		assert.ErrorAs(t, err, &srcErr)
		assert.Equal(t, SopsAgeKeyFileEnv, srcErr.Source)
	})
}

// TestTypedErrors_MessageTextUnchanged pins the exact user-facing
// message for the scenarios the sentinels attach to: the typed-error
// surface is additive, so introducing it must not change any rendered
// text (#41 constraint).
func TestTypedErrors_MessageTextUnchanged(t *testing.T) {
	t.Run("empty command", func(t *testing.T) {
		_, err := getOutputFromCmd("", nil)
		assert.EqualError(t, err, `failed to parse command "": empty command`)
	})

	t.Run("no identities aggregate", func(t *testing.T) {
		err := formatError(
			"failed to load age identities",
			nil,
			errSet{errors.New("boom")},
			[]string{"locA", "locB"},
			ErrNoIdentities,
		)
		assert.EqualError(t, err, "failed to load age identities. "+
			"Errors while loading age identities: boom. "+
			"Did not find keys in locations 'locA' and 'locB'.")
	})

	t.Run("decrypt failure aggregate", func(t *testing.T) {
		err := formatError(
			"failed to create reader for decrypting sops data key with age",
			errors.New("no identity matched any of the recipients"),
			nil,
			nil,
			ErrNoIdentityMatched,
		)
		assert.EqualError(t, err, "failed to create reader for decrypting "+
			"sops data key with age: no identity matched any of the recipients")
	})
}

// TestTypedErrors_SentinelDoesNotLeakIntoText guards the sentinelError
// mechanism itself: attaching a sentinel must leave the wrapped error's
// message byte-identical.
func TestTypedErrors_SentinelDoesNotLeakIntoText(t *testing.T) {
	inner := errors.New("exec: \"meow\": executable file not found in $PATH")
	wrapped := withSentinel(ErrKeyCommandFailed, inner)
	assert.Equal(t, inner.Error(), wrapped.Error())
	assert.ErrorIs(t, wrapped, ErrKeyCommandFailed)
	assert.ErrorIs(t, wrapped, inner)
}
