package protowire

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trendvidia/sops/v4"
	"github.com/trendvidia/sops/v4/age"
	"github.com/trendvidia/sops/v4/config"
	"github.com/trendvidia/sops/v4/kms"
)

func newStore() *Store {
	return NewStore(&config.ProtowireStoreConfig{})
}

func TestRoundTripSimpleBranch(t *testing.T) {
	branch := sops.TreeBranch{
		{Key: "hello", Value: "world"},
		{Key: "count", Value: 42},
		{Key: "ratio", Value: 0.5},
		{Key: "enabled", Value: true},
		{Key: "missing", Value: nil},
		{Key: "tags", Value: []interface{}{"a", "b", "c"}},
	}

	store := newStore()
	out, err := store.EmitPlainFile(sops.TreeBranches{branch})
	require.NoError(t, err)
	assert.Contains(t, string(out), `hello = "world"`)
	assert.Contains(t, string(out), "count = 42")
	assert.Contains(t, string(out), "enabled = true")
	assert.Contains(t, string(out), "missing = null")

	branches, err := store.LoadPlainFile(out)
	require.NoError(t, err)
	require.Len(t, branches, 1)
	assert.Equal(t, "world", lookup(branches[0], "hello"))
	assert.Equal(t, 42, lookup(branches[0], "count"))
	assert.Equal(t, 0.5, lookup(branches[0], "ratio"))
	assert.Equal(t, true, lookup(branches[0], "enabled"))
	assert.Nil(t, lookup(branches[0], "missing"))
	assert.Equal(t, []interface{}{"a", "b", "c"}, lookup(branches[0], "tags"))
}

func TestRoundTripNestedBranch(t *testing.T) {
	branch := sops.TreeBranch{
		{
			Key: "server",
			Value: sops.TreeBranch{
				{Key: "host", Value: "example.com"},
				{Key: "port", Value: 8080},
			},
		},
		{
			Key: "endpoints",
			Value: []interface{}{
				sops.TreeBranch{
					{Key: "path", Value: "/api"},
					{Key: "method", Value: "GET"},
				},
				sops.TreeBranch{
					{Key: "path", Value: "/health"},
					{Key: "method", Value: "GET"},
				},
			},
		},
	}

	store := newStore()
	out, err := store.EmitPlainFile(sops.TreeBranches{branch})
	require.NoError(t, err)

	// Sub-branch becomes a Block with identifier name `server`.
	assert.Contains(t, string(out), "server {")
	// List of branches becomes [{...}, {...}].
	assert.Contains(t, string(out), "endpoints = [")

	branches, err := store.LoadPlainFile(out)
	require.NoError(t, err)
	require.Len(t, branches, 1)
	server, ok := lookup(branches[0], "server").(sops.TreeBranch)
	require.True(t, ok, "server must be a TreeBranch")
	assert.Equal(t, "example.com", lookup(server, "host"))
	assert.Equal(t, 8080, lookup(server, "port"))

	endpoints, ok := lookup(branches[0], "endpoints").([]interface{})
	require.True(t, ok, "endpoints must be a list")
	require.Len(t, endpoints, 2)
	first, ok := endpoints[0].(sops.TreeBranch)
	require.True(t, ok, "endpoint[0] must be a TreeBranch")
	assert.Equal(t, "/api", lookup(first, "path"))
}

func TestRoundTripWithComments(t *testing.T) {
	branch := sops.TreeBranch{
		{Key: sops.Comment{Value: " greeting"}, Value: nil},
		{Key: "hello", Value: "world"},
	}
	store := newStore()
	out, err := store.EmitPlainFile(sops.TreeBranches{branch})
	require.NoError(t, err)
	assert.Contains(t, string(out), "# greeting")
	assert.Contains(t, string(out), `hello = "world"`)

	branches, err := store.LoadPlainFile(out)
	require.NoError(t, err)
	require.Len(t, branches, 1)
	// Comment should round-trip back as a Comment item.
	var foundComment bool
	for _, item := range branches[0] {
		if c, ok := item.Key.(sops.Comment); ok && strings.Contains(c.Value, "greeting") {
			foundComment = true
			break
		}
	}
	assert.True(t, foundComment, "comment should round-trip")
}

func TestEmitExample(t *testing.T) {
	store := newStore()
	out := store.EmitExample()
	assert.NotEmpty(t, out)
	// Re-parse to confirm the example is syntactically valid PXF.
	_, err := store.LoadPlainFile(out)
	require.NoError(t, err)
}

func TestEmitValue(t *testing.T) {
	store := newStore()
	out, err := store.EmitValue("hello world")
	require.NoError(t, err)
	assert.Equal(t, `"hello world"`, string(bytes.TrimSpace(out)))

	out, err = store.EmitValue(7)
	require.NoError(t, err)
	assert.Equal(t, "7", string(bytes.TrimSpace(out)))
}

func TestTopLevelNonIdentifierKeyRejected(t *testing.T) {
	branch := sops.TreeBranch{
		{Key: "Welcome!", Value: "msg"},
	}
	store := newStore()
	_, err := store.EmitPlainFile(sops.TreeBranches{branch})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "identifier")
}

func TestNestedNonIdentifierKeyAccepted(t *testing.T) {
	branch := sops.TreeBranch{
		{
			Key: "data",
			Value: sops.TreeBranch{
				{Key: "Welcome!", Value: "msg"},
			},
		},
	}
	store := newStore()
	out, err := store.EmitPlainFile(sops.TreeBranches{branch})
	require.NoError(t, err)
	assert.Contains(t, string(out), `"Welcome!": "msg"`)

	branches, err := store.LoadPlainFile(out)
	require.NoError(t, err)
	data, ok := lookup(branches[0], "data").(sops.TreeBranch)
	require.True(t, ok)
	assert.Equal(t, "msg", lookup(data, "Welcome!"))
}

func lookup(branch sops.TreeBranch, key string) interface{} {
	for _, item := range branch {
		if k, ok := item.Key.(string); ok && k == key {
			return item.Value
		}
	}
	return nil
}

func TestEncryptedRoundTrip(t *testing.T) {
	// Build a tree with realistic data and a fully-populated metadata
	// block (including an age master key), emit it, reload it, and
	// confirm both sides survive the PXF serialization round-trip.
	lastModified := time.Date(2026, 5, 2, 13, 0, 0, 0, time.UTC)

	original := sops.Tree{
		Branches: sops.TreeBranches{
			sops.TreeBranch{
				{Key: "secret", Value: "ENC[AES256_GCM,data:abc,iv:def,tag:ghi,type:str]"},
				{Key: "count", Value: 7},
				{
					Key: "nested",
					Value: sops.TreeBranch{
						{Key: "inner", Value: "ENC[AES256_GCM,data:xyz,iv:uvw,tag:rst,type:str]"},
					},
				},
			},
		},
		Metadata: sops.Metadata{
			LastModified:              lastModified,
			MessageAuthenticationCode: "ENC[AES256_GCM,data:mac,iv:mi,tag:mt,type:str]",
			Version:                   "3.16.0",
			UnencryptedSuffix:         "_plain",
			KeyGroups: []sops.KeyGroup{
				{
					&age.MasterKey{
						Recipient:    "age1lzd99uklcjnc0e7d860axevet2cz99ce9pq6tzuzd05l5nr28ams36nvun",
						EncryptedKey: "-----BEGIN AGE ENCRYPTED FILE-----\nMOCK\n-----END AGE ENCRYPTED FILE-----",
					},
					// KMS key alongside the age key to verify CreationDate
					// round-trips — age.MasterKey intentionally has no
					// CreationDate field in the storage format, so KMS
					// is the right shape to pin that behavior here.
					&kms.MasterKey{
						Arn:          "arn:aws:kms:us-east-1:000000000000:key/00000000-0000-0000-0000-000000000000",
						EncryptedKey: "MOCK_KMS_KEY",
						CreationDate: time.Date(2026, 4, 1, 10, 0, 0, 0, time.UTC),
					},
				},
			},
		},
	}

	store := newStore()
	encoded, err := store.EmitEncryptedFile(original)
	require.NoError(t, err, "EmitEncryptedFile")
	assert.Contains(t, string(encoded), "sops {", "metadata must be embedded as a sops block")

	reloaded, err := store.LoadEncryptedFile(encoded)
	require.NoError(t, err, "LoadEncryptedFile")

	// Data branches survive.
	require.Len(t, reloaded.Branches, 1)
	assert.Equal(t, "ENC[AES256_GCM,data:abc,iv:def,tag:ghi,type:str]", lookup(reloaded.Branches[0], "secret"))
	assert.Equal(t, 7, lookup(reloaded.Branches[0], "count"))
	nested, ok := lookup(reloaded.Branches[0], "nested").(sops.TreeBranch)
	require.True(t, ok, "nested must round-trip as a TreeBranch")
	assert.Equal(t, "ENC[AES256_GCM,data:xyz,iv:uvw,tag:rst,type:str]", lookup(nested, "inner"))

	// Metadata scalars survive.
	assert.Equal(t, original.Metadata.LastModified, reloaded.Metadata.LastModified)
	assert.Equal(t, original.Metadata.MessageAuthenticationCode, reloaded.Metadata.MessageAuthenticationCode)
	assert.Equal(t, original.Metadata.Version, reloaded.Metadata.Version)
	assert.Equal(t, original.Metadata.UnencryptedSuffix, reloaded.Metadata.UnencryptedSuffix)

	// Age and KMS master keys both survive. The reloaded group is
	// grouped by key type (see internalGroupFrom in stores/stores.go:
	// KMS first, ..., age last), so look them up by type rather than
	// by source-order index.
	require.Len(t, reloaded.Metadata.KeyGroups, 1)
	require.Len(t, reloaded.Metadata.KeyGroups[0], 2)
	var gotAge *age.MasterKey
	var gotKMS *kms.MasterKey
	for _, k := range reloaded.Metadata.KeyGroups[0] {
		switch v := k.(type) {
		case *age.MasterKey:
			gotAge = v
		case *kms.MasterKey:
			gotKMS = v
		}
	}
	require.NotNil(t, gotAge, "age key missing from reloaded group")
	require.NotNil(t, gotKMS, "kms key missing from reloaded group")

	assert.Equal(t, "age1lzd99uklcjnc0e7d860axevet2cz99ce9pq6tzuzd05l5nr28ams36nvun", gotAge.Recipient)
	assert.Contains(t, gotAge.EncryptedKey, "MOCK")

	assert.Equal(t, "arn:aws:kms:us-east-1:000000000000:key/00000000-0000-0000-0000-000000000000", gotKMS.Arn)
	assert.Equal(t, "MOCK_KMS_KEY", gotKMS.EncryptedKey)
	// CreationDate round-trip: pins that the KMS key's timestamp
	// survives the PXF encode/decode cycle, closing the question I
	// flagged in the v4 audit but didn't verify.
	assert.True(t, gotKMS.CreationDate.Equal(time.Date(2026, 4, 1, 10, 0, 0, 0, time.UTC)),
		"KMS CreationDate did not round-trip: got %v", gotKMS.CreationDate)
}

func TestLoadEncryptedFileNoMetadata(t *testing.T) {
	// Plaintext PXF (no `sops { ... }` block) must return
	// MetadataNotFound, matching sibling stores.
	store := newStore()
	_, err := store.LoadEncryptedFile([]byte(`hello = "world"`))
	assert.Equal(t, sops.MetadataNotFound, err)
}

func TestLoadPlainFileMalformed(t *testing.T) {
	// Confirm malformed inputs surface a wrapped parse error from the
	// store rather than crashing or returning a partial branch. Cases
	// are chosen to exercise the store's error wrapping; each must
	// produce a non-nil error mentioning "unmarshal" (the store's
	// wrapper prefix).
	cases := []struct {
		name string
		in   string
	}{
		{name: "unterminated block", in: `keys {`},
		{name: "unterminated string", in: `key = "no closing quote`},
		{name: "unterminated list", in: `xs = [1, 2,`},
		{name: "garbage bytes", in: "\x00\x01\x02 not pxf"},
		{name: "stray closing brace", in: `}`},
		{name: "key with no value", in: `key =`},
		{name: "missing equals", in: `key "value"`},
	}
	store := newStore()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := store.LoadPlainFile([]byte(tc.in))
			require.Error(t, err, "expected parse error for %q", tc.in)
			assert.Contains(t, err.Error(), "unmarshal", "error should be wrapped by the store: %v", err)
		})
	}
}

func TestEmitPlainFileRejectsMultipleBranches(t *testing.T) {
	// PXF stores a single document per file; multi-branch input must
	// be rejected at emit time rather than producing concatenated PXF.
	store := newStore()
	_, err := store.EmitPlainFile(sops.TreeBranches{
		{{Key: "a", Value: 1}},
		{{Key: "b", Value: 2}},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "single document")
}

func TestLoadEncryptedFileCorruptMetadata(t *testing.T) {
	// Decrypt-side malformed-metadata cases. Each input parses as valid
	// PXF (LoadPlainFile succeeds) but the embedded `sops` metadata is
	// shaped wrong for ExtractMetadata. Must surface a clean error
	// rather than crash or return partial metadata.
	cases := []struct {
		name      string
		in        string
		wantInErr string
	}{
		{
			name:      "sops is a string, not a block",
			in:        `sops = "oops"`,
			wantInErr: "not a mapping",
		},
		{
			name: "duplicate sops blocks at top level",
			in: `sops {
  version = "3.16.0"
}
sops {
  version = "3.16.1"
}
`,
			wantInErr: "duplicate",
		},
		{
			name: "bad lastmodified timestamp",
			in: `sops {
  lastmodified = "not-a-timestamp"
  version = "3.16.0"
}
`,
			// stores.parseTimestamp wraps with the field name so the
			// error tells the user WHICH timestamp failed to parse.
			wantInErr: "lastmodified",
		},
	}
	store := newStore()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := store.LoadEncryptedFile([]byte(tc.in))
			require.Error(t, err, "expected LoadEncryptedFile to error for %q", tc.in)
			// Case-insensitive match because error wording varies across
			// extraction stages ("Found sops entry...", "lastmodified:", etc).
			assert.Contains(t, strings.ToLower(err.Error()), strings.ToLower(tc.wantInErr),
				"error should mention %q; got: %v", tc.wantInErr, err)
		})
	}
}

func TestRoundTripNestedMapEntryKeys(t *testing.T) {
	// Nested map-entry keys with non-identifier strings (quoted keys
	// inside a block) must round-trip without being mangled. Sibling
	// stores (yaml/json) accept arbitrary string keys; protowire's
	// stricter top-level identifier rule applies only at the root.
	branch := sops.TreeBranch{
		{
			Key: "envs",
			Value: sops.TreeBranch{
				{Key: "production-eu", Value: "ENC[AES256_GCM,data:p,iv:i,tag:t,type:str]"},
				{Key: "staging.us-east-1", Value: "ENC[AES256_GCM,data:s,iv:i,tag:t,type:str]"},
			},
		},
	}
	store := newStore()
	out, err := store.EmitPlainFile(sops.TreeBranches{branch})
	require.NoError(t, err)

	branches, err := store.LoadPlainFile(out)
	require.NoError(t, err)
	require.Len(t, branches, 1)
	envs, ok := lookup(branches[0], "envs").(sops.TreeBranch)
	require.True(t, ok, "envs must be a TreeBranch")
	assert.Equal(t, "ENC[AES256_GCM,data:p,iv:i,tag:t,type:str]", lookup(envs, "production-eu"))
	assert.Equal(t, "ENC[AES256_GCM,data:s,iv:i,tag:t,type:str]", lookup(envs, "staging.us-east-1"))
}
