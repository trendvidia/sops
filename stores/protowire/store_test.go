package protowire

import (
	"bytes"
	"strings"
	"testing"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
