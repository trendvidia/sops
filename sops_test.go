package sops

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/trendvidia/sops/v4/age"
	"github.com/trendvidia/sops/v4/hcvault"
	"github.com/trendvidia/sops/v4/pgp"
)

type reverseCipher struct{}

// reverse returns its argument string reversed rune-wise left to right.
func reverse(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < len(r)/2; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

func (c reverseCipher) Encrypt(value interface{}, key []byte, path string) (string, error) {
	b, err := ToBytes(value)
	if err != nil {
		return "", err
	}
	return reverse(string(b)), nil
}
func (c reverseCipher) Decrypt(value string, key []byte, path string) (plaintext interface{}, err error) {
	if value == "error" {
		return nil, fmt.Errorf("Error")
	}
	return reverse(value), nil
}

type encPrefixCipher struct{}

func (c encPrefixCipher) Encrypt(value interface{}, key []byte, path string) (string, error) {
	b, err := ToBytes(value)
	if err != nil {
		return "", err
	}
	return "ENC:" + string(b), nil
}
func (c encPrefixCipher) Decrypt(value string, key []byte, path string) (plaintext interface{}, err error) {
	v, ok := strings.CutPrefix(value, "ENC:")
	if !ok {
		return nil, fmt.Errorf("String not prefixed with 'ENC:'")
	}
	return v, nil
}

func TestUnencryptedSuffix(t *testing.T) {
	branches := TreeBranches{
		TreeBranch{
			TreeItem{
				Key:   "foo_unencrypted",
				Value: "bar",
			},
			TreeItem{
				Key: "bar_unencrypted",
				Value: TreeBranch{
					TreeItem{
						Key:   "foo",
						Value: "bar",
					},
				},
			},
		},
	}
	tree := Tree{Branches: branches, Metadata: Metadata{UnencryptedSuffix: "_unencrypted"}}
	expected := TreeBranch{
		TreeItem{
			Key:   "foo_unencrypted",
			Value: "bar",
		},
		TreeItem{
			Key: "bar_unencrypted",
			Value: TreeBranch{
				TreeItem{
					Key:   "foo",
					Value: "bar",
				},
			},
		},
	}
	cipher := reverseCipher{}
	_, err := tree.Encrypt(bytes.Repeat([]byte("f"), 32), cipher)
	if err != nil {
		t.Errorf("Encrypting the tree failed: %s", err)
	}
	if !reflect.DeepEqual(tree.Branches[0], expected) {
		t.Errorf("Trees don't match: \ngot \t\t%+v,\n expected \t\t%+v", tree.Branches[0], expected)
	}
	_, err = tree.Decrypt(bytes.Repeat([]byte("f"), 32), cipher)
	if err != nil {
		t.Errorf("Decrypting the tree failed: %s", err)
	}
	if !reflect.DeepEqual(tree.Branches[0], expected) {
		t.Errorf("Trees don't match: \ngot\t\t\t%+v,\nexpected\t\t%+v", tree.Branches[0], expected)
	}
}

func TestEncryptedSuffix(t *testing.T) {
	branches := TreeBranches{
		TreeBranch{
			TreeItem{
				Key:   "foo_encrypted",
				Value: "bar",
			},
			TreeItem{
				Key: "bar",
				Value: TreeBranch{
					TreeItem{
						Key:   "foo",
						Value: "bar",
					},
				},
			},
		},
	}
	tree := Tree{Branches: branches, Metadata: Metadata{EncryptedSuffix: "_encrypted"}}
	expected := TreeBranch{
		TreeItem{
			Key:   "foo_encrypted",
			Value: "rab",
		},
		TreeItem{
			Key: "bar",
			Value: TreeBranch{
				TreeItem{
					Key:   "foo",
					Value: "bar",
				},
			},
		},
	}
	cipher := reverseCipher{}
	_, err := tree.Encrypt(bytes.Repeat([]byte("f"), 32), cipher)
	if err != nil {
		t.Errorf("Encrypting the tree failed: %s", err)
	}
	if !reflect.DeepEqual(tree.Branches[0], expected) {
		t.Errorf("Trees don't match: \ngot \t\t%+v,\n expected \t\t%+v", tree.Branches[0], expected)
	}
	_, err = tree.Decrypt(bytes.Repeat([]byte("f"), 32), cipher)
	if err != nil {
		t.Errorf("Decrypting the tree failed: %s", err)
	}
	expected[0].Value = "bar"
	if !reflect.DeepEqual(tree.Branches[0], expected) {
		t.Errorf("Trees don't match: \ngot\t\t\t%+v,\nexpected\t\t%+v", tree.Branches[0], expected)
	}
}

func TestEncryptedRegex(t *testing.T) {
	branches := TreeBranches{
		TreeBranch{
			TreeItem{
				Key:   "enc:foo",
				Value: "bar",
			},
			TreeItem{
				Key: "bar",
				Value: TreeBranch{
					TreeItem{
						Key:   "foo",
						Value: "bar",
					},
				},
			},
		},
	}
	tree := Tree{Branches: branches, Metadata: Metadata{EncryptedRegex: "^enc:"}}
	expected := TreeBranch{
		TreeItem{
			Key:   "enc:foo",
			Value: "rab",
		},
		TreeItem{
			Key: "bar",
			Value: TreeBranch{
				TreeItem{
					Key:   "foo",
					Value: "bar",
				},
			},
		},
	}
	cipher := reverseCipher{}
	_, err := tree.Encrypt(bytes.Repeat([]byte("f"), 32), cipher)
	if err != nil {
		t.Errorf("Encrypting the tree failed: %s", err)
	}
	if !reflect.DeepEqual(tree.Branches[0], expected) {
		t.Errorf("Trees don't match: \ngot \t\t%+v,\n expected \t\t%+v", tree.Branches[0], expected)
	}
	_, err = tree.Decrypt(bytes.Repeat([]byte("f"), 32), cipher)
	if err != nil {
		t.Errorf("Decrypting the tree failed: %s", err)
	}
	expected[0].Value = "bar"
	if !reflect.DeepEqual(tree.Branches[0], expected) {
		t.Errorf("Trees don't match: \ngot\t\t\t%+v,\nexpected\t\t%+v", tree.Branches[0], expected)
	}
}

func TestUnencryptedRegex(t *testing.T) {
	branches := TreeBranches{
		TreeBranch{
			TreeItem{
				Key:   "dec:foo",
				Value: "bar",
			},
			TreeItem{
				Key: "dec:bar",
				Value: TreeBranch{
					TreeItem{
						Key:   "foo",
						Value: "bar",
					},
				},
			},
		},
	}
	tree := Tree{Branches: branches, Metadata: Metadata{UnencryptedRegex: "^dec:"}}
	expected := TreeBranch{
		TreeItem{
			Key:   "dec:foo",
			Value: "bar",
		},
		TreeItem{
			Key: "dec:bar",
			Value: TreeBranch{
				TreeItem{
					Key:   "foo",
					Value: "bar",
				},
			},
		},
	}
	cipher := reverseCipher{}

	_, err := tree.Encrypt(bytes.Repeat([]byte("f"), 32), cipher)
	if err != nil {
		t.Errorf("Encrypting the tree failed: %s", err)
	}
	// expected[1].Value[] = "bar"
	if !reflect.DeepEqual(tree.Branches[0], expected) {
		t.Errorf("Trees don't match: \ngot \t\t%+v,\n expected \t\t%+v", tree.Branches[0], expected)
	}
	_, err = tree.Decrypt(bytes.Repeat([]byte("f"), 32), cipher)
	if err != nil {
		t.Errorf("Decrypting the tree failed: %s", err)
	}
	if !reflect.DeepEqual(tree.Branches[0], expected) {
		t.Errorf("Trees don't match: \ngot\t\t\t%+v,\nexpected\t\t%+v", tree.Branches[0], expected)
	}
}

func TestMACOnlyEncrypted(t *testing.T) {
	branches := TreeBranches{
		TreeBranch{
			TreeItem{
				Key:   "foo_encrypted",
				Value: "bar",
			},
			TreeItem{
				Key: "bar",
				Value: TreeBranch{
					TreeItem{
						Key:   "foo",
						Value: "bar",
					},
				},
			},
		},
	}
	tree := Tree{Branches: branches, Metadata: Metadata{EncryptedSuffix: "_encrypted", MACOnlyEncrypted: true}}
	onlyEncrypted := TreeBranches{
		TreeBranch{
			TreeItem{
				Key:   "foo_encrypted",
				Value: "bar",
			},
		},
	}
	treeOnlyEncrypted := Tree{Branches: onlyEncrypted, Metadata: Metadata{EncryptedSuffix: "_encrypted", MACOnlyEncrypted: true}}
	cipher := reverseCipher{}
	mac, err := tree.Encrypt(bytes.Repeat([]byte("f"), 32), cipher)
	if err != nil {
		t.Errorf("Encrypting the tree failed: %s", err)
	}
	macOnlyEncrypted, err := treeOnlyEncrypted.Encrypt(bytes.Repeat([]byte("f"), 32), cipher)
	if err != nil {
		t.Errorf("Encrypting the treeOnlyEncrypted failed: %s", err)
	}
	if mac != macOnlyEncrypted {
		t.Errorf("MACs don't match:\ngot \t\t%+v,\nexpected \t\t%+v", mac, macOnlyEncrypted)
	}
}

func TestMACOnlyEncryptedNoConfusion(t *testing.T) {
	branches := TreeBranches{
		TreeBranch{
			TreeItem{
				Key:   "foo_encrypted",
				Value: "bar",
			},
			TreeItem{
				Key: "bar",
				Value: TreeBranch{
					TreeItem{
						Key:   "foo",
						Value: "bar",
					},
				},
			},
		},
	}
	tree := Tree{Branches: branches, Metadata: Metadata{EncryptedSuffix: "_encrypted", MACOnlyEncrypted: true}}
	onlyEncrypted := TreeBranches{
		TreeBranch{
			TreeItem{
				Key:   "foo_encrypted",
				Value: "bar",
			},
		},
	}
	treeOnlyEncrypted := Tree{Branches: onlyEncrypted, Metadata: Metadata{EncryptedSuffix: "_encrypted"}}
	cipher := reverseCipher{}
	mac, err := tree.Encrypt(bytes.Repeat([]byte("f"), 32), cipher)
	if err != nil {
		t.Errorf("Encrypting the tree failed: %s", err)
	}
	macOnlyEncrypted, err := treeOnlyEncrypted.Encrypt(bytes.Repeat([]byte("f"), 32), cipher)
	if err != nil {
		t.Errorf("Encrypting the treeOnlyEncrypted failed: %s", err)
	}
	if mac == macOnlyEncrypted {
		t.Errorf("MACs match but they should not")
	}
}

func TestEncryptedCommentRegex(t *testing.T) {
	branches := TreeBranches{
		TreeBranch{
			TreeItem{
				Key:   Comment{Value: "sops:enc"},
				Value: nil,
			},
			TreeItem{
				Key:   "foo",
				Value: "bar",
			},
			TreeItem{
				Key: "bar",
				Value: TreeBranch{
					TreeItem{
						Key:   "foo",
						Value: "bar",
					},
					TreeItem{
						Key:   Comment{Value: "before"},
						Value: nil,
					},
					TreeItem{
						Key:   Comment{Value: "sops:enc"},
						Value: nil,
					},
					TreeItem{
						Key:   "encrypted",
						Value: "bar",
					},
				},
			},
			TreeItem{
				Key: "array",
				Value: []interface{}{
					"bar",
					Comment{Value: "sops:enc"},
					"baz",
				},
			},
			TreeItem{
				Key:   Comment{Value: "sops:enc"},
				Value: nil,
			},
			TreeItem{
				Key:   Comment{Value: "after"},
				Value: nil,
			},
			TreeItem{
				Key: "encarray",
				Value: []interface{}{
					"bar",
					"baz",
				},
			},
		},
	}
	tree := Tree{Branches: branches, Metadata: Metadata{EncryptedCommentRegex: "sops:enc"}}
	expected := TreeBranch{
		TreeItem{
			Key:   Comment{Value: "sops:enc"},
			Value: nil,
		},
		TreeItem{
			Key:   "foo",
			Value: "rab",
		},
		TreeItem{
			Key: "bar",
			Value: TreeBranch{
				TreeItem{
					Key:   "foo",
					Value: "bar",
				},
				TreeItem{
					Key:   Comment{Value: "before"},
					Value: nil,
				},
				TreeItem{
					Key:   Comment{Value: "sops:enc"},
					Value: nil,
				},
				TreeItem{
					Key:   "encrypted",
					Value: "rab",
				},
			},
		},
		TreeItem{
			Key: "array",
			Value: []interface{}{
				"bar",
				Comment{Value: "sops:enc"},
				"zab",
			},
		},
		TreeItem{
			Key:   Comment{Value: "sops:enc"},
			Value: nil,
		},
		TreeItem{
			Key:   Comment{Value: "retfa"},
			Value: nil,
		},
		TreeItem{
			Key: "encarray",
			Value: []interface{}{
				"rab",
				"zab",
			},
		},
	}
	cipher := reverseCipher{}
	_, err := tree.Encrypt(bytes.Repeat([]byte("f"), 32), cipher)
	if err != nil {
		t.Errorf("Encrypting the tree failed: %s", err)
	}
	if !reflect.DeepEqual(tree.Branches[0], expected) {
		t.Errorf("Trees don't match: \ngot \t\t%+v,\n expected \t\t%+v", tree.Branches[0], expected)
	}
	_, err = tree.Decrypt(bytes.Repeat([]byte("f"), 32), cipher)
	if err != nil {
		t.Errorf("Decrypting the tree failed: %s", err)
	}
	expected[1].Value = "bar"
	expected[2].Value.(TreeBranch)[3].Value = "bar"
	expected[3].Value.([]interface{})[2] = "baz"
	expected[5].Key = Comment{Value: "after"}
	expected[6].Value = []interface{}{
		"bar",
		"baz",
	}
	if !reflect.DeepEqual(tree.Branches[0], expected) {
		t.Errorf("Trees don't match: \ngot\t\t\t%+v,\nexpected\t\t%+v", tree.Branches[0], expected)
	}
}

func TestUnencryptedCommentRegex(t *testing.T) {
	branches := TreeBranches{
		TreeBranch{
			TreeItem{
				Key:   Comment{Value: "sops:noenc"},
				Value: nil,
			},
			TreeItem{
				Key:   "foo",
				Value: "bar",
			},
			TreeItem{
				Key: "bar",
				Value: TreeBranch{
					TreeItem{
						Key:   "foo",
						Value: "bar",
					},
					TreeItem{
						Key:   Comment{Value: "before"},
						Value: nil,
					},
					TreeItem{
						Key:   Comment{Value: "sops:noenc"},
						Value: nil,
					},
					TreeItem{
						Key:   "notencrypted",
						Value: "bar",
					},
				},
			},
			TreeItem{
				Key: "array",
				Value: []interface{}{
					"bar",
					Comment{Value: "sops:noenc"},
					"baz",
				},
			},
			TreeItem{
				Key:   Comment{Value: "sops:noenc"},
				Value: nil,
			},
			TreeItem{
				Key:   Comment{Value: "after"},
				Value: nil,
			},
			TreeItem{
				Key: "notencarray",
				Value: []interface{}{
					"bar",
					"baz",
				},
			},
		},
	}
	// Fork policy: all comments stay plaintext by default. The
	// UnencryptedCommentRegex carve-out then keeps the NEARBY values
	// (not the comments themselves — comments were already plaintext)
	// unencrypted. The "before" comment, which upstream expects to
	// encrypt as "erofeb", now stays as "before" under fork policy.
	tree := Tree{Branches: branches, Metadata: Metadata{UnencryptedCommentRegex: "sops:noenc"}}
	expected := TreeBranch{
		TreeItem{
			Key:   Comment{Value: "sops:noenc"},
			Value: nil,
		},
		TreeItem{
			Key:   "foo",
			Value: "bar",
		},
		TreeItem{
			Key: "bar",
			Value: TreeBranch{
				TreeItem{
					Key:   "foo",
					Value: "rab",
				},
				TreeItem{
					Key:   Comment{Value: "before"},
					Value: nil,
				},
				TreeItem{
					Key:   Comment{Value: "sops:noenc"},
					Value: nil,
				},
				TreeItem{
					Key:   "notencrypted",
					Value: "bar",
				},
			},
		},
		TreeItem{
			Key: "array",
			Value: []interface{}{
				"rab",
				Comment{Value: "sops:noenc"},
				"baz",
			},
		},
		TreeItem{
			Key:   Comment{Value: "sops:noenc"},
			Value: nil,
		},
		TreeItem{
			Key:   Comment{Value: "after"},
			Value: nil,
		},
		TreeItem{
			Key: "notencarray",
			Value: []interface{}{
				"bar",
				"baz",
			},
		},
	}
	cipher := reverseCipher{}
	_, err := tree.Encrypt(bytes.Repeat([]byte("f"), 32), cipher)
	if err != nil {
		t.Errorf("Encrypting the tree failed: %s", err)
	}
	if !reflect.DeepEqual(tree.Branches[0], expected) {
		t.Errorf("Trees don't match: \ngot \t\t%+v,\n expected \t\t%+v", tree.Branches[0], expected)
	}
	_, err = tree.Decrypt(bytes.Repeat([]byte("f"), 32), cipher)
	if err != nil {
		t.Errorf("Decrypting the tree failed: %s", err)
	}
	expected[2].Value.(TreeBranch)[0].Value = "bar"
	expected[2].Value.(TreeBranch)[1].Key = Comment{Value: "before"}
	expected[3].Value.([]interface{})[0] = "bar"
	if !reflect.DeepEqual(tree.Branches[0], expected) {
		t.Errorf("Trees don't match: \ngot\t\t\t%+v,\nexpected\t\t%+v", tree.Branches[0], expected)
	}
}

func TestUnencryptedCommentRegexFail(t *testing.T) {
	branches := TreeBranches{
		TreeBranch{
			TreeItem{
				Key:   Comment{Value: "sops:noenc"},
				Value: nil,
			},
			TreeItem{
				Key:   "foo",
				Value: "bar",
			},
		},
	}
	tree := Tree{Branches: branches, Metadata: Metadata{UnencryptedCommentRegex: "ENC"}}
	cipher := encPrefixCipher{}
	_, err := tree.Encrypt(bytes.Repeat([]byte("f"), 32), cipher)
	// Upstream: the comment "sops:noenc" would be encrypted to
	// "ENC:sops:noenc", that ciphertext would match
	// UnencryptedCommentRegex ("ENC"), and sops would error to flag
	// the config conflict. Under fork policy, comments are never
	// encrypted in the first place, so the conflict is unreachable
	// — Encrypt completes without error.
	assert.NoError(t, err,
		"comments don't encrypt under fork policy → no ciphertext that could match UnencryptedCommentRegex")
}

type MockCipher struct{}

func (m MockCipher) Encrypt(value interface{}, key []byte, path string) (string, error) {
	return "a", nil
}

func (m MockCipher) Decrypt(value string, key []byte, path string) (interface{}, error) {
	return "a", nil
}

func TestEncrypt(t *testing.T) {
	branches := TreeBranches{
		TreeBranch{
			TreeItem{
				Key:   "foo",
				Value: "bar",
			},
			TreeItem{
				Key: "baz",
				Value: TreeBranch{
					TreeItem{
						Key:   "bar",
						Value: 5,
					},
				},
			},
			TreeItem{
				Key:   "bar",
				Value: false,
			},
			TreeItem{
				Key:   "foobar",
				Value: 2.12,
			},
			TreeItem{
				Key:   "barfoo",
				Value: nil,
			},
		},
		TreeBranch{
			TreeItem{
				Key:   "foo2",
				Value: "bar",
			},
		},
		TreeBranch{
			TreeItem{
				Key:   "foo3",
				Value: "bar",
			},
		},
	}
	expected := TreeBranches{
		TreeBranch{
			TreeItem{
				Key:   "foo",
				Value: "a",
			},
			TreeItem{
				Key: "baz",
				Value: TreeBranch{
					TreeItem{
						Key:   "bar",
						Value: "a",
					},
				},
			},
			TreeItem{
				Key:   "bar",
				Value: "a",
			},
			TreeItem{
				Key:   "foobar",
				Value: "a",
			},
			TreeItem{
				Key:   "barfoo",
				Value: nil,
			},
		},
		TreeBranch{
			TreeItem{
				Key:   "foo2",
				Value: "a",
			},
		},
		TreeBranch{
			TreeItem{
				Key:   "foo3",
				Value: "a",
			},
		},
	}
	tree := Tree{Branches: branches, Metadata: Metadata{UnencryptedSuffix: DefaultUnencryptedSuffix}}
	tree.Encrypt(bytes.Repeat([]byte{'f'}, 32), MockCipher{})
	if !reflect.DeepEqual(tree.Branches, expected) {
		t.Errorf("%s does not equal expected tree: %s", tree.Branches, expected)
	}
}

func TestDecrypt(t *testing.T) {
	branches := TreeBranches{
		TreeBranch{
			TreeItem{
				Key:   "foo",
				Value: "bar",
			},
			TreeItem{
				Key: "baz",
				Value: TreeBranch{
					TreeItem{
						Key:   "bar",
						Value: "5",
					},
				},
			},
			TreeItem{
				Key:   "bar",
				Value: "false",
			},
			TreeItem{
				Key:   "foobar",
				Value: "2.12",
			},
			TreeItem{
				Key:   "barfoo",
				Value: nil,
			},
		},
		TreeBranch{
			TreeItem{
				Key:   "foo",
				Value: "bar",
			},
			TreeItem{
				Key: "baz",
				Value: TreeBranch{
					TreeItem{
						Key:   "bar",
						Value: "6",
					},
				},
			},
		},
		TreeBranch{
			TreeItem{
				Key:   "foo3",
				Value: "bar",
			},
		},
	}
	expected := TreeBranches{
		TreeBranch{
			TreeItem{
				Key:   "foo",
				Value: "a",
			},
			TreeItem{
				Key: "baz",
				Value: TreeBranch{
					TreeItem{
						Key:   "bar",
						Value: "a",
					},
				},
			},
			TreeItem{
				Key:   "bar",
				Value: "a",
			},
			TreeItem{
				Key:   "foobar",
				Value: "a",
			},
			TreeItem{
				Key:   "barfoo",
				Value: nil,
			},
		},
		TreeBranch{
			TreeItem{
				Key:   "foo",
				Value: "a",
			},
			TreeItem{
				Key: "baz",
				Value: TreeBranch{
					TreeItem{
						Key:   "bar",
						Value: "a",
					},
				},
			},
		},
		TreeBranch{
			TreeItem{
				Key:   "foo3",
				Value: "a",
			},
		},
	}
	tree := Tree{Branches: branches, Metadata: Metadata{UnencryptedSuffix: DefaultUnencryptedSuffix}}
	tree.Decrypt(bytes.Repeat([]byte{'f'}, 32), MockCipher{})
	if !reflect.DeepEqual(tree.Branches, expected) {
		t.Errorf("%s does not equal expected tree: %s", tree.Branches[0], expected)
	}
}

type WrongType struct{}

func TestEncryptWrongType(t *testing.T) {
	branches := TreeBranches{
		TreeBranch{
			TreeItem{
				Key:   "foo",
				Value: WrongType{},
			},
		},
	}
	tree := Tree{Branches: branches, Metadata: Metadata{UnencryptedSuffix: DefaultUnencryptedSuffix}}
	result, err := tree.Encrypt(bytes.Repeat([]byte{'f'}, 32), MockCipher{})
	assert.Equal(t, "", result)
	assert.ErrorContains(t, err, "unknown type: sops.WrongType")
}

func TestTruncateTree(t *testing.T) {
	tree := TreeBranch{
		TreeItem{
			Key:   "foo",
			Value: 2,
		},
		TreeItem{
			Key: "bar",
			Value: TreeBranch{
				TreeItem{
					Key: "foobar",
					Value: []int{
						1,
						2,
						3,
						4,
					},
				},
			},
		},
	}
	expected := 3
	result, err := tree.Truncate([]interface{}{
		"bar",
		"foobar",
		2,
	})
	assert.NoError(t, err)
	assert.Equal(t, expected, result)
}

func TestTruncateTreeNotFound(t *testing.T) {
	tree := TreeBranch{
		TreeItem{
			Key:   "foo",
			Value: 2,
		},
	}
	result, err := tree.Truncate([]interface{}{"baz"})
	assert.ErrorContains(t, err, "baz")
	assert.Nil(t, result, "Truncate result was not nil upon %s", err)
}

func TestTruncateTreeNotArray(t *testing.T) {
	tree := TreeBranch{
		TreeItem{
			Key:   "foo",
			Value: 2,
		},
	}
	result, err := tree.Truncate([]interface{}{"foo", 99})
	assert.ErrorContains(t, err, "99")
	assert.Nil(t, result, "Truncate result was not nil upon %s", err)
}

func TestTruncateTreeArrayOutOfBounds(t *testing.T) {
	tree := TreeBranch{
		TreeItem{
			Key: "foo",
			Value: []interface{}{
				"one",
				"two",
			},
		},
	}
	result, err := tree.Truncate([]interface{}{"foo", 99})
	assert.ErrorContains(t, err, "99")
	assert.Nil(t, result, "Truncate result was not nil upon %s", err)
}

// Upstream sops encrypts comments by default. This fork inverts
// that default (comments are documentation, not secrets — see the
// shouldBeEncrypted fork-policy comment) so TestEncryptComments
// and TestDecryptComments no longer apply: there is no metadata
// configuration that makes a bare comment encrypt itself, since
// EncryptedCommentRegex deliberately excludes the comment being
// processed (it's a marker for "encrypt the following items").
// The TestEncryptCommentsForkPolicy test below replaces them with
// the new contract.

func TestEncryptCommentsForkPolicy(t *testing.T) {
	tree := Tree{
		Branches: TreeBranches{
			TreeBranch{
				TreeItem{
					Key:   Comment{Value: "foo"},
					Value: nil,
				},
				TreeItem{
					Key:   "secret",
					Value: "shh",
				},
				TreeItem{
					Key: "list",
					Value: []interface{}{
						"1",
						Comment{Value: "bar"},
						"2",
					},
				},
			},
		},
		// Default policy: no comment-related metadata set.
		Metadata: Metadata{},
	}
	tree.Encrypt(bytes.Repeat([]byte{'f'}, 32), reverseCipher{})
	// Comments stay as Comment{} values (and stay plaintext) — when
	// encryption fires upstream, the Comment value is replaced with
	// the ciphertext string. Our fork keeps the Comment object
	// intact instead.
	assert.Equal(t, "foo", tree.Branches[0][0].Key.(Comment).Value,
		"top-level comment stays plaintext")
	listComment, ok := tree.Branches[0][2].Value.([]interface{})[1].(Comment)
	assert.True(t, ok, "in-list comment stays a Comment{} rather than the ciphertext string")
	assert.Equal(t, "bar", listComment.Value)
	// Real values still encrypt (reverseCipher reverses).
	assert.Equal(t, "hhs", tree.Branches[0][1].Value)
}

func TestDecryptUnencryptedComments(t *testing.T) {
	tree := Tree{
		Branches: TreeBranches{
			TreeBranch{
				TreeItem{
					// We use `error` to simulate an error decrypting, the fake cipher will error in this case
					Key:   Comment{Value: "error"},
					Value: nil,
				},
			},
		},
		Metadata: Metadata{},
	}
	tree.Decrypt(bytes.Repeat([]byte{'f'}, 32), reverseCipher{})
	assert.Equal(t, "error", tree.Branches[0][0].Key.(Comment).Value)
}

func TestSetNewKey(t *testing.T) {
	branch := TreeBranch{
		TreeItem{
			Key: "foo",
			Value: TreeBranch{
				TreeItem{
					Key: "bar",
					Value: TreeBranch{
						TreeItem{
							Key:   "baz",
							Value: "foobar",
						},
					},
				},
			},
		},
	}
	set, changed := branch.Set([]interface{}{"foo", "bar", "foo"}, "hello")
	assert.Equal(t, true, changed)
	assert.Equal(t, "hello", set[0].Value.(TreeBranch)[0].Value.(TreeBranch)[1].Value)
}

func TestSetNewKeyUnchanged(t *testing.T) {
	branch := TreeBranch{
		TreeItem{
			Key: "foo",
			Value: TreeBranch{
				TreeItem{
					Key: "bar",
					Value: TreeBranch{
						TreeItem{
							Key:   "baz",
							Value: "foobar",
						},
					},
				},
			},
		},
	}
	set, changed := branch.Set([]interface{}{"foo", "bar", "baz"}, "foobar")
	assert.Equal(t, false, changed)
	assert.Equal(t, "foobar", set[0].Value.(TreeBranch)[0].Value.(TreeBranch)[0].Value)
}

func TestSetNewBranch(t *testing.T) {
	branch := TreeBranch{
		TreeItem{
			Key:   "key",
			Value: "value",
		},
	}
	set, changed := branch.Set([]interface{}{"foo", "bar", "baz"}, "hello")
	assert.Equal(t, true, changed)
	assert.Equal(t, TreeBranch{
		TreeItem{
			Key:   "key",
			Value: "value",
		},
		TreeItem{
			Key: "foo",
			Value: TreeBranch{
				TreeItem{
					Key: "bar",
					Value: TreeBranch{
						TreeItem{
							Key:   "baz",
							Value: "hello",
						},
					},
				},
			},
		},
	}, set)
}

func TestSetArrayDeepNew(t *testing.T) {
	branch := TreeBranch{
		TreeItem{
			Key: "foo",
			Value: []interface{}{
				"one",
				"two",
			},
		},
	}
	set, changed := branch.Set([]interface{}{"foo", 2, "bar"}, "hello")
	assert.Equal(t, true, changed)
	assert.Equal(t, "hello", set[0].Value.([]interface{})[2].(TreeBranch)[0].Value)
}

func TestSetNewKeyDeep(t *testing.T) {
	branch := TreeBranch{
		TreeItem{
			Key:   "foo",
			Value: "bar",
		},
	}
	set, changed := branch.Set([]interface{}{"foo", "bar", "baz"}, "hello")
	assert.Equal(t, true, changed)
	assert.Equal(t, "hello", set[0].Value.(TreeBranch)[0].Value.(TreeBranch)[0].Value)
}

func TestSetNewKeyOnEmptyBranch(t *testing.T) {
	branch := TreeBranch{}
	set, changed := branch.Set([]interface{}{"foo", "bar", "baz"}, "hello")
	assert.Equal(t, true, changed)
	assert.Equal(t, "hello", set[0].Value.(TreeBranch)[0].Value.(TreeBranch)[0].Value)
}

func TestSetArray(t *testing.T) {
	branch := TreeBranch{
		TreeItem{
			Key: "foo",
			Value: []interface{}{
				"one",
				"two",
				"three",
			},
		},
	}
	set, changed := branch.Set([]interface{}{"foo", 0}, "uno")
	assert.Equal(t, true, changed)
	assert.Equal(t, "uno", set[0].Value.([]interface{})[0])
}

func TestSetArrayNew(t *testing.T) {
	branch := TreeBranch{}
	set, changed := branch.Set([]interface{}{"foo", 0, 0}, "uno")
	assert.Equal(t, true, changed)
	assert.Equal(t, "uno", set[0].Value.([]interface{})[0].([]interface{})[0])
}

func TestSetExisting(t *testing.T) {
	branch := TreeBranch{
		TreeItem{
			Key:   "foo",
			Value: "foobar",
		},
	}
	set, changed := branch.Set([]interface{}{"foo"}, "bar")
	assert.Equal(t, true, changed)
	assert.Equal(t, "bar", set[0].Value)
}

func TestSetArrayLeafNewItem(t *testing.T) {
	branch := TreeBranch{
		TreeItem{
			Key:   "array",
			Value: []interface{}{},
		},
	}
	set, changed := branch.Set([]interface{}{"array", 2}, "hello")
	assert.Equal(t, true, changed)
	assert.Equal(t, TreeBranch{
		TreeItem{
			Key: "array",
			Value: []interface{}{
				"hello",
			},
		},
	}, set)
}

func TestSetArrayNonLeaf(t *testing.T) {
	branch := TreeBranch{
		TreeItem{
			Key: "array",
			Value: []interface{}{
				1,
			},
		},
	}
	set, changed := branch.Set([]interface{}{"array", 0, "hello"}, "hello")
	assert.Equal(t, true, changed)
	assert.Equal(t, TreeBranch{
		TreeItem{
			Key: "array",
			Value: []interface{}{
				TreeBranch{
					TreeItem{
						Key:   "hello",
						Value: "hello",
					},
				},
			},
		},
	}, set)
}

func TestUnsetKeyRootLeaf(t *testing.T) {
	branch := TreeBranch{
		TreeItem{
			Key:   "foo",
			Value: "foo",
		},
		TreeItem{
			Key:   "foofoo",
			Value: "foofoo",
		},
	}
	unset, err := branch.Unset([]interface{}{"foofoo"})
	assert.NoError(t, err)
	assert.Equal(t, TreeBranch{
		TreeItem{
			Key:   "foo",
			Value: "foo",
		},
	}, unset)
}

func TestUnsetKeyBranchLeaf(t *testing.T) {
	branch := TreeBranch{
		TreeItem{
			Key: "foo",
			Value: TreeBranch{
				TreeItem{
					Key:   "bar",
					Value: "bar",
				},
				TreeItem{
					Key:   "barbar",
					Value: "barbar",
				},
			},
		},
	}
	unset, err := branch.Unset([]interface{}{"foo", "barbar"})
	assert.NoError(t, err)
	assert.Equal(t, TreeBranch{
		TreeItem{
			Key: "foo",
			Value: TreeBranch{
				TreeItem{
					Key:   "bar",
					Value: "bar",
				},
			},
		},
	}, unset)
}

func TestUnsetKeyBranch(t *testing.T) {
	branch := TreeBranch{
		TreeItem{
			Key:   "foo",
			Value: "foo",
		},
		TreeItem{
			Key: "foofoo",
			Value: TreeBranch{
				TreeItem{
					Key:   "bar",
					Value: "bar",
				},
			},
		},
	}
	unset, err := branch.Unset([]interface{}{"foofoo"})
	assert.NoError(t, err)
	assert.Equal(t, TreeBranch{
		TreeItem{
			Key:   "foo",
			Value: "foo",
		},
	}, unset)
}

func TestUnsetKeyRootLastLeaf(t *testing.T) {
	branch := TreeBranch{
		TreeItem{
			Key:   "foo",
			Value: "foo",
		},
	}
	unset, err := branch.Unset([]interface{}{"foo"})
	assert.NoError(t, err)
	assert.Equal(t, TreeBranch{}, unset)
}

func TestUnsetKeyBranchLastLeaf(t *testing.T) {
	branch := TreeBranch{
		TreeItem{
			Key: "foo",
			Value: TreeBranch{
				TreeItem{
					Key:   "bar",
					Value: "bar",
				},
			},
		},
	}
	unset, err := branch.Unset([]interface{}{"foo", "bar"})
	assert.NoError(t, err)
	assert.Equal(t, TreeBranch{
		TreeItem{
			Key:   "foo",
			Value: TreeBranch{},
		},
	}, unset)
}

func TestUnsetKeyArray(t *testing.T) {
	branch := TreeBranch{
		TreeItem{
			Key: "foo",
			Value: TreeBranch{
				TreeItem{
					Key: "bar",
					Value: []interface{}{
						TreeBranch{
							TreeItem{
								Key:   "baz",
								Value: "baz",
							},
						},
					},
				},
			},
		},
	}
	unset, err := branch.Unset([]interface{}{"foo", "bar"})
	assert.NoError(t, err)
	assert.Equal(t, TreeBranch{
		TreeItem{
			Key:   "foo",
			Value: TreeBranch{},
		},
	}, unset)
}

func TestUnsetArrayItem(t *testing.T) {
	branch := TreeBranch{
		TreeItem{
			Key: "foo",
			Value: []interface{}{
				TreeBranch{
					TreeItem{
						Key:   "bar",
						Value: "bar",
					},
				},
				TreeBranch{
					TreeItem{
						Key:   "barbar",
						Value: "barbar",
					},
				},
			},
		},
	}
	unset, err := branch.Unset([]interface{}{"foo", 1})
	assert.NoError(t, err)
	assert.Equal(t, TreeBranch{
		TreeItem{
			Key: "foo",
			Value: []interface{}{
				TreeBranch{
					TreeItem{
						Key:   "bar",
						Value: "bar",
					},
				},
			},
		},
	}, unset)
}

func TestUnsetKeyInArrayItem(t *testing.T) {
	branch := TreeBranch{
		TreeItem{
			Key: "foo",
			Value: []interface{}{
				TreeBranch{
					TreeItem{
						Key:   "bar",
						Value: "bar",
					},
					TreeItem{
						Key:   "barbar",
						Value: "barbar",
					},
				},
			},
		},
	}
	unset, err := branch.Unset([]interface{}{"foo", 0, "barbar"})
	assert.NoError(t, err)
	assert.Equal(t, TreeBranch{
		TreeItem{
			Key: "foo",
			Value: []interface{}{
				TreeBranch{
					TreeItem{
						Key:   "bar",
						Value: "bar",
					},
				},
			},
		},
	}, unset)
}

func TestUnsetArrayLastItem(t *testing.T) {
	branch := TreeBranch{
		TreeItem{
			Key: "foo",
			Value: []interface{}{
				TreeBranch{
					TreeItem{
						Key:   "bar",
						Value: "bar",
					},
				},
			},
		},
	}
	unset, err := branch.Unset([]interface{}{"foo", 0})
	assert.NoError(t, err)
	assert.Equal(t, TreeBranch{
		TreeItem{
			Key:   "foo",
			Value: []interface{}{},
		},
	}, unset)
}

func TestUnsetKeyNotFound(t *testing.T) {
	branch := TreeBranch{
		TreeItem{
			Key: "foo",
			Value: TreeBranch{
				TreeItem{
					Key:   "bar",
					Value: "bar",
				},
			},
		},
	}
	unset, err := branch.Unset([]interface{}{"foo", "unknown-value"})
	assert.Equal(t, err.(*SopsKeyNotFound).Key, "unknown-value")
	assert.ErrorContains(t, err, "unknown-value")
	assert.Nil(t, unset, "Unset result was not nil upon %s", err)
}

func TestUnsetKeyInArrayNotFound(t *testing.T) {
	branch := TreeBranch{
		TreeItem{
			Key: "foo",
			Value: []interface{}{
				TreeBranch{
					TreeItem{
						Key:   "bar",
						Value: "bar",
					},
				},
			},
		},
	}
	unset, err := branch.Unset([]interface{}{"foo", 0, "unknown"})
	assert.Equal(t, err.(*SopsKeyNotFound).Key, "unknown")
	assert.Nil(t, unset, "Unset result was not nil upon %s", err)
}

func TestUnsetArrayItemOutOfBounds(t *testing.T) {
	branch := TreeBranch{
		TreeItem{
			Key: "foo",
			Value: []interface{}{
				TreeBranch{
					TreeItem{
						Key:   "bar",
						Value: "bar",
					},
				},
			},
		},
	}
	unset, err := branch.Unset([]interface{}{"foo", 99})
	assert.Equal(t, err.(*SopsKeyNotFound).Key, 99)
	assert.Nil(t, unset, "Unset result was not nil upon %s", err)
}

func TestUnsetKeyNotABranch(t *testing.T) {
	branch := TreeBranch{
		TreeItem{
			Key:   "foo",
			Value: 99,
		},
	}
	unset, err := branch.Unset([]interface{}{"foo", "bar"})
	assert.ErrorContains(t, err, "Unsupported type")
	assert.Nil(t, unset, "Unset result was not nil upon %s", err)
}

func TestEmitAsMap(t *testing.T) {
	expected := map[string]interface{}{
		"foobar": "barfoo",
		"number": 42,
		"foo": map[string]interface{}{
			"bar": map[string]interface{}{
				"baz": "foobar",
			},
		},
	}
	branches := TreeBranches{
		TreeBranch{
			TreeItem{
				Key:   "foobar",
				Value: "barfoo",
			},
			TreeItem{
				Key:   "number",
				Value: 42,
			},
			TreeItem{
				Key:   Comment{Value: "comment"},
				Value: nil,
			},
		},
		TreeBranch{
			TreeItem{
				Key: "foo",
				Value: TreeBranch{
					TreeItem{
						Key: "bar",
						Value: TreeBranch{
							TreeItem{
								Key:   "baz",
								Value: "foobar",
							},
						},
					},
				},
			},
		},
	}

	data, err := EmitAsMap(branches)

	assert.NoError(t, err)
	assert.Equal(t, expected, data)
}

func TestSortKeyGroupIndices(t *testing.T) {
	t.Run("default order", func(t *testing.T) {
		group := KeyGroup{&hcvault.MasterKey{}, &age.MasterKey{}, &pgp.MasterKey{}}
		expected := []int{1, 2, 0}
		indices := sortKeyGroupIndices(group, DefaultDecryptionOrder)
		assert.Equal(t, expected, indices)
	})

	t.Run("different keygroup", func(t *testing.T) {
		group := KeyGroup{&hcvault.MasterKey{}, &pgp.MasterKey{}, &age.MasterKey{}}
		expected := []int{2, 1, 0}
		indices := sortKeyGroupIndices(group, DefaultDecryptionOrder)
		assert.Equal(t, expected, indices)
	})

	t.Run("repeated key", func(t *testing.T) {
		group := KeyGroup{&pgp.MasterKey{}, &hcvault.MasterKey{}, &pgp.MasterKey{}, &age.MasterKey{}}
		expected := []int{3, 0, 2, 1}
		indices := sortKeyGroupIndices(group, DefaultDecryptionOrder)
		assert.Equal(t, expected, indices)
	})

	t.Run("full order", func(t *testing.T) {
		group := KeyGroup{&hcvault.MasterKey{}, &pgp.MasterKey{}, &age.MasterKey{}}
		expected := []int{1, 2, 0}
		indices := sortKeyGroupIndices(group, []string{"pgp", "age", "hc_vault"})
		assert.Equal(t, expected, indices)
	})

	t.Run("empty order", func(t *testing.T) {
		group := KeyGroup{&hcvault.MasterKey{}, &pgp.MasterKey{}, &age.MasterKey{}}
		expected := []int{0, 1, 2}
		indices := sortKeyGroupIndices(group, []string{})
		assert.Equal(t, expected, indices)
	})

	t.Run("one match", func(t *testing.T) {
		group := KeyGroup{&hcvault.MasterKey{}, &pgp.MasterKey{}, &age.MasterKey{}}
		expected := []int{2, 0, 1}
		indices := sortKeyGroupIndices(group, []string{"azure_kv", "age"})
		assert.Equal(t, expected, indices)
	})

	t.Run("nonmatching order", func(t *testing.T) {
		group := KeyGroup{&pgp.MasterKey{}, &hcvault.MasterKey{}, &age.MasterKey{}}
		expected := []int{0, 1, 2}
		indices := sortKeyGroupIndices(group, []string{"azure_kv"})
		assert.Equal(t, expected, indices)
	})

	t.Run("nonexistent keys", func(t *testing.T) {
		group := KeyGroup{&hcvault.MasterKey{}, &pgp.MasterKey{}, &age.MasterKey{}}
		expected := []int{2, 1, 0}
		indices := sortKeyGroupIndices(group, []string{"dummy1", "age", "dummy2", "pgp", "dummy3"})
		assert.Equal(t, expected, indices)
	})
}

func TestParseDirective(t *testing.T) {
	cases := map[string]Directive{
		"sops:unencrypted":      DirectiveUnencrypted,
		" sops:unencrypted":     DirectiveUnencrypted, // leading space (typical: "# sops:unencrypted" -> " sops:unencrypted")
		"  SOPS:UNENCRYPTED  ":  DirectiveUnencrypted, // case + trailing space
		"sops:encrypted":        DirectiveEncrypted,
		" sops:encrypted":       DirectiveEncrypted,
		"sopsunencrypted":       DirectiveNone, // missing colon
		"a sops:unencrypted":    DirectiveNone, // not at start of trimmed text
		"sops:unencrypted x":    DirectiveNone, // extra trailing tokens not allowed
		"":                      DirectiveNone,
		"just a regular comment": DirectiveNone,
	}
	for input, expected := range cases {
		t.Run(input, func(t *testing.T) {
			assert.Equal(t, expected, ParseDirective(input))
		})
	}
}

// TestDirectiveUnencryptedScalar verifies that a `# sops:unencrypted` directive
// before a scalar leaves that scalar in plaintext while neighbouring keys are
// still encrypted.
func TestDirectiveUnencryptedScalar(t *testing.T) {
	branches := TreeBranches{
		TreeBranch{
			TreeItem{Key: "encrypted_one", Value: "secret1"},
			TreeItem{Key: Comment{Value: " sops:unencrypted"}, Value: nil},
			TreeItem{Key: "plain", Value: "visible"},
			TreeItem{Key: "encrypted_two", Value: "secret2"},
		},
	}
	tree := Tree{Branches: branches, Metadata: Metadata{}}
	cipher := reverseCipher{}
	_, err := tree.Encrypt(bytes.Repeat([]byte("f"), 32), cipher)
	assert.NoError(t, err)

	got := tree.Branches[0]
	assert.Equal(t, reverse("secret1"), got[0].Value, "encrypted_one should be encrypted")
	// The directive comment itself remains plaintext.
	assert.Equal(t, " sops:unencrypted", got[1].Key.(Comment).Value)
	// `plain` follows the directive and stays in clear text.
	assert.Equal(t, "visible", got[2].Value, "plain should NOT be encrypted")
	// The directive only applies to the next item; siblings after `plain` get encrypted.
	assert.Equal(t, reverse("secret2"), got[3].Value, "encrypted_two should be encrypted")
}

// TestDirectiveUnencryptedSubtree verifies that a directive on a block-valued
// key applies to every leaf inside that block.
func TestDirectiveUnencryptedSubtree(t *testing.T) {
	branches := TreeBranches{
		TreeBranch{
			TreeItem{Key: Comment{Value: " sops:unencrypted"}, Value: nil},
			TreeItem{
				Key: "config",
				Value: TreeBranch{
					TreeItem{Key: "host", Value: "example.com"},
					TreeItem{Key: "port", Value: "8080"},
					TreeItem{Key: "tags", Value: []interface{}{"a", "b"}},
				},
			},
			TreeItem{Key: "secret", Value: "still-encrypted"},
		},
	}
	tree := Tree{Branches: branches, Metadata: Metadata{}}
	cipher := reverseCipher{}
	_, err := tree.Encrypt(bytes.Repeat([]byte("f"), 32), cipher)
	assert.NoError(t, err)

	got := tree.Branches[0]
	cfg := got[1].Value.(TreeBranch)
	assert.Equal(t, "example.com", cfg[0].Value, "config.host should be unencrypted")
	assert.Equal(t, "8080", cfg[1].Value, "config.port should be unencrypted")
	assert.Equal(t, []interface{}{"a", "b"}, cfg[2].Value, "config.tags should be unencrypted")
	assert.Equal(t, reverse("still-encrypted"), got[2].Value, "sibling secret should still encrypt")
}

// TestDirectiveEncryptedOverridesUnencryptedSuffix verifies that a directive
// can force encryption of an item that the suffix rule would otherwise leave
// in plaintext.
func TestDirectiveEncryptedOverridesUnencryptedSuffix(t *testing.T) {
	branches := TreeBranches{
		TreeBranch{
			TreeItem{Key: "regular_unencrypted", Value: "implied-by-suffix"},
			TreeItem{Key: Comment{Value: " sops:encrypted"}, Value: nil},
			TreeItem{Key: "secret_unencrypted", Value: "directive-overrides"},
		},
	}
	tree := Tree{
		Branches: branches,
		Metadata: Metadata{UnencryptedSuffix: DefaultUnencryptedSuffix},
	}
	cipher := reverseCipher{}
	_, err := tree.Encrypt(bytes.Repeat([]byte("f"), 32), cipher)
	assert.NoError(t, err)

	got := tree.Branches[0]
	assert.Equal(t, "implied-by-suffix", got[0].Value, "suffix wins for items without a directive")
	assert.Equal(t, reverse("directive-overrides"), got[2].Value, "directive overrides suffix")
}

// TestDirectiveRoundTrip verifies that an encrypt → decrypt round-trip yields
// the original tree, including the directive comments themselves.
func TestDirectiveRoundTrip(t *testing.T) {
	original := func() TreeBranch {
		return TreeBranch{
			TreeItem{Key: "encrypted_field", Value: "secret"},
			TreeItem{Key: Comment{Value: " sops:unencrypted"}, Value: nil},
			TreeItem{Key: "plain_field", Value: "visible"},
		}
	}
	branches := TreeBranches{original()}
	tree := Tree{Branches: branches, Metadata: Metadata{}}
	key := bytes.Repeat([]byte("f"), 32)
	cipher := reverseCipher{}

	macEnc, err := tree.Encrypt(key, cipher)
	assert.NoError(t, err)

	macDec, err := tree.Decrypt(key, cipher)
	assert.NoError(t, err)
	assert.Equal(t, macEnc, macDec, "MAC must match across encrypt/decrypt")

	assert.True(t, reflect.DeepEqual(tree.Branches[0], original()),
		"round-trip mismatch:\n got:      %+v\n expected: %+v",
		tree.Branches[0], original())
}

// TestDirectiveDoesNotLeakToSiblings verifies that a directive only applies to
// the immediately following non-comment item, not to siblings beyond it.
func TestDirectiveDoesNotLeakToSiblings(t *testing.T) {
	branches := TreeBranches{
		TreeBranch{
			TreeItem{Key: Comment{Value: " sops:unencrypted"}, Value: nil},
			TreeItem{Key: "plain", Value: "visible"},
			TreeItem{Key: "secret", Value: "should-be-encrypted"},
		},
	}
	tree := Tree{Branches: branches, Metadata: Metadata{}}
	_, err := tree.Encrypt(bytes.Repeat([]byte("f"), 32), reverseCipher{})
	assert.NoError(t, err)

	got := tree.Branches[0]
	assert.Equal(t, "visible", got[1].Value, "directive applies to next item")
	assert.Equal(t, reverse("should-be-encrypted"), got[2].Value, "directive does NOT leak to siblings")
}

// TestDirectiveInnermostWins verifies that a directive on a child overrides a
// directive at an outer level.
func TestDirectiveInnermostWins(t *testing.T) {
	branches := TreeBranches{
		TreeBranch{
			TreeItem{Key: Comment{Value: " sops:unencrypted"}, Value: nil},
			TreeItem{
				Key: "outer",
				Value: TreeBranch{
					TreeItem{Key: "inherited_plain", Value: "stays-plain"},
					TreeItem{Key: Comment{Value: " sops:encrypted"}, Value: nil},
					TreeItem{Key: "forced_encrypted", Value: "now-encrypted"},
				},
			},
		},
	}
	tree := Tree{Branches: branches, Metadata: Metadata{}}
	_, err := tree.Encrypt(bytes.Repeat([]byte("f"), 32), reverseCipher{})
	assert.NoError(t, err)

	outer := tree.Branches[0][1].Value.(TreeBranch)
	assert.Equal(t, "stays-plain", outer[0].Value,
		"item inheriting outer unencrypted directive stays plain")
	assert.Equal(t, reverse("now-encrypted"), outer[2].Value,
		"inner encrypted directive overrides outer unencrypted")
}

// TestDirectiveMACChangesWithMACOnlyEncrypted ensures the MAC remains coherent
// when a directive flips the encrypt decision under MACOnlyEncrypted.
func TestDirectiveMACOnlyEncrypted(t *testing.T) {
	build := func() Tree {
		return Tree{
			Branches: TreeBranches{
				TreeBranch{
					TreeItem{Key: "a", Value: "encrypted-value"},
					TreeItem{Key: Comment{Value: " sops:unencrypted"}, Value: nil},
					TreeItem{Key: "b", Value: "plain-value"},
				},
			},
			Metadata: Metadata{MACOnlyEncrypted: true},
		}
	}
	key := bytes.Repeat([]byte("f"), 32)
	cipher := reverseCipher{}

	enc := build()
	macEnc, err := enc.Encrypt(key, cipher)
	assert.NoError(t, err)
	macDec, err := enc.Decrypt(key, cipher)
	assert.NoError(t, err)
	assert.Equal(t, macEnc, macDec, "MAC stable across encrypt/decrypt under MACOnlyEncrypted")
}
