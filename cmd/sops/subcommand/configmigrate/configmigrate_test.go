package configmigrate

import (
	"strings"
	"testing"

	"github.com/trendvidia/protowire-go/encoding/pxf"
	configpb "github.com/trendvidia/sops/v4/config/configpb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func convert(t *testing.T, yaml string) (*configpb.ConfigFile, []string) {
	t.Helper()
	out, warnings, err := ConvertYAML([]byte(yaml))
	require.NoError(t, err)
	var pb configpb.ConfigFile
	require.NoError(t, pxf.Unmarshal(out, &pb), "produced PXF must parse")
	return &pb, warnings
}

func TestConvertScalarAndCSVKeyFields(t *testing.T) {
	pb, warnings := convert(t, `
creation_rules:
  - path_regex: foobar*
    kms: "arn1,arn2"
    pgp: single-fp
    age:
      - age1aaa
      - age1bbb
`)
	assert.Empty(t, warnings)
	require.Len(t, pb.CreationRules, 1)
	r := pb.CreationRules[0]
	assert.Equal(t, "foobar*", r.GetPathRegex())
	assert.Equal(t, []string{"arn1", "arn2"}, r.GetKms())
	assert.Equal(t, []string{"single-fp"}, r.GetPgp())
	assert.Equal(t, []string{"age1aaa", "age1bbb"}, r.GetAge())
}

func TestConvertKeyGroupsAndDestinationRules(t *testing.T) {
	pb, warnings := convert(t, `
creation_rules:
  - path_regex: ""
    key_groups:
      - kms:
          - arn: foo
            role: myrole
            aws_profile: bar
            context:
              baz: bam
        pgp:
          - fp1
        gcp_kms:
          - resource_id: rid
        azure_keyvault:
          - vaultUrl: https://foo.vault.azure.net
            key: foo-key
            version: v1
        hc_vault:
          - https://vault/keys/x
        merge:
          - pgp:
              - fp2
destination_rules:
  - s3_bucket: bucket
    s3_prefix: pre/
    path_regex: s3/*
    recreation_rule:
      pgp: newpgp
`)
	assert.Empty(t, warnings)

	require.Len(t, pb.CreationRules, 1)
	kg := pb.CreationRules[0].GetKeyGroups()
	require.Len(t, kg, 1)
	require.Len(t, kg[0].GetKms(), 1)
	assert.Equal(t, "foo", kg[0].GetKms()[0].GetArn())
	assert.Equal(t, "myrole", kg[0].GetKms()[0].GetRole())
	assert.Equal(t, map[string]string{"baz": "bam"}, kg[0].GetKms()[0].GetContext())
	assert.Equal(t, []string{"fp1"}, kg[0].GetPgp())
	assert.Equal(t, "rid", kg[0].GetGcpKms()[0].GetResourceId())
	assert.Equal(t, "https://foo.vault.azure.net", kg[0].GetAzureKeyvault()[0].GetVaultUrl())
	assert.Equal(t, []string{"https://vault/keys/x"}, kg[0].GetHcVault())
	require.Len(t, kg[0].GetMerge(), 1)
	assert.Equal(t, []string{"fp2"}, kg[0].GetMerge()[0].GetPgp())

	require.Len(t, pb.DestinationRules, 1)
	d := pb.DestinationRules[0]
	assert.Equal(t, "bucket", d.GetS3Bucket())
	assert.Equal(t, "s3/*", d.GetPathRegex())
	require.NotNil(t, d.GetRecreationRule())
	assert.Equal(t, []string{"newpgp"}, d.GetRecreationRule().GetPgp())
}

func TestConvertStoresIndent(t *testing.T) {
	pb, _ := convert(t, `
stores:
  json:
    indent: 2
  json_binary:
    indent: 0
`)
	require.NotNil(t, pb.GetStores())
	require.NotNil(t, pb.GetStores().GetJson())
	assert.Equal(t, int32(2), pb.GetStores().GetJson().GetIndent())
	// indent: 0 must survive as an explicit 0, not be dropped.
	require.NotNil(t, pb.GetStores().GetJsonBinary())
	assert.NotNil(t, pb.GetStores().GetJsonBinary().Indent)
	assert.Equal(t, int32(0), pb.GetStores().GetJsonBinary().GetIndent())
	// yaml indent was not set: leave it unset.
	assert.Nil(t, pb.GetStores().GetYaml())
}

func TestConvertWarnsOnIgnoredFields(t *testing.T) {
	// hc_vault_uris and reencryption_rule were silently ignored by the
	// YAML loader (they are not real fields). The migration must warn.
	_, warnings := convert(t, `
creation_rules:
  - path_regex: foobar*
    pgp: fp1
    hc_vault_uris: "http://vault/keys/x"
destination_rules:
  - s3_bucket: bucket
    path_regex: s3/*
    reencryption_rule:
      pgp: newpgp
`)
	joined := strings.Join(warnings, "\n")
	assert.Contains(t, joined, "hc_vault_uris")
	assert.Contains(t, joined, "reencryption_rule")
	// The internal Go type name must not leak into user-facing warnings.
	assert.NotContains(t, joined, "yaml")
	assert.NotContains(t, joined, "configmigrate")
}

func TestConvertEmptyConfig(t *testing.T) {
	pb, warnings := convert(t, ``)
	assert.Empty(t, warnings)
	assert.Empty(t, pb.GetCreationRules())
	assert.Empty(t, pb.GetDestinationRules())
	assert.Nil(t, pb.GetStores())
}

func TestConvertMalformedYAMLErrors(t *testing.T) {
	_, _, err := ConvertYAML([]byte("creation_rules: [this is: not valid"))
	assert.Error(t, err)
}
