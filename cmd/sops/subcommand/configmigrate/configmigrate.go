// Package configmigrate converts a legacy YAML sops configuration file
// (.sops.yaml / .sops.yml) into the current PXF format (.sops.pxf).
//
// It carries its own copy of the frozen legacy YAML schema so that the
// config package proper does not have to keep any YAML-parsing code
// around after the migration to PXF.
package configmigrate

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/trendvidia/protowire-go/encoding/pxf"
	configpb "github.com/trendvidia/sops/v4/config/configpb"
	"go.yaml.in/yaml/v3"
)

// ConvertYAML parses data as a legacy YAML sops config and returns the
// equivalent PXF-encoded config. It also returns a list of human-readable
// warnings for keys that the legacy YAML loader silently ignored (for
// example the historical typos hc_vault_uris and reencryption_rule),
// which would otherwise be dropped without a trace.
func ConvertYAML(data []byte) (pxfBytes []byte, warnings []string, err error) {
	// First pass: strict decode to surface fields that are not part of
	// the schema. These never did anything under YAML; flag them so the
	// user can fix or drop them rather than assume they were honored.
	var probe yamlConfig
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if derr := dec.Decode(&probe); derr != nil {
		if te, ok := derr.(*yaml.TypeError); ok {
			warnings = unknownFieldWarnings(te.Errors)
		}
		// Non-TypeError problems (malformed YAML) are reported by the
		// lenient pass below, which returns the actual parse error.
	}

	// Second pass: lenient decode used for the actual conversion.
	var cfg yamlConfig
	if derr := yaml.Unmarshal(data, &cfg); derr != nil {
		return nil, warnings, fmt.Errorf("could not parse YAML config: %w", derr)
	}

	out, err := pxf.Marshal(cfg.toProto())
	if err != nil {
		return nil, warnings, fmt.Errorf("could not encode PXF config: %w", err)
	}
	return out, warnings, nil
}

// unknownFieldWarnings keeps only the "field X not found" messages from a
// yaml.TypeError and rewrites them without the internal Go type name.
func unknownFieldWarnings(errs []string) []string {
	var out []string
	for _, e := range errs {
		if i := strings.Index(e, " not found in type "); i >= 0 {
			out = append(out, e[:i]+" is not a recognized config field and was ignored")
		}
	}
	return out
}

// ---- Frozen legacy YAML schema ----

type yamlConfig struct {
	CreationRules    []yamlCreationRule    `yaml:"creation_rules"`
	DestinationRules []yamlDestinationRule `yaml:"destination_rules"`
	Stores           *yamlStores           `yaml:"stores"`
}

type yamlStores struct {
	Dotenv     *struct{}   `yaml:"dotenv"`
	INI        *struct{}   `yaml:"ini"`
	JSONBinary *yamlIndent `yaml:"json_binary"`
	JSON       *yamlIndent `yaml:"json"`
	YAML       *yamlIndent `yaml:"yaml"`
	Protowire  *struct{}   `yaml:"protowire"`
}

type yamlIndent struct {
	Indent *int `yaml:"indent"`
}

type yamlCreationRule struct {
	PathRegex               string         `yaml:"path_regex"`
	KMS                     interface{}    `yaml:"kms"`
	AwsProfile              string         `yaml:"aws_profile"`
	Age                     interface{}    `yaml:"age"`
	PGP                     interface{}    `yaml:"pgp"`
	GCPKMS                  interface{}    `yaml:"gcp_kms"`
	HCKms                   interface{}    `yaml:"hckms"`
	AzureKeyVault           interface{}    `yaml:"azure_keyvault"`
	VaultURI                interface{}    `yaml:"hc_vault_transit_uri"`
	KeyGroups               []yamlKeyGroup `yaml:"key_groups"`
	ShamirThreshold         int            `yaml:"shamir_threshold"`
	UnencryptedSuffix       string         `yaml:"unencrypted_suffix"`
	EncryptedSuffix         string         `yaml:"encrypted_suffix"`
	UnencryptedRegex        string         `yaml:"unencrypted_regex"`
	EncryptedRegex          string         `yaml:"encrypted_regex"`
	UnencryptedCommentRegex string         `yaml:"unencrypted_comment_regex"`
	EncryptedCommentRegex   string         `yaml:"encrypted_comment_regex"`
	MACOnlyEncrypted        bool           `yaml:"mac_only_encrypted"`
}

type yamlKeyGroup struct {
	Merge   []yamlKeyGroup `yaml:"merge"`
	KMS     []yamlKMSKey   `yaml:"kms"`
	GCPKMS  []yamlGCPKey   `yaml:"gcp_kms"`
	HCKms   []yamlHCKMSKey `yaml:"hckms"`
	AzureKV []yamlAzureKey `yaml:"azure_keyvault"`
	Vault   []string       `yaml:"hc_vault"`
	Age     []string       `yaml:"age"`
	PGP     []string       `yaml:"pgp"`
}

type yamlKMSKey struct {
	Arn        string            `yaml:"arn"`
	Role       string            `yaml:"role"`
	Context    map[string]string `yaml:"context"`
	AwsProfile string            `yaml:"aws_profile"`
}

type yamlGCPKey struct {
	ResourceID string `yaml:"resource_id"`
}

type yamlAzureKey struct {
	VaultURL string `yaml:"vaultUrl"`
	Key      string `yaml:"key"`
	Version  string `yaml:"version"`
}

type yamlHCKMSKey struct {
	KeyID string `yaml:"key_id"`
}

type yamlDestinationRule struct {
	PathRegex        string            `yaml:"path_regex"`
	S3Bucket         string            `yaml:"s3_bucket"`
	S3Prefix         string            `yaml:"s3_prefix"`
	GCSBucket        string            `yaml:"gcs_bucket"`
	GCSPrefix        string            `yaml:"gcs_prefix"`
	VaultPath        string            `yaml:"vault_path"`
	VaultAddress     string            `yaml:"vault_address"`
	VaultKVMountName string            `yaml:"vault_kv_mount_name"`
	VaultKVVersion   int               `yaml:"vault_kv_version"`
	RecreationRule   *yamlCreationRule `yaml:"recreation_rule"`
	OmitExtensions   bool              `yaml:"omit_extensions"`
}

// ---- Legacy YAML -> proto ----

func (c yamlConfig) toProto() *configpb.ConfigFile {
	pb := &configpb.ConfigFile{}
	for _, r := range c.CreationRules {
		pb.CreationRules = append(pb.CreationRules, r.toProto())
	}
	for _, d := range c.DestinationRules {
		pb.DestinationRules = append(pb.DestinationRules, d.toProto())
	}
	pb.Stores = c.Stores.toProto()
	return pb
}

func (r yamlCreationRule) toProto() *configpb.CreationRule {
	return &configpb.CreationRule{
		PathRegex:               r.PathRegex,
		Kms:                     toList(r.KMS),
		AwsProfile:              r.AwsProfile,
		Age:                     toList(r.Age),
		Pgp:                     toList(r.PGP),
		GcpKms:                  toList(r.GCPKMS),
		Hckms:                   toList(r.HCKms),
		AzureKeyvault:           toList(r.AzureKeyVault),
		HcVaultTransitUri:       toList(r.VaultURI),
		KeyGroups:               keyGroupsToProto(r.KeyGroups),
		ShamirThreshold:         int32(r.ShamirThreshold),
		UnencryptedSuffix:       r.UnencryptedSuffix,
		EncryptedSuffix:         r.EncryptedSuffix,
		UnencryptedRegex:        r.UnencryptedRegex,
		EncryptedRegex:          r.EncryptedRegex,
		UnencryptedCommentRegex: r.UnencryptedCommentRegex,
		EncryptedCommentRegex:   r.EncryptedCommentRegex,
		MacOnlyEncrypted:        r.MACOnlyEncrypted,
	}
}

func keyGroupsToProto(groups []yamlKeyGroup) []*configpb.KeyGroup {
	var out []*configpb.KeyGroup
	for _, g := range groups {
		out = append(out, g.toProto())
	}
	return out
}

func (g yamlKeyGroup) toProto() *configpb.KeyGroup {
	pb := &configpb.KeyGroup{
		Merge:   keyGroupsToProto(g.Merge),
		HcVault: g.Vault,
		Age:     g.Age,
		Pgp:     g.PGP,
	}
	for _, k := range g.KMS {
		pb.Kms = append(pb.Kms, &configpb.KmsKey{
			Arn:        k.Arn,
			Role:       k.Role,
			Context:    k.Context,
			AwsProfile: k.AwsProfile,
		})
	}
	for _, k := range g.GCPKMS {
		pb.GcpKms = append(pb.GcpKms, &configpb.GcpKmsKey{ResourceId: k.ResourceID})
	}
	for _, k := range g.HCKms {
		pb.Hckms = append(pb.Hckms, &configpb.HcKmsKey{KeyId: k.KeyID})
	}
	for _, k := range g.AzureKV {
		pb.AzureKeyvault = append(pb.AzureKeyvault, &configpb.AzureKvKey{
			VaultUrl: k.VaultURL,
			Key:      k.Key,
			Version:  k.Version,
		})
	}
	return pb
}

func (d yamlDestinationRule) toProto() *configpb.DestinationRule {
	pb := &configpb.DestinationRule{
		PathRegex:        d.PathRegex,
		S3Bucket:         d.S3Bucket,
		S3Prefix:         d.S3Prefix,
		GcsBucket:        d.GCSBucket,
		GcsPrefix:        d.GCSPrefix,
		VaultPath:        d.VaultPath,
		VaultAddress:     d.VaultAddress,
		VaultKvMountName: d.VaultKVMountName,
		VaultKvVersion:   int32(d.VaultKVVersion),
		OmitExtensions:   d.OmitExtensions,
	}
	if d.RecreationRule != nil {
		pb.RecreationRule = d.RecreationRule.toProto()
	}
	return pb
}

func (s *yamlStores) toProto() *configpb.StoresConfig {
	if s == nil {
		return nil
	}
	pb := &configpb.StoresConfig{}
	set := false
	if s.JSON != nil && s.JSON.Indent != nil {
		pb.Json = &configpb.JsonStoreConfig{Indent: int32Ptr(*s.JSON.Indent)}
		set = true
	}
	if s.JSONBinary != nil && s.JSONBinary.Indent != nil {
		pb.JsonBinary = &configpb.JsonBinaryStoreConfig{Indent: int32Ptr(*s.JSONBinary.Indent)}
		set = true
	}
	if s.YAML != nil && s.YAML.Indent != nil {
		pb.Yaml = &configpb.YamlStoreConfig{Indent: int32Ptr(*s.YAML.Indent)}
		set = true
	}
	if !set {
		return nil
	}
	return pb
}

// toList normalizes the legacy "scalar (optionally comma-separated), or
// list of strings" key-field shorthand into a plain list.
func toList(field interface{}) []string {
	switch v := field.(type) {
	case nil:
		return nil
	case string:
		var out []string
		for _, part := range strings.Split(v, ",") {
			if t := strings.TrimSpace(part); t != "" {
				out = append(out, t)
			}
		}
		return out
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, item := range v {
			out = append(out, fmt.Sprintf("%v", item))
		}
		return out
	case []string:
		return v
	default:
		return nil
	}
}

func int32Ptr(i int) *int32 {
	v := int32(i)
	return &v
}
