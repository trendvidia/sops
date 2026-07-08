/*
Package config provides a way to find and load SOPS configuration files
*/
package config //import "github.com/trendvidia/sops/v4/config"

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/trendvidia/protowire-go/encoding/pxf"
	"github.com/trendvidia/sops/v4"
	"github.com/trendvidia/sops/v4/age"
	"github.com/trendvidia/sops/v4/azkv"
	"github.com/trendvidia/sops/v4/config/configpb"
	"github.com/trendvidia/sops/v4/gcpkms"
	"github.com/trendvidia/sops/v4/hckms"
	"github.com/trendvidia/sops/v4/hcvault"
	"github.com/trendvidia/sops/v4/kms"
	"github.com/trendvidia/sops/v4/pgp"
	"github.com/trendvidia/sops/v4/publish"
)

type fileSystem interface {
	Stat(name string) (os.FileInfo, error)
}

type osFS struct {
	stat func(string) (os.FileInfo, error)
}

func (fs osFS) Stat(name string) (os.FileInfo, error) {
	return fs.stat(name)
}

var fs fileSystem = osFS{stat: os.Stat}

const (
	maxDepth       = 100
	configFileName = ".sops.pxf"
)

// legacyConfigNames are the pre-PXF (YAML) config file names. They are no
// longer loaded, but sops still looks for them so it can emit a helpful
// "please migrate to .sops.pxf" warning when it finds one.
var legacyConfigNames = []string{".sops.yaml", ".sops.yml"}

// ConfigFileResult contains the path to a config file and any warnings
type ConfigFileResult struct {
	Path    string
	Warning string
}

// LookupConfigFile looks for a sops config file in the current working directory
// and on parent directories, up to the maxDepth limit.
// It returns a result containing the file path and any warnings.
func LookupConfigFile(start string) (ConfigFileResult, error) {
	filepath := path.Dir(start)
	var foundAlternatePath string

	for i := 0; i < maxDepth; i++ {
		configPath := path.Join(filepath, configFileName)
		_, err := fs.Stat(configPath)
		if err == nil {
			result := ConfigFileResult{Path: configPath}

			if foundAlternatePath != "" {
				result.Warning = fmt.Sprintf(
					"ignoring %q when searching for config file; the config file must be called %q; using %q instead",
					foundAlternatePath, configFileName, configPath)
			}
			return result, nil
		}

		// Check for a legacy (YAML) config filename if we haven't found
		// one yet, so we can warn the user to migrate to .sops.pxf.
		if foundAlternatePath == "" {
			for _, legacyName := range legacyConfigNames {
				legacyPath := path.Join(filepath, legacyName)
				if _, altErr := fs.Stat(legacyPath); altErr == nil {
					foundAlternatePath = legacyPath
					break
				}
			}
		}

		filepath = path.Join(filepath, "..")
	}

	// No config file found
	result := ConfigFileResult{}
	if foundAlternatePath != "" {
		result.Warning = fmt.Sprintf(
			"ignoring %q when searching for config file; the config file must be called %q",
			foundAlternatePath, configFileName)
	}

	return result, fmt.Errorf("config file not found")
}

// FindConfigFile looks for a sops config file in the current working directory and on parent directories, up to the limit defined by the maxDepth constant.
func FindConfigFile(start string) (string, error) {
	result, err := LookupConfigFile(start)
	return result.Path, err
}

type DotenvStoreConfig struct{}

type INIStoreConfig struct{}

type JSONStoreConfig struct {
	Indent int
}

type JSONBinaryStoreConfig struct {
	Indent int
}

type YAMLStoreConfig struct {
	Indent int
}

type ProtowireStoreConfig struct{}

type StoresConfig struct {
	Dotenv     DotenvStoreConfig
	INI        INIStoreConfig
	JSONBinary JSONBinaryStoreConfig
	JSON       JSONStoreConfig
	YAML       YAMLStoreConfig
	Protowire  ProtowireStoreConfig
}

type configFile struct {
	CreationRules    []creationRule
	DestinationRules []destinationRule
	Stores           StoresConfig
}

type keyGroup struct {
	Merge   []keyGroup
	KMS     []kmsKey
	GCPKMS  []gcpKmsKey
	HCKms   []hckmsKey
	AzureKV []azureKVKey
	Vault   []string
	Age     []string
	PGP     []string
}

type gcpKmsKey struct {
	ResourceID string
}

type kmsKey struct {
	Arn        string
	Role       string
	Context    map[string]*string
	AwsProfile string
}

type azureKVKey struct {
	VaultURL string
	Key      string
	Version  string
}

type hckmsKey struct {
	KeyID string
}

type destinationRule struct {
	PathRegex        string
	S3Bucket         string
	S3Prefix         string
	GCSBucket        string
	GCSPrefix        string
	VaultPath        string
	VaultAddress     string
	VaultKVMountName string
	VaultKVVersion   int
	RecreationRule   creationRule
	OmitExtensions   bool
}

type creationRule struct {
	PathRegex               string
	KMS                     []string
	AwsProfile              string
	Age                     []string
	PGP                     []string
	GCPKMS                  []string
	HCKms                   []string
	AzureKeyVault           []string
	VaultURI                []string
	KeyGroups               []keyGroup
	ShamirThreshold         int
	UnencryptedSuffix       string
	EncryptedSuffix         string
	UnencryptedRegex        string
	EncryptedRegex          string
	UnencryptedCommentRegex string
	EncryptedCommentRegex   string
	MACOnlyEncrypted        bool
}

func NewStoresConfig() *StoresConfig {
	storesConfig := &StoresConfig{}
	storesConfig.JSON.Indent = -1
	storesConfig.JSONBinary.Indent = -1
	return storesConfig
}

// Load parses PXF-encoded config bytes into the temporary struct. The
// caller is expected to have pre-populated f.Stores with defaults (via
// NewStoresConfig); store options present in the PXF document override
// those defaults, while absent options are left untouched.
func (f *configFile) load(data []byte) error {
	var pb configpb.ConfigFile
	if err := pxf.Unmarshal(data, &pb); err != nil {
		return fmt.Errorf("could not unmarshal config file: %w", err)
	}
	f.CreationRules = creationRulesFromProto(pb.GetCreationRules())
	f.DestinationRules = destinationRulesFromProto(pb.GetDestinationRules())
	applyStoresConfig(&f.Stores, pb.GetStores())
	return nil
}

func creationRulesFromProto(pbRules []*configpb.CreationRule) []creationRule {
	if len(pbRules) == 0 {
		return nil
	}
	rules := make([]creationRule, len(pbRules))
	for i, r := range pbRules {
		rules[i] = creationRuleFromProto(r)
	}
	return rules
}

func creationRuleFromProto(r *configpb.CreationRule) creationRule {
	return creationRule{
		PathRegex:               r.GetPathRegex(),
		KMS:                     r.GetKms(),
		AwsProfile:              r.GetAwsProfile(),
		Age:                     r.GetAge(),
		PGP:                     r.GetPgp(),
		GCPKMS:                  r.GetGcpKms(),
		HCKms:                   r.GetHckms(),
		AzureKeyVault:           r.GetAzureKeyvault(),
		VaultURI:                r.GetHcVaultTransitUri(),
		KeyGroups:               keyGroupsFromProto(r.GetKeyGroups()),
		ShamirThreshold:         int(r.GetShamirThreshold()),
		UnencryptedSuffix:       r.GetUnencryptedSuffix(),
		EncryptedSuffix:         r.GetEncryptedSuffix(),
		UnencryptedRegex:        r.GetUnencryptedRegex(),
		EncryptedRegex:          r.GetEncryptedRegex(),
		UnencryptedCommentRegex: r.GetUnencryptedCommentRegex(),
		EncryptedCommentRegex:   r.GetEncryptedCommentRegex(),
		MACOnlyEncrypted:        r.GetMacOnlyEncrypted(),
	}
}

func keyGroupsFromProto(pbGroups []*configpb.KeyGroup) []keyGroup {
	if len(pbGroups) == 0 {
		return nil
	}
	groups := make([]keyGroup, len(pbGroups))
	for i, g := range pbGroups {
		groups[i] = keyGroupFromProto(g)
	}
	return groups
}

func keyGroupFromProto(g *configpb.KeyGroup) keyGroup {
	kg := keyGroup{
		Merge:   keyGroupsFromProto(g.GetMerge()),
		Vault:   g.GetHcVault(),
		Age:     g.GetAge(),
		PGP:     g.GetPgp(),
		HCKms:   nil,
		KMS:     nil,
		GCPKMS:  nil,
		AzureKV: nil,
	}
	for _, k := range g.GetKms() {
		kg.KMS = append(kg.KMS, kmsKey{
			Arn:        k.GetArn(),
			Role:       k.GetRole(),
			Context:    stringPtrMap(k.GetContext()),
			AwsProfile: k.GetAwsProfile(),
		})
	}
	for _, k := range g.GetGcpKms() {
		kg.GCPKMS = append(kg.GCPKMS, gcpKmsKey{ResourceID: k.GetResourceId()})
	}
	for _, k := range g.GetHckms() {
		kg.HCKms = append(kg.HCKms, hckmsKey{KeyID: k.GetKeyId()})
	}
	for _, k := range g.GetAzureKeyvault() {
		kg.AzureKV = append(kg.AzureKV, azureKVKey{
			VaultURL: k.GetVaultUrl(),
			Key:      k.GetKey(),
			Version:  k.GetVersion(),
		})
	}
	return kg
}

func destinationRulesFromProto(pbRules []*configpb.DestinationRule) []destinationRule {
	if len(pbRules) == 0 {
		return nil
	}
	rules := make([]destinationRule, len(pbRules))
	for i, r := range pbRules {
		rules[i] = destinationRule{
			PathRegex:        r.GetPathRegex(),
			S3Bucket:         r.GetS3Bucket(),
			S3Prefix:         r.GetS3Prefix(),
			GCSBucket:        r.GetGcsBucket(),
			GCSPrefix:        r.GetGcsPrefix(),
			VaultPath:        r.GetVaultPath(),
			VaultAddress:     r.GetVaultAddress(),
			VaultKVMountName: r.GetVaultKvMountName(),
			VaultKVVersion:   int(r.GetVaultKvVersion()),
			RecreationRule:   creationRuleFromProto(r.GetRecreationRule()),
			OmitExtensions:   r.GetOmitExtensions(),
		}
	}
	return rules
}

// applyStoresConfig overlays store options from the PXF document onto the
// already-defaulted StoresConfig. Only the indent fields carry presence
// semantics: an absent indent leaves the default (-1 for JSON/JSON-binary)
// in place, while an explicitly set value (including 0) overrides it.
func applyStoresConfig(dst *StoresConfig, pb *configpb.StoresConfig) {
	if pb == nil {
		return
	}
	if js := pb.GetJson(); js != nil && js.Indent != nil {
		dst.JSON.Indent = int(js.GetIndent())
	}
	if jb := pb.GetJsonBinary(); jb != nil && jb.Indent != nil {
		dst.JSONBinary.Indent = int(jb.GetIndent())
	}
	if y := pb.GetYaml(); y != nil && y.Indent != nil {
		dst.YAML.Indent = int(y.GetIndent())
	}
}

// stringPtrMap converts a proto map<string,string> into the map[string]*string
// shape kms.NewMasterKeyWithProfile expects for its encryption context.
func stringPtrMap(m map[string]string) map[string]*string {
	if m == nil {
		return nil
	}
	out := make(map[string]*string, len(m))
	for k, v := range m {
		v := v
		out[k] = &v
	}
	return out
}

// Config is the configuration for a given SOPS file
type Config struct {
	KeyGroups               []sops.KeyGroup
	ShamirThreshold         int
	UnencryptedSuffix       string
	EncryptedSuffix         string
	UnencryptedRegex        string
	EncryptedRegex          string
	UnencryptedCommentRegex string
	EncryptedCommentRegex   string
	MACOnlyEncrypted        bool
	Destination             publish.Destination
	OmitExtensions          bool
}

func deduplicateKeygroup(group sops.KeyGroup) sops.KeyGroup {
	var deduplicatedKeygroup sops.KeyGroup

	unique := make(map[string]bool)
	for _, v := range group {
		key := fmt.Sprintf("%T/%v", v, v.ToString())
		if _, ok := unique[key]; ok {
			// key already contained, therefore not unique
			continue
		}

		deduplicatedKeygroup = append(deduplicatedKeygroup, v)
		unique[key] = true
	}

	return deduplicatedKeygroup
}

func extractMasterKeys(group keyGroup) (sops.KeyGroup, error) {
	var keyGroup sops.KeyGroup
	for _, k := range group.Merge {
		subKeyGroup, err := extractMasterKeys(k)
		if err != nil {
			return nil, err
		}
		keyGroup = append(keyGroup, subKeyGroup...)
	}

	for _, k := range group.Age {
		keys, err := age.MasterKeysFromRecipients(k)
		if err != nil {
			return nil, err
		}
		for _, key := range keys {
			keyGroup = append(keyGroup, key)
		}
	}
	for _, k := range group.PGP {
		keyGroup = append(keyGroup, pgp.NewMasterKeyFromFingerprint(k))
	}
	for _, k := range group.KMS {
		keyGroup = append(keyGroup, kms.NewMasterKeyWithProfile(k.Arn, k.Role, k.Context, k.AwsProfile))
	}
	for _, k := range group.GCPKMS {
		keyGroup = append(keyGroup, gcpkms.NewMasterKeyFromResourceID(k.ResourceID))
	}
	for _, k := range group.HCKms {
		key, err := hckms.NewMasterKey(k.KeyID)
		if err != nil {
			return nil, err
		}
		keyGroup = append(keyGroup, key)
	}
	for _, k := range group.AzureKV {
		if key, err := azkv.NewMasterKeyWithOptionalVersion(k.VaultURL, k.Key, k.Version); err == nil {
			keyGroup = append(keyGroup, key)
		} else {
			return nil, err
		}
	}
	for _, k := range group.Vault {
		if masterKey, err := hcvault.NewMasterKeyFromURI(k); err == nil {
			keyGroup = append(keyGroup, masterKey)
		} else {
			return nil, err
		}
	}
	return deduplicateKeygroup(keyGroup), nil
}

func getKeyGroupsFromCreationRule(cRule *creationRule, kmsEncryptionContext map[string]*string) ([]sops.KeyGroup, error) {
	var groups []sops.KeyGroup
	if len(cRule.KeyGroups) > 0 {
		for _, group := range cRule.KeyGroups {
			keyGroup, err := extractMasterKeys(group)
			if err != nil {
				return nil, err
			}
			groups = append(groups, keyGroup)
		}
	} else {
		var keyGroup sops.KeyGroup
		if len(cRule.Age) > 0 {
			ageKeys, err := age.MasterKeysFromRecipients(strings.Join(cRule.Age, ","))
			if err != nil {
				return nil, err
			}
			for _, ak := range ageKeys {
				keyGroup = append(keyGroup, ak)
			}
		}
		for _, k := range pgp.MasterKeysFromFingerprintString(strings.Join(cRule.PGP, ",")) {
			keyGroup = append(keyGroup, k)
		}
		for _, k := range kms.MasterKeysFromArnString(strings.Join(cRule.KMS, ","), kmsEncryptionContext, cRule.AwsProfile) {
			keyGroup = append(keyGroup, k)
		}
		for _, k := range gcpkms.MasterKeysFromResourceIDString(strings.Join(cRule.GCPKMS, ",")) {
			keyGroup = append(keyGroup, k)
		}
		hckmsMasterKeys, err := hckms.NewMasterKeyFromKeyIDString(strings.Join(cRule.HCKms, ","))
		if err != nil {
			return nil, err
		}
		for _, k := range hckmsMasterKeys {
			keyGroup = append(keyGroup, k)
		}
		azureKeys, err := azkv.MasterKeysFromURLs(strings.Join(cRule.AzureKeyVault, ","))
		if err != nil {
			return nil, err
		}
		for _, k := range azureKeys {
			keyGroup = append(keyGroup, k)
		}
		vaultKeys, err := hcvault.NewMasterKeysFromURIs(strings.Join(cRule.VaultURI, ","))
		if err != nil {
			return nil, err
		}
		for _, k := range vaultKeys {
			keyGroup = append(keyGroup, k)
		}
		groups = append(groups, keyGroup)
	}
	return groups, nil
}

func loadConfigFile(confPath string) (*configFile, error) {
	confBytes, err := os.ReadFile(confPath)
	if err != nil {
		return nil, fmt.Errorf("could not read config file: %s", err)
	}
	conf := &configFile{}
	conf.Stores = *NewStoresConfig()
	err = conf.load(confBytes)
	if err != nil {
		return nil, fmt.Errorf("error loading config: %s", err)
	}
	return conf, nil
}

func configFromRule(rule *creationRule, kmsEncryptionContext map[string]*string) (*Config, error) {
	cryptRuleCount := 0
	if rule.UnencryptedSuffix != "" {
		cryptRuleCount++
	}
	if rule.EncryptedSuffix != "" {
		cryptRuleCount++
	}
	if rule.UnencryptedRegex != "" {
		cryptRuleCount++
	}
	if rule.EncryptedRegex != "" {
		cryptRuleCount++
	}
	if rule.UnencryptedCommentRegex != "" {
		cryptRuleCount++
	}
	if rule.EncryptedCommentRegex != "" {
		cryptRuleCount++
	}

	if cryptRuleCount > 1 {
		return nil, fmt.Errorf("error loading config: cannot use more than one of encrypted_suffix, unencrypted_suffix, encrypted_regex, unencrypted_regex, encrypted_comment_regex, or unencrypted_comment_regex for the same rule")
	}

	groups, err := getKeyGroupsFromCreationRule(rule, kmsEncryptionContext)
	if err != nil {
		return nil, err
	}

	return &Config{
		KeyGroups:               groups,
		ShamirThreshold:         rule.ShamirThreshold,
		UnencryptedSuffix:       rule.UnencryptedSuffix,
		EncryptedSuffix:         rule.EncryptedSuffix,
		UnencryptedRegex:        rule.UnencryptedRegex,
		EncryptedRegex:          rule.EncryptedRegex,
		UnencryptedCommentRegex: rule.UnencryptedCommentRegex,
		EncryptedCommentRegex:   rule.EncryptedCommentRegex,
		MACOnlyEncrypted:        rule.MACOnlyEncrypted,
	}, nil
}

func parseDestinationRuleForFile(conf *configFile, filePath string, kmsEncryptionContext map[string]*string) (*Config, error) {
	var rule *creationRule
	var dRule *destinationRule

	if len(conf.DestinationRules) > 0 {
		for _, r := range conf.DestinationRules {
			if r.PathRegex == "" {
				dRule = &r
				rule = &dRule.RecreationRule
				break
			}
			if r.PathRegex != "" {
				if match, _ := regexp.MatchString(r.PathRegex, filePath); match {
					dRule = &r
					rule = &dRule.RecreationRule
					break
				}
			}
		}
	}

	if dRule == nil {
		return nil, fmt.Errorf("error loading config: no matching destination found in config")
	}

	var dest publish.Destination
	destinationCount := 0
	if dRule.S3Bucket != "" {
		destinationCount++
	}
	if dRule.GCSBucket != "" {
		destinationCount++
	}
	if dRule.VaultPath != "" {
		destinationCount++
	}

	if destinationCount > 1 {
		return nil, fmt.Errorf("error loading config: more than one destinations were found in a single destination rule, you can only use one per rule")
	}
	if dRule.S3Bucket != "" {
		dest = publish.NewS3Destination(dRule.S3Bucket, dRule.S3Prefix)
	}
	if dRule.GCSBucket != "" {
		dest = publish.NewGCSDestination(dRule.GCSBucket, dRule.GCSPrefix)
	}
	if dRule.VaultPath != "" {
		dest = publish.NewVaultDestination(dRule.VaultAddress, dRule.VaultPath, dRule.VaultKVMountName, dRule.VaultKVVersion)
	}

	config, err := configFromRule(rule, kmsEncryptionContext)
	if err != nil {
		return nil, err
	}
	config.Destination = dest
	config.OmitExtensions = dRule.OmitExtensions

	return config, nil
}

func parseCreationRuleForFile(conf *configFile, confPath, filePath string, kmsEncryptionContext map[string]*string) (*Config, error) {
	// If config file doesn't contain CreationRules (it's empty or only contains DestionationRules), assume it does not exist
	if conf.CreationRules == nil {
		return nil, nil
	}

	configDir, err := filepath.Abs(filepath.Dir(confPath))
	if err != nil {
		return nil, err
	}

	// compare file path relative to path of config file
	filePath = strings.TrimPrefix(filePath, configDir+string(filepath.Separator))

	var rule *creationRule

	for _, r := range conf.CreationRules {
		if r.PathRegex == "" {
			rule = &r
			break
		}
		reg, err := regexp.Compile(r.PathRegex)
		if err != nil {
			return nil, fmt.Errorf("can not compile regexp: %w", err)
		}
		if reg.MatchString(filePath) {
			rule = &r
			break
		}
	}

	if rule == nil {
		return nil, fmt.Errorf("error loading config: no matching creation rules found")
	}

	config, err := configFromRule(rule, kmsEncryptionContext)
	if err != nil {
		return nil, err
	}

	return config, nil
}

// LoadCreationRuleForFile load the configuration for a given SOPS file from the config file at confPath. A kmsEncryptionContext
// should be provided for configurations that do not contain key groups, as there's no way to specify context inside
// a SOPS config file outside of key groups.
func LoadCreationRuleForFile(confPath string, filePath string, kmsEncryptionContext map[string]*string) (*Config, error) {
	conf, err := loadConfigFile(confPath)
	if err != nil {
		return nil, err
	}

	return parseCreationRuleForFile(conf, confPath, filePath, kmsEncryptionContext)
}

// LoadDestinationRuleForFile works the same as LoadCreationRuleForFile, but gets the "creation_rule" from the matching destination_rule's
// "recreation_rule".
func LoadDestinationRuleForFile(confPath string, filePath string, kmsEncryptionContext map[string]*string) (*Config, error) {
	conf, err := loadConfigFile(confPath)
	if err != nil {
		return nil, err
	}
	return parseDestinationRuleForFile(conf, filePath, kmsEncryptionContext)
}

func LoadStoresConfig(confPath string) (*StoresConfig, error) {
	conf, err := loadConfigFile(confPath)
	if err != nil {
		return nil, err
	}
	return &conf.Stores, nil
}
