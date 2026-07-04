package age

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"filippo.io/age/armor"
	"filippo.io/age/plugin"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"

	"github.com/trendvidia/sops/v4/age/keypb"
	"github.com/trendvidia/sops/v4/logging"
	"github.com/google/shlex"
)

const (
	// SopsAgeKeyEnv can be set as an environment variable with a string list
	// of age keys as value.
	SopsAgeKeyEnv = "SOPS_AGE_KEY"
	// SopsAgeKeyFileEnv can be set as an environment variable pointing to an
	// age keys file.
	SopsAgeKeyFileEnv = "SOPS_AGE_KEY_FILE"
	// SopsAgeKeyCmdEnv can be set as an environment variable with a command
	// to execute that returns the age keys.
	SopsAgeKeyCmdEnv = "SOPS_AGE_KEY_CMD"
	// SopsAgeRecipientEnv is passed as an environment variable to the command
	// set in SopsAgeKeyCmdEnv and contains the Bech32-encoded age public key
	// for which the private key should be returned.
	SopsAgeRecipientEnv = "SOPS_AGE_RECIPIENT"
	// SopsAgeSshPrivateKeyCmdEnv can be set as an environment variable with a command
	// to execute that returns the private SSH key.
	SopsAgeSshPrivateKeyCmdEnv = "SOPS_AGE_SSH_PRIVATE_KEY_CMD"
	// SopsAgeSshPrivateKeyFileEnv can be set as an environment variable pointing to
	// a private SSH key file.
	SopsAgeSshPrivateKeyFileEnv = "SOPS_AGE_SSH_PRIVATE_KEY_FILE"
	// DefaultAgeKeyFilePath is the standardized default age key file
	// path (relative to $HOME) consulted when none of the
	// SOPS_AGE_KEY{,_FILE,_CMD} env vars resolve. Hardcoded — same on
	// every supported OS, no XDG_CONFIG_HOME indirection, no
	// os.UserConfigDir() macOS/Windows quirks. PXF format only.
	DefaultAgeKeyFilePath = ".config/sops/age/keys.pxf"
	// KeyTypeIdentifier is the string used to identify an age MasterKey.
	KeyTypeIdentifier = "age"
)

// log is the global logger for any age MasterKey.
var log *logrus.Logger

func init() {
	log = logging.NewLogger("AGE")
}

// MasterKey is an age key used to Encrypt and Decrypt SOPS' data key.
type MasterKey struct {
	// Identity used to contain a Bench32-encoded private key.
	// Deprecated: private keys are no longer publicly exposed.
	// Instead, they are either injected by a (local) key service server
	// using ParsedIdentities.ApplyToMasterKey, or loaded from the runtime
	// environment (variables) as defined by the `SopsAgeKey*` constants.
	Identity string
	// Recipient contains the Bench32-encoded age public key used to Encrypt.
	Recipient string
	// EncryptedKey contains the SOPS data key encrypted with age.
	EncryptedKey string

	// parsedIdentities contains a slice of parsed age identities.
	// It is used to lazy-load the Identities at-most once.
	// It can also be injected by a (local) keyservice.KeyServiceServer using
	// ParsedIdentities.ApplyToMasterKey().
	parsedIdentities []age.Identity
	// parsedRecipient contains a parsed age public key.
	// It is used to lazy-load the Recipient at-most once.
	parsedRecipient age.Recipient
}

// MasterKeysFromRecipients takes a comma-separated list of Bech32-encoded
// public keys, parses them, and returns a slice of new MasterKeys.
func MasterKeysFromRecipients(commaSeparatedRecipients string) ([]*MasterKey, error) {
	if commaSeparatedRecipients == "" {
		// otherwise Split returns [""] and MasterKeyFromRecipient is unhappy
		return make([]*MasterKey, 0), nil
	}
	recipients := strings.Split(commaSeparatedRecipients, ",")

	var keys []*MasterKey
	for _, recipient := range recipients {
		key, err := MasterKeyFromRecipient(recipient)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// errSet is a collection of captured errors.
type errSet []error

// Error joins the errors into a "; " separated string.
func (e errSet) Error() string {
	str := make([]string, len(e))
	for i, err := range e {
		str[i] = err.Error()
	}
	return strings.Join(str, "; ")
}

// MasterKeyFromRecipient takes a Bech32-encoded age public key, parses it, and
// returns a new MasterKey.
func MasterKeyFromRecipient(recipient string) (*MasterKey, error) {
	recipient = strings.TrimSpace(recipient)
	parsedRecipient, err := parseRecipient(recipient)
	if err != nil {
		return nil, err
	}
	return &MasterKey{
		Recipient:       recipient,
		parsedRecipient: parsedRecipient,
	}, nil
}

// ParsedIdentities contains a set of parsed age identities.
// It allows for creating a (local) keyservice.KeyServiceServer which parses
// identities only once, to then inject them using ApplyToMasterKey() for all
// requests.
type ParsedIdentities []age.Identity

// Import attempts to parse the given identities, to then add them to itself.
// It returns any parsing error.
// A single identity argument is allowed to be a multiline string containing
// multiple identities. Empty lines and lines starting with "#" are ignored.
// It is not thread safe, and parallel importing would better be done by
// parsing (using age.ParseIdentities) and appending to the slice yourself, in
// combination with e.g. a sync.Mutex.
func (i *ParsedIdentities) Import(identity ...string) error {
	// one identity per line
	r := strings.NewReader(strings.Join(identity, "\n"))

	identities, err := parseIdentities(r, false)
	if err != nil {
		return fmt.Errorf("failed to parse and add to age identities: %w", err)
	}
	*i = append(*i, identities...)
	return nil
}

// ApplyToMasterKey configures the ParsedIdentities on the provided key.
func (i ParsedIdentities) ApplyToMasterKey(key *MasterKey) {
	key.parsedIdentities = i
}

// Encrypt takes a SOPS data key, encrypts it with the Recipient, and stores
// the result in the EncryptedKey field.
//
// Consider using EncryptContext instead.
func (key *MasterKey) Encrypt(dataKey []byte) error {
	return key.EncryptContext(context.Background(), dataKey)
}

// EncryptContext takes a SOPS data key, encrypts it with the Recipient,
// and stores the result in the EncryptedKey field. age encryption is
// purely local — ctx is accepted for API symmetry with KMS-backed
// providers but the actual encrypt does not honor cancellation (runs
// in-memory in microseconds).
func (key *MasterKey) EncryptContext(ctx context.Context, dataKey []byte) error {
	_ = ctx // local crypto; nothing to cancel.
	return key.encryptInternal(dataKey)
}

func (key *MasterKey) encryptInternal(dataKey []byte) error {
	if key.parsedRecipient == nil {
		parsedRecipient, err := parseRecipient(key.Recipient)
		if err != nil {
			log.WithField("recipient", key.parsedRecipient).Info("Encryption failed")
			return err
		}
		key.parsedRecipient = parsedRecipient
	}

	var buffer bytes.Buffer
	aw := armor.NewWriter(&buffer)
	w, err := age.Encrypt(aw, key.parsedRecipient)
	if err != nil {
		log.WithField("recipient", key.parsedRecipient).Info("Encryption failed")
		return fmt.Errorf("failed to create writer for encrypting sops data key with age: %w", err)
	}
	if _, err := w.Write(dataKey); err != nil {
		log.WithField("recipient", key.parsedRecipient).Info("Encryption failed")
		return fmt.Errorf("failed to encrypt sops data key with age: %w", err)
	}
	if err := w.Close(); err != nil {
		log.WithField("recipient", key.parsedRecipient).Info("Encryption failed")
		return fmt.Errorf("failed to close writer for encrypting sops data key with age: %w", err)
	}
	if err := aw.Close(); err != nil {
		log.WithField("recipient", key.parsedRecipient).Info("Encryption failed")
		return fmt.Errorf("failed to close armored writer: %w", err)
	}

	key.SetEncryptedDataKey(buffer.Bytes())
	log.WithField("recipient", key.parsedRecipient).Info("Encryption succeeded")
	return nil
}

// EncryptIfNeeded encrypts the provided SOPS data key, if it has not been
// encrypted yet.
func (key *MasterKey) EncryptIfNeeded(dataKey []byte) error {
	if key.EncryptedKey == "" {
		return key.Encrypt(dataKey)
	}
	return nil
}

// EncryptedDataKey returns the encrypted SOPS data key this master key holds.
func (key *MasterKey) EncryptedDataKey() []byte {
	return []byte(key.EncryptedKey)
}

// SetEncryptedDataKey sets the encrypted SOPS data key for this master key.
func (key *MasterKey) SetEncryptedDataKey(enc []byte) {
	key.EncryptedKey = string(enc)
}

func formatError(msg string, err error, errs errSet, unusedLocations []string) error {
	var loadSuffix string
	if len(errs) > 0 {
		loadSuffix = fmt.Sprintf(". Errors while loading age identities: %s", errs.Error())
	}
	var unusedSuffix string
	if len(unusedLocations) > 0 {
		count := len(unusedLocations)
		if count == 1 {
			unusedSuffix = fmt.Sprintf(" '%s'", unusedLocations[0])
		} else if count == 2 {
			unusedSuffix = fmt.Sprintf("s '%s' and '%s'", unusedLocations[0], unusedLocations[1])
		} else {
			unusedSuffix = fmt.Sprintf("s '%s', and '%s'", strings.Join(unusedLocations[:count - 1], "', '"), unusedLocations[count - 1])
		}
		unusedSuffix = fmt.Sprintf(". Did not find keys in location%s.", unusedSuffix)
	}
	if err != nil {
		return fmt.Errorf("%s: %w%s%s", msg, err, loadSuffix, unusedSuffix)
	} else {
		return fmt.Errorf("%s%s%s", msg, loadSuffix, unusedSuffix)
	}
}

// Decrypt decrypts the EncryptedKey with the parsed or loaded identities, and
// returns the result.
//
// Consider using DecryptContext instead.
func (key *MasterKey) Decrypt() ([]byte, error) {
	return key.DecryptContext(context.Background())
}

// DecryptContext decrypts the EncryptedKey with the parsed or loaded
// identities, and returns the result. age decryption is purely local — the
// ctx is accepted for API symmetry with KMS-backed providers but the actual
// decrypt does not honor cancellation (it runs in-memory in microseconds).
func (key *MasterKey) DecryptContext(ctx context.Context) ([]byte, error) {
	_ = ctx // local crypto; nothing to cancel.
	return key.decryptInternal()
}

func (key *MasterKey) decryptInternal() ([]byte, error) {
	var errs errSet
	var unusedLocations []string
	if len(key.parsedIdentities) == 0 {
		var ids ParsedIdentities
		ids, unusedLocations, errs = key.loadIdentities()
		if len(ids) == 0 {
			log.Info("Decryption failed")
			return nil, formatError("failed to load age identities", nil, errs, unusedLocations)
		}
		ids.ApplyToMasterKey(key)
	}

	src := bytes.NewReader([]byte(key.EncryptedKey))
	ar := armor.NewReader(src)
	r, err := age.Decrypt(ar, key.parsedIdentities...)
	if err != nil {
		log.Info("Decryption failed")
		return nil, formatError("failed to create reader for decrypting sops data key with age", err, errs, unusedLocations)
	}

	var b bytes.Buffer
	if _, err := io.Copy(&b, r); err != nil {
		log.Info("Decryption failed")
		return nil, fmt.Errorf("failed to copy age decrypted data into bytes.Buffer: %w", err)
	}

	log.Info("Decryption succeeded")
	return b.Bytes(), nil
}

// NeedsRotation returns whether the data key needs to be rotated or not.
func (key *MasterKey) NeedsRotation() bool {
	return false
}

// ToString converts the key to a string representation.
func (key *MasterKey) ToString() string {
	return key.Recipient
}

// ToMap converts the MasterKey to a map for serialization purposes.
func (key *MasterKey) ToMap() map[string]interface{} {
	out := make(map[string]interface{})
	out["recipient"] = key.Recipient
	out["enc"] = key.EncryptedKey
	return out
}

// TypeToIdentifier returns the string identifier for the MasterKey type.
func (key *MasterKey) TypeToIdentifier() string {
	return KeyTypeIdentifier
}

// getOutputFromCmd executes a shell command provided in param 'cmdString',
// optionally adding env vars provided in param 'envVars',
// and returns the command's output and error
func getOutputFromCmd(cmdString string, envVars []string) ([]byte, error) {
	var out []byte

	args, err := shlex.Split(cmdString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse command %s: %w", cmdString, err)
	}
	// A set-but-empty (or whitespace-only) command splits to no argv;
	// surface it as a per-source error instead of panicking on args[0].
	// A cleared-but-still-exported SOPS_AGE_KEY_CMD is the common way
	// in (#38).
	if len(args) == 0 {
		return nil, fmt.Errorf("failed to parse command %q: empty command", cmdString)
	}
	cmd := exec.Command(args[0], args[1:]...)
	if envVars != nil {
		cmd.Env = append(os.Environ(), envVars[0:]...)
	}
	out, err = cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to execute command %s: %w", cmdString, err)
	}

	return out, nil
}

// loadAgeSSHIdentity attempts to load age SSH identities in this order:
// 1. An SSH private key from the SopsAgeSshPrivateKeyFileEnv environment variable.
// 2. An SSH private key returned by executing the command from the
// SopsAgeSshPrivateKeyCmdEnv environment variable
// 3. `~/.ssh/id_ed25519` or `~/.ssh/id_rsa`.
// If no age SSH identity is found, it will return nil.
func (key *MasterKey) loadAgeSSHIdentities() ([]age.Identity, []string, errSet) {
	var identities []age.Identity
	var unusedLocations []string
	var errs errSet

	sshKeyFilePath, ok := os.LookupEnv(SopsAgeSshPrivateKeyFileEnv)
	if ok {
		identity, err := parseSSHIdentityFromPrivateKeyFile(sshKeyFilePath)
		if err != nil {
			errs = append(errs, err)
		} else {
			identities = append(identities, identity)
		}
	} else {
		unusedLocations = append(unusedLocations, SopsAgeSshPrivateKeyFileEnv)
	}

	sshKeyCmd, ok := os.LookupEnv(SopsAgeSshPrivateKeyCmdEnv)
	if ok {
		out, err := getOutputFromCmd(sshKeyCmd, []string{fmt.Sprintf("%s=%s", SopsAgeRecipientEnv, key.Recipient)})
		if err != nil {
			errs = append(errs, err)
		} else {
			identity, err := parseSSHIdentityFromPrivateKeyCmdOutput(out)
			if err != nil {
				errs = append(errs, err)
			} else {
				identities = append(identities, identity)
			}
		}
	} else {
		unusedLocations = append(unusedLocations, SopsAgeSshPrivateKeyCmdEnv)
	}

	userHomeDir, err := os.UserHomeDir()
	if err != nil {
		errs = append(errs, err)
	} else if userHomeDir == "" {
		log.Warnf("could not determine the user home directory: %v", err)
	} else {
		sshEd25519PrivateKeyPath := filepath.Join(userHomeDir, ".ssh", "id_ed25519")
		if _, err := os.Stat(sshEd25519PrivateKeyPath); err == nil {
			identity, err := parseSSHIdentityFromPrivateKeyFile(sshEd25519PrivateKeyPath)
			if err != nil {
				errs = append(errs, err)
			} else {
				identities = append(identities, identity)
			}
		} else {
			unusedLocations = append(unusedLocations, sshEd25519PrivateKeyPath)
		}

		sshRsaPrivateKeyPath := filepath.Join(userHomeDir, ".ssh", "id_rsa")
		if _, err := os.Stat(sshRsaPrivateKeyPath); err == nil {
			identity, err := parseSSHIdentityFromPrivateKeyFile(sshRsaPrivateKeyPath)
			if err != nil {
				errs = append(errs, err)
			} else {
				identities = append(identities, identity)
			}
		} else {
			unusedLocations = append(unusedLocations, sshRsaPrivateKeyPath)
		}
	}

	return identities, unusedLocations, errs
}

// defaultAgeKeyFile returns the standardized default age key file
// path: $HOME/DefaultAgeKeyFilePath. Identical across Linux, macOS,
// and Windows ($HOME on Windows resolves via os.UserHomeDir() to
// %USERPROFILE%). PXF format only — the legacy line-based keys.txt
// at the old XDG path is no longer implicit.
func defaultAgeKeyFile() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, filepath.FromSlash(DefaultAgeKeyFilePath)), nil
}

type identityReader struct {
	reader                   io.Reader
	allowMultipleKeysPerLine bool
}

// loadIdentities attempts to load the age identities from every
// configured source. Sources are consulted in this precedence-aligned
// order (matching the encrypt-side pxfSources):
//
//  1. SOPS_AGE_KEY_FILE      — PXF if `.pxf` suffix; line-based otherwise.
//  2. SOPS_AGE_KEY            — PXF if content sniffs PXF; line-based otherwise.
//  3. SOPS_AGE_KEY_CMD        — PXF if stdout sniffs PXF; line-based otherwise.
//  4. $HOME/.config/sops/age/keys.pxf — standardized default; PXF only,
//     consulted only when the file exists.
//
// Plus a decrypt-only side channel (loaded up front; no encrypt-by-name
// analogue):
//
//   SOPS_AGE_SSH_PRIVATE_KEY_FILE / _CMD, ~/.ssh/id_ed25519, ~/.ssh/id_rsa
//
// Identities from every resolving source are unioned — any one of them
// can decrypt the file. Walk order is documentation only; semantics is
// set-based. Order matters on the encrypt side (first-hit-wins
// RecipientFromKeyFileByName) and the documented decrypt order mirrors
// it for consistency.
func (key *MasterKey) loadIdentities() (ParsedIdentities, []string, errSet) {
	identities, unusedLocations, errs := key.loadAgeSSHIdentities()

	var readers = make(map[string]identityReader, 0)

	if ageKeyFile, ok := os.LookupEnv(SopsAgeKeyFileEnv); ok {
		if strings.HasSuffix(ageKeyFile, keypb.FileExtension) {
			ids, err := loadPXFIdentities(ageKeyFile)
			if err != nil {
				errs = append(errs, err)
			} else {
				identities = append(identities, ids...)
				if len(ids) == 0 {
					unusedLocations = append(unusedLocations, SopsAgeKeyFileEnv)
				}
			}
		} else {
			f, err := os.Open(ageKeyFile)
			if err != nil {
				errs = append(errs, fmt.Errorf("failed to open %s file: %w", SopsAgeKeyFileEnv, err))
			} else {
				defer f.Close()
				readers[SopsAgeKeyFileEnv] = identityReader{
					reader:                   f,
					allowMultipleKeysPerLine: false,
				}
			}
		}
	} else {
		unusedLocations = append(unusedLocations, SopsAgeKeyFileEnv)
	}

	if ageKey, ok := os.LookupEnv(SopsAgeKeyEnv); ok {
		data := []byte(ageKey)
		if isPXFContent(data) {
			ids, err := parsePXFIdentities(SopsAgeKeyEnv, data)
			if err != nil {
				errs = append(errs, err)
			} else {
				identities = append(identities, ids...)
				if len(ids) == 0 {
					unusedLocations = append(unusedLocations, SopsAgeKeyEnv)
				}
			}
		} else {
			readers[SopsAgeKeyEnv] = identityReader{
				reader:                   bytes.NewReader(data),
				allowMultipleKeysPerLine: true,
			}
		}
	} else {
		unusedLocations = append(unusedLocations, SopsAgeKeyEnv)
	}

	if ageKeyCmd, ok := os.LookupEnv(SopsAgeKeyCmdEnv); ok {
		out, err := getOutputFromCmd(ageKeyCmd, []string{fmt.Sprintf("%s=%s", SopsAgeRecipientEnv, key.Recipient)})
		if err != nil {
			errs = append(errs, err)
		} else if isPXFContent(out) {
			ids, err := parsePXFIdentities(SopsAgeKeyCmdEnv, out)
			if err != nil {
				errs = append(errs, err)
			} else {
				identities = append(identities, ids...)
				if len(ids) == 0 {
					unusedLocations = append(unusedLocations, SopsAgeKeyCmdEnv)
				}
			}
		} else {
			readers[SopsAgeKeyCmdEnv] = identityReader{
				reader:                   bytes.NewReader(out),
				allowMultipleKeysPerLine: false,
			}
		}
	} else {
		unusedLocations = append(unusedLocations, SopsAgeKeyCmdEnv)
	}

	// Standardized default: $HOME/.config/sops/age/keys.pxf (PXF only).
	// Silent skip if $HOME is undeterminable or the file doesn't exist —
	// the contract is "set an env var or drop a file at this path."
	// Bubbling a "$HOME undeterminable" error here would mask the real
	// "no source configured" diagnostic the caller surfaces when both
	// identities and readers are empty.
	if defaultPath, err := defaultAgeKeyFile(); err == nil {
		if _, statErr := os.Stat(defaultPath); statErr == nil {
			ids, err := loadPXFIdentities(defaultPath)
			if err != nil {
				errs = append(errs, err)
			} else {
				identities = append(identities, ids...)
				if len(ids) == 0 {
					unusedLocations = append(unusedLocations, defaultPath)
				}
			}
		} else if len(readers) == 0 && len(identities) == 0 {
			unusedLocations = append(unusedLocations, defaultPath)
		}
	}

	for location, r := range readers {
		ids, err := unwrapIdentities(location, r.reader, r.allowMultipleKeysPerLine)
		if err != nil {
			errs = append(errs, err)
		} else {
			identities = append(identities, ids...)
			if len(ids) == 0 {
				unusedLocations = append(unusedLocations, location)
			}
		}
	}
	return identities, unusedLocations, errs
}

// parseRecipient attempts to parse a string containing an encoded age public
// key or a public ssh key.
func parseRecipient(recipient string) (age.Recipient, error) {
	switch {
	case strings.HasPrefix(recipient, "age1pq1"):
		parsedRecipient, err := age.ParseHybridRecipient(recipient)
		if err != nil {
			return nil, fmt.Errorf("failed to parse input as Bech32-encoded age public key: %w", err)
		}

		return parsedRecipient, nil
	case strings.HasPrefix(recipient, "age1") && strings.Count(recipient, "1") > 1:
		parsedRecipient, err := plugin.NewRecipient(recipient, pluginTerminalUI)
		if err != nil {
			return nil, fmt.Errorf("failed to parse input as age key from age plugin: %w", err)
		}
		return parsedRecipient, nil
	case strings.HasPrefix(recipient, "age1"):
		parsedRecipient, err := age.ParseX25519Recipient(recipient)
		if err != nil {
			return nil, fmt.Errorf("failed to parse input as Bech32-encoded age public key: %w", err)
		}

		return parsedRecipient, nil
	case strings.HasPrefix(recipient, "ssh-"):
		parsedRecipient, err := agessh.ParseRecipient(recipient)
		if err != nil {
			return nil, fmt.Errorf("failed to parse input as age-ssh public key: %w", err)
		}
		return parsedRecipient, nil
	}

	return nil, fmt.Errorf("failed to parse input, unknown recipient type: %q", recipient)
}

// parseIdentities attempts to parse one or more age identities from the provided reader.
// One identity per line.
// Empty lines and lines starting with "#" are ignored.
// If allowMultipleKeysPerLine is true, every non-empty lines is split by words,
// and every word is parsed as an identity.
func parseIdentities(r io.Reader, allowMultipleKeysPerLine bool) (ParsedIdentities, error) {
	var identities ParsedIdentities

	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := scanner.Text()

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if allowMultipleKeysPerLine {
			lineScanner := bufio.NewScanner(strings.NewReader(line))
			lineScanner.Split(bufio.ScanWords)
			for lineScanner.Scan() {
				word := lineScanner.Text()
				parsed, err := parseIdentity(word)
				if err != nil {
					return nil, err
				}
				identities = append(identities, parsed)
			}
		} else {
			parsed, err := parseIdentity(line)
			if err != nil {
				return nil, err
			}
			identities = append(identities, parsed)
		}
	}

	return identities, nil
}

func parseIdentity(s string) (age.Identity, error) {
	switch {
	case strings.HasPrefix(s, "AGE-PLUGIN-"):
		return plugin.NewIdentity(s, pluginTerminalUI)
	case strings.HasPrefix(s, "AGE-SECRET-KEY-PQ-1"):
		return age.ParseHybridIdentity(s)
	case strings.HasPrefix(s, "AGE-SECRET-KEY-1"):
		return age.ParseX25519Identity(s)
	default:
		return nil, fmt.Errorf("unknown identity type")
	}
}

// isPXFContent reports whether data looks like PXF-encoded age key
// material rather than the legacy line-based format or an age-encrypted
// identity blob.
//
// The probe skips blank lines and `#` comments (both formats accept
// them), then requires the first content line to positively match a
// PXF top-level entry shape: `identifier = …` or `identifier { … }`
// (per protowire-go's grammar — map-style `:` is reserved for nested
// entries and is rejected at the top level). Everything else —
// including legacy `AGE-…` lines, armored `-----BEGIN AGE` blobs, and
// random junk — falls through to the legacy parser, which surfaces the
// real error.
func isPXFContent(data []byte) bool {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		return looksLikePXFTopLevelEntry(line)
	}
	return false
}

// looksLikePXFTopLevelEntry reports whether line starts with an
// identifier followed by `=` or `{` (after optional whitespace) — the
// only two shapes PXF accepts at the top level of a document.
func looksLikePXFTopLevelEntry(line string) bool {
	if line == "" {
		return false
	}
	c := line[0]
	if !(c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
		return false
	}
	i := 1
	for i < len(line) {
		c := line[i]
		if c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			i++
			continue
		}
		break
	}
	for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
		i++
	}
	if i >= len(line) {
		return false
	}
	return line[i] == '=' || line[i] == '{'
}

// parsePXFIdentities parses data as a PXF-encoded AgeKeyFile and
// returns every entry in its `keys` map as an age identity. source is
// used only for error messages. The file's `default` field is ignored
// here — defaults are an encrypt-side concept, surfaced via
// DefaultRecipientFromKeyFile.
func parsePXFIdentities(source string, data []byte) (ParsedIdentities, error) {
	f, err := keypb.Parse(source, data)
	if err != nil {
		return nil, err
	}
	var ids ParsedIdentities
	for name, secret := range f.Keys {
		id, err := parseIdentity(secret)
		if err != nil {
			return nil, fmt.Errorf("age key file %q: parsing key %q: %w", source, name, err)
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// loadPXFIdentities reads a PXF-formatted age key file and parses every
// entry in its `keys` map as an age identity.
func loadPXFIdentities(path string) (ParsedIdentities, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read age key file: %w", err)
	}
	return parsePXFIdentities(path, data)
}

// pxfSourceFn lazily yields a parsed PXF AgeKeyFile from one of the
// SopsAgeKey* env vars, along with a human-readable label for error
// messages. It returns (nil, nil) if the env var is unset or its
// content is not PXF (so the caller falls through to the next source).
type pxfSourceFn func() (string, *keypb.AgeKeyFile, error)

// pxfSources returns the PXF age key sources in precedence order:
//
//  1. SOPS_AGE_KEY_FILE      — when its path ends in `.pxf`.
//  2. SOPS_AGE_KEY            — when its value is PXF content.
//  3. SOPS_AGE_KEY_CMD        — when its stdout is PXF content.
//  4. $HOME/.config/sops/age/keys.pxf — standardized default,
//     consulted only when the file exists.
//
// Each source is lazy: later sources only run when earlier ones don't
// resolve. The CLI translates --age-key-file / --age-key /
// --age-key-cmd flags into the corresponding env vars at subcommand
// entry, so CLI > env > default precedence falls out of the env-var
// ordering above.
//
// SOPS_AGE_KEY_FILE is dispatched on its extension (`.pxf`); the env
// and cmd sources are dispatched by content sniffing via isPXFContent.
// The default file is PXF-only — there is no implicit line-based
// fallback (callers wanting the legacy format must set
// SOPS_AGE_KEY_FILE explicitly).
func pxfSources() []pxfSourceFn {
	return []pxfSourceFn{
		func() (string, *keypb.AgeKeyFile, error) {
			path, ok := os.LookupEnv(SopsAgeKeyFileEnv)
			if !ok || !strings.HasSuffix(path, keypb.FileExtension) {
				return "", nil, nil
			}
			f, err := keypb.ReadFile(path)
			return path, f, err
		},
		func() (string, *keypb.AgeKeyFile, error) {
			ageKey, ok := os.LookupEnv(SopsAgeKeyEnv)
			if !ok {
				return "", nil, nil
			}
			data := []byte(ageKey)
			if !isPXFContent(data) {
				return "", nil, nil
			}
			f, err := keypb.Parse(SopsAgeKeyEnv, data)
			return SopsAgeKeyEnv, f, err
		},
		func() (string, *keypb.AgeKeyFile, error) {
			ageKeyCmd, ok := os.LookupEnv(SopsAgeKeyCmdEnv)
			if !ok {
				return "", nil, nil
			}
			// SOPS_AGE_RECIPIENT is unknown at this point — we're
			// computing the recipient. Pass empty so the command can
			// distinguish "produce all keys" from a specific lookup.
			out, err := getOutputFromCmd(ageKeyCmd, []string{fmt.Sprintf("%s=", SopsAgeRecipientEnv)})
			if err != nil {
				return SopsAgeKeyCmdEnv, nil, err
			}
			if !isPXFContent(out) {
				return "", nil, nil
			}
			f, err := keypb.Parse(SopsAgeKeyCmdEnv, out)
			return SopsAgeKeyCmdEnv, f, err
		},
		func() (string, *keypb.AgeKeyFile, error) {
			path, err := defaultAgeKeyFile()
			if err != nil {
				return "", nil, nil
			}
			if _, err := os.Stat(path); err != nil {
				return "", nil, nil
			}
			f, err := keypb.ReadFile(path)
			return path, f, err
		},
	}
}

// DefaultRecipientFromKeyFile returns the Bech32-encoded age public
// key of the "default" entry from the first PXF-formatted age key
// source that has one set. See pxfSources for the precedence chain
// (env-var driven; CLI flag values are translated to env vars at
// subcommand entry).
//
// Returns "" with a nil error when no source supplies a default. The
// function name is retained for backwards compatibility; the resolved
// source may be the env, the cmd, or the default file.
//
// Returns an error if a PXF source is malformed, if the default name
// isn't present in its `keys` map, or if the default key's secret
// cannot be derived into a recipient (i.e. it is a plugin identity).
func DefaultRecipientFromKeyFile() (string, error) {
	for _, source := range pxfSources() {
		label, f, err := source()
		if err != nil {
			return "", err
		}
		if f == nil || f.Default == "" {
			continue
		}
		return recipientFromAgeKeyFile(label, f, f.Default, "default")
	}
	return "", nil
}

// RecipientFromKeyFileByName resolves `name` against the first
// PXF-formatted age key source that contains it and returns the
// Bech32-encoded age public key of that entry. Sources are consulted
// in the same order as DefaultRecipientFromKeyFile (see pxfSources).
// Backs the --age-key-name / SOPS_AGE_KEY_NAME CLI surface.
//
// Errors if no PXF source is configured, if all configured sources
// lack the named entry, or if the entry's secret can't be derived
// (plugin identity).
func RecipientFromKeyFileByName(name string) (string, error) {
	var (
		anyPXFSource bool
		lastLabel    string
	)
	for _, source := range pxfSources() {
		label, f, err := source()
		if err != nil {
			return "", err
		}
		if f == nil {
			continue
		}
		anyPXFSource = true
		lastLabel = label
		if _, ok := f.Keys[name]; !ok {
			continue
		}
		return recipientFromAgeKeyFile(label, f, name, "key")
	}
	if !anyPXFSource {
		return "", fmt.Errorf("--age-key-name requires a PXF-formatted age key source (%s, %s, %s, or $HOME/%s)",
			SopsAgeKeyFileEnv, SopsAgeKeyEnv, SopsAgeKeyCmdEnv, DefaultAgeKeyFilePath)
	}
	return "", fmt.Errorf("age key file %q: key %q not in keys", lastLabel, name)
}

// recipientFromAgeKeyFile is the shared body of
// DefaultRecipientFromKeyFile and RecipientFromKeyFileByName. `label`
// is "default" or "key", used to vary the error wording.
func recipientFromAgeKeyFile(path string, f *keypb.AgeKeyFile, name, label string) (string, error) {
	if _, ok := f.Keys[name]; !ok {
		return "", fmt.Errorf("age key file %q: %s %q not in keys", path, label, name)
	}
	r, err := f.RecipientForName(name)
	if err != nil {
		return "", fmt.Errorf("age key file %q: parsing %s %q: %w", path, label, name, err)
	}
	if r == "" {
		return "", fmt.Errorf("age key file %q: %s %q recipient cannot be derived (plugin identities unsupported here)", path, label, name)
	}
	return r, nil
}

// parseSSHIdentityFromPrivateKeyCmdOutput returns an age.Identity from the given
// private key. Note that encrypted private keys are not supported.
func parseSSHIdentityFromPrivateKeyCmdOutput(key []byte) (age.Identity, error) {
	id, err := agessh.ParseIdentity(key)
	if sshErr, ok := err.(*ssh.PassphraseMissingError); ok {
		return nil, fmt.Errorf("the SSH key returned by running SOPS_AGE_SSH_PRIVATE_KEY_CMD is password protected, which is unsupported. (%q)", sshErr)
	}
	if err != nil {
		return nil, fmt.Errorf("malformed SSH identity returned by running SOPS_AGE_SSH_PRIVATE_KEY_CMD: %q", err)
	}
	return id, nil
}
