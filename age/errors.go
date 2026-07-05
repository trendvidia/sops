package age

import "errors"

// Typed errors for age key-source failures. Embedders that classify
// decrypt failures into user-facing buckets (e.g. "no usable key" vs.
// "your key-fetch command is broken") should test against these with
// [errors.Is] / [errors.As] instead of matching message text — the
// message text is not a stable contract.
//
// All of these survive the sops-level per-group aggregation when a
// file is decrypted through the in-process local keyservice (every
// aggregate in the chain implements Unwrap() []error). A gRPC
// keyservice flattens errors to strings on the wire; nothing typed
// survives that boundary.
var (
	// ErrNoIdentities is wrapped into the "failed to load age
	// identities" failure returned when decryption found no age key
	// material in any configured source (env vars, key files, key
	// command, SSH fallbacks, default key file).
	ErrNoIdentities = errors.New("no age identities found in any key source")

	// ErrNoIdentityMatched is wrapped into the decrypt failure
	// returned when identities were loaded but none of them could
	// decrypt the sops data key.
	ErrNoIdentityMatched = errors.New("no age identity matched the sops data key")

	// ErrKeyCommandFailed is wrapped into the failure returned when a
	// configured key command (SOPS_AGE_KEY_CMD or
	// SOPS_AGE_SSH_PRIVATE_KEY_CMD) could not be parsed into an argv
	// or executed successfully. A set-but-empty command is not this
	// error; see ErrEmptyKeyCommand.
	ErrKeyCommandFailed = errors.New("age key command failed")

	// ErrEmptyKeyCommand is wrapped into the failure returned when a
	// key command env var is set but empty (or whitespace-only) — the
	// `export SOPS_AGE_KEY_CMD=` case from #38. Deliberately distinct
	// from ErrKeyCommandFailed: an empty command means "no key
	// material configured here", not "the configured command is
	// broken" (#39). The message this sentinel renders as must stay
	// "empty command" — it is the suffix of the user-facing
	// `failed to parse command "": empty command` text.
	ErrEmptyKeyCommand = errors.New("empty command")

	// ErrKeyFileParse is wrapped into failures where age key material
	// was found (in a key file, env var content, or key command
	// output) but could not be parsed into identities.
	ErrKeyFileParse = errors.New("age key material could not be parsed")
)

// KeySourceError attributes a key-source load failure to the source it
// came from. Retrieve it with [errors.As]; note errors.As surfaces only
// the first match, so callers inspecting a multi-source failure may
// want to walk Unwrap() []error trees themselves.
//
// Its message is exactly the wrapped error's message, so wrapping a
// load error in a KeySourceError does not change any user-facing text.
type KeySourceError struct {
	// Source names the key source that failed: one of the SopsAge*Env
	// environment variable names, or a file path (the default key
	// file, or an SSH default key path).
	Source string
	// Err is the underlying failure.
	Err error
}

func (e *KeySourceError) Error() string { return e.Err.Error() }

func (e *KeySourceError) Unwrap() error { return e.Err }

// sentinelError attaches a sentinel to err so [errors.Is] can classify
// err without the sentinel's text appearing in the rendered message.
type sentinelError struct {
	sentinel error
	err      error
}

func (e *sentinelError) Error() string { return e.err.Error() }

func (e *sentinelError) Unwrap() []error { return []error{e.sentinel, e.err} }

func withSentinel(sentinel, err error) error {
	return &sentinelError{sentinel: sentinel, err: err}
}

// loadIdentitiesError is the aggregate failure formatError builds. It
// renders the exact legacy flattened message while exposing the
// underlying per-source errors (and any classification sentinels) to
// [errors.Is] / [errors.As].
type loadIdentitiesError struct {
	msg  string
	errs []error
}

func (e *loadIdentitiesError) Error() string { return e.msg }

func (e *loadIdentitiesError) Unwrap() []error { return e.errs }
