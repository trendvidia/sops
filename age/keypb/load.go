// Package keypb defines the PXF-formatted age key file schema and the
// helpers for reading it.
//
// The schema lives here (rather than in the protowire library) because
// it is a sops-specific use case. Consumers like the pxfed editor can
// import this package to read keys.pxf files directly without having
// to depend on the age driver.
package keypb

import (
	"fmt"
	"os"

	"github.com/trendvidia/protowire-go/encoding/pxf"
)

// FileExtension is the suffix used to flag a key file as PXF-formatted.
// The age driver dispatches on this extension to decide between the
// PXF parser and the legacy line-based parser.
const FileExtension = ".pxf"

// ReadFile reads the file at path and parses it as a PXF-encoded
// AgeKeyFile. It does not check the file extension — callers should
// dispatch on FileExtension before calling.
func ReadFile(path string) (*AgeKeyFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read age key file: %w", err)
	}
	return Parse(path, data)
}

// Parse decodes data as a PXF-encoded AgeKeyFile. source is used only
// for error messages (e.g. a file path or env var name). Use this when
// the bytes come from somewhere other than a file on disk — for
// example, the value of SOPS_AGE_KEY or the stdout of SOPS_AGE_KEY_CMD.
func Parse(source string, data []byte) (*AgeKeyFile, error) {
	var f AgeKeyFile
	if err := pxf.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse age key file %q: %w", source, err)
	}
	return &f, nil
}
