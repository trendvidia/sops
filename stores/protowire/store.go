// Package protowire implements a sops store that reads and writes the
// PXF (Protocol-buffer eXchange Format) text format from
// github.com/trendvidia/protowire-go. PXF is a typed, comment-aware text
// format with support for nested messages, lists, timestamps, durations,
// and bytes literals.
//
// This store uses the schema-free AST path of the protowire-go pxf package
// (Parse / FormatDocument), so sops trees of arbitrary shape round-trip
// without needing a proto descriptor.
package protowire //import "github.com/getsops/sops/v3/stores/protowire"

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/config"
	"github.com/getsops/sops/v3/stores"
	"github.com/trendvidia/protowire-go/encoding/pxf"
)

// Store handles storage of PXF data.
type Store struct {
	config config.ProtowireStoreConfig
}

// NewStore returns a Store that reads and writes the PXF text format.
func NewStore(c *config.ProtowireStoreConfig) *Store {
	return &Store{config: *c}
}

func (store *Store) Name() string {
	return "protowire"
}

// LoadEncryptedFile loads an encrypted PXF file onto a sops.Tree object.
func (store *Store) LoadEncryptedFile(in []byte) (sops.Tree, error) {
	branches, err := store.LoadPlainFile(in)
	if err != nil {
		return sops.Tree{}, err
	}
	branches, metadata, err := stores.ExtractMetadata(branches, stores.MetadataOpts{
		Flatten: stores.MetadataFlattenNone,
	})
	if err != nil {
		return sops.Tree{}, err
	}
	return sops.Tree{
		Branches: branches,
		Metadata: metadata,
	}, nil
}

// LoadPlainFile loads plaintext PXF file bytes onto a sops.TreeBranches object.
func (store *Store) LoadPlainFile(in []byte) (sops.TreeBranches, error) {
	doc, err := pxf.Parse(in)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal input data: %s", err)
	}
	branch, err := documentToTreeBranch(doc)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal input data: %s", err)
	}
	return sops.TreeBranches{branch}, nil
}

// EmitEncryptedFile returns the encrypted bytes of the PXF file corresponding
// to a sops.Tree runtime object.
func (store *Store) EmitEncryptedFile(in sops.Tree) ([]byte, error) {
	branches, err := stores.SerializeMetadata(in, stores.MetadataOpts{
		Flatten: stores.MetadataFlattenNone,
	})
	if err != nil {
		return nil, fmt.Errorf("Error marshaling metadata: %s", err)
	}
	return store.EmitPlainFile(branches)
}

// EmitPlainFile returns the plaintext bytes of the PXF file corresponding to
// a sops.TreeBranches runtime object.
func (store *Store) EmitPlainFile(in sops.TreeBranches) ([]byte, error) {
	if len(in) != 1 {
		return nil, errors.New("PXF stores a single document per file; got more than one tree branch")
	}
	doc, err := treeBranchToDocument(in[0])
	if err != nil {
		return nil, fmt.Errorf("Error marshaling to PXF: %s", err)
	}
	return pxf.FormatDocument(doc), nil
}

// EmitPlainFileTo streams the plaintext PXF output directly to w.
// Implements [sops.PlainFileEmitterTo].
//
// Caveat: protowire-go's `pxf.FormatDocument` returns `[]byte` (no
// streaming variant yet); this implementation still allocates one
// intermediate `[]byte` before writing. The FINAL plaintext does land
// in the caller's writer, which is the load-bearing seam for
// mlock-residency at the consumer boundary. A follow-up PR on
// protowire-go is tracked to add `pxf.FormatDocumentTo(io.Writer)` so
// this can become fully streaming.
func (store *Store) EmitPlainFileTo(w io.Writer, in sops.TreeBranches) error {
	if len(in) != 1 {
		return errors.New("PXF stores a single document per file; got more than one tree branch")
	}
	doc, err := treeBranchToDocument(in[0])
	if err != nil {
		return fmt.Errorf("Error marshaling to PXF: %s", err)
	}
	_, err = w.Write(pxf.FormatDocument(doc))
	return err
}

// EmitValue returns bytes corresponding to a single encoded value in a generic
// interface{} object.
func (store *Store) EmitValue(v interface{}) ([]byte, error) {
	val, err := goValueToPXFValue(v)
	if err != nil {
		return nil, err
	}
	return formatStandaloneValue(val), nil
}

// EmitExample returns the bytes corresponding to an example complex tree.
func (store *Store) EmitExample() []byte {
	out, err := store.EmitPlainFile(stores.ExampleComplexTree.Branches)
	if err != nil {
		panic(err)
	}
	return out
}

// HasSopsTopLevelKey checks whether a top-level "sops" key exists.
func (store *Store) HasSopsTopLevelKey(branch sops.TreeBranch) bool {
	return stores.HasSopsTopLevelKey(branch)
}

// --- Document → TreeBranch -------------------------------------------------

func documentToTreeBranch(doc *pxf.Document) (sops.TreeBranch, error) {
	var branch sops.TreeBranch
	branch = appendCommentsAsItems(branch, doc.LeadingComments)
	branch, err := appendEntriesToBranch(branch, doc.Entries)
	if err != nil {
		return nil, err
	}
	return branch, nil
}

func appendEntriesToBranch(branch sops.TreeBranch, entries []pxf.Entry) (sops.TreeBranch, error) {
	for _, e := range entries {
		switch entry := e.(type) {
		case *pxf.Assignment:
			branch = appendCommentsAsItems(branch, entry.LeadingComments)
			val, err := pxfValueToGoValue(entry.Value)
			if err != nil {
				return nil, err
			}
			branch = append(branch, sops.TreeItem{Key: entry.Key, Value: val})
			branch = appendInlineCommentAsItem(branch, entry.TrailingComment)
		case *pxf.MapEntry:
			branch = appendCommentsAsItems(branch, entry.LeadingComments)
			val, err := pxfValueToGoValue(entry.Value)
			if err != nil {
				return nil, err
			}
			branch = append(branch, sops.TreeItem{Key: entry.Key, Value: val})
			branch = appendInlineCommentAsItem(branch, entry.TrailingComment)
		case *pxf.Block:
			branch = appendCommentsAsItems(branch, entry.LeadingComments)
			sub, err := appendEntriesToBranch(nil, entry.Entries)
			if err != nil {
				return nil, err
			}
			branch = append(branch, sops.TreeItem{Key: entry.Name, Value: sub})
		default:
			return nil, fmt.Errorf("unexpected PXF entry type %T", entry)
		}
	}
	return branch, nil
}

func pxfValueToGoValue(v pxf.Value) (interface{}, error) {
	switch v := v.(type) {
	case *pxf.StringVal:
		return v.Value, nil
	case *pxf.IntVal:
		// Sops core only walks `int` and `float64` for numeric leaves
		// (see Tree.walkValue / ToBytes in sops.go). Decode as `int` when
		// the value fits in Go's int — that covers every realistic config
		// integer — and fall back to a string otherwise to avoid silent
		// precision loss.
		if n, err := strconv.ParseInt(v.Raw, 10, 0); err == nil {
			return int(n), nil
		}
		return v.Raw, nil
	case *pxf.FloatVal:
		f, err := strconv.ParseFloat(v.Raw, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid float %q: %v", v.Raw, err)
		}
		return f, nil
	case *pxf.BoolVal:
		return v.Value, nil
	case *pxf.NullVal:
		return nil, nil
	case *pxf.BytesVal:
		return v.Value, nil
	case *pxf.IdentVal:
		// Bare identifiers map back to strings (no proto enum context here).
		switch v.Name {
		case "true":
			return true, nil
		case "false":
			return false, nil
		case "null":
			return nil, nil
		}
		return v.Name, nil
	case *pxf.TimestampVal:
		return v.Value, nil
	case *pxf.DurationVal:
		return v.Value, nil
	case *pxf.ListVal:
		out := make([]interface{}, 0, len(v.Elements))
		for _, elem := range v.Elements {
			ev, err := pxfValueToGoValue(elem)
			if err != nil {
				return nil, err
			}
			out = append(out, ev)
		}
		return out, nil
	case *pxf.BlockVal:
		sub, err := appendEntriesToBranch(nil, v.Entries)
		if err != nil {
			return nil, err
		}
		return sub, nil
	}
	return nil, fmt.Errorf("unexpected PXF value type %T", v)
}

func appendCommentsAsItems(branch sops.TreeBranch, comments []pxf.Comment) sops.TreeBranch {
	for _, c := range comments {
		branch = append(branch, sops.TreeItem{
			Key:   sops.Comment{Value: stripCommentPrefix(c.Text)},
			Value: nil,
		})
	}
	return branch
}

func appendInlineCommentAsItem(branch sops.TreeBranch, comment string) sops.TreeBranch {
	if comment == "" {
		return branch
	}
	branch = append(branch, sops.TreeItem{
		Key:   sops.Comment{Value: stripCommentPrefix(comment), Inline: true},
		Value: nil,
	})
	return branch
}

func stripCommentPrefix(text string) string {
	switch {
	case strings.HasPrefix(text, "//"):
		return text[2:]
	case strings.HasPrefix(text, "#"):
		return text[1:]
	case strings.HasPrefix(text, "/*") && strings.HasSuffix(text, "*/"):
		return strings.TrimSpace(text[2 : len(text)-2])
	}
	return text
}

// --- TreeBranch → Document -------------------------------------------------

func treeBranchToDocument(branch sops.TreeBranch) (*pxf.Document, error) {
	doc := &pxf.Document{}
	entries, leading, err := branchToEntries(branch, true)
	if err != nil {
		return nil, err
	}
	doc.LeadingComments = leading
	doc.Entries = entries
	return doc, nil
}

// branchToEntries converts a sops.TreeBranch to a slice of PXF entries.
//
// At the top level (topLevel=true), keys must be valid PXF identifiers;
// non-identifier keys would produce an invalid document. Inside nested
// blocks (topLevel=false) a key may be an arbitrary string and is emitted
// as a MapEntry (`key: value`).
//
// Leading comments encountered before the first non-comment item are
// returned separately so the caller can attach them either to the document
// (top level) or to the enclosing block as part of the entry stream.
func branchToEntries(branch sops.TreeBranch, topLevel bool) ([]pxf.Entry, []pxf.Comment, error) {
	var (
		entries  []pxf.Entry
		pending  []pxf.Comment
		leading  []pxf.Comment
		started  bool
	)
	flushPendingTo := func(target *[]pxf.Comment) {
		*target = append(*target, pending...)
		pending = nil
	}
	for _, item := range branch {
		if c, ok := item.Key.(sops.Comment); ok {
			if c.Inline {
				if started && len(entries) > 0 {
					attachTrailingComment(entries[len(entries)-1], commentText(c))
					continue
				}
			}
			pending = append(pending, pxf.Comment{Text: commentText(c)})
			continue
		}
		if !started {
			leading = pending
			pending = nil
			started = true
		}
		key, err := keyToString(item.Key)
		if err != nil {
			return nil, nil, err
		}
		entry, err := buildEntry(key, item.Value, topLevel)
		if err != nil {
			return nil, nil, err
		}
		if len(pending) > 0 {
			setLeadingComments(entry, pending)
			pending = nil
		}
		entries = append(entries, entry)
	}
	// Trailing comments after the last non-comment item: attach to the last
	// entry's leading-comment block (best effort) so they aren't dropped.
	if len(pending) > 0 {
		if len(entries) > 0 {
			flushPendingTo(getLeadingCommentsPtr(entries[len(entries)-1]))
		} else {
			flushPendingTo(&leading)
		}
	}
	return entries, leading, nil
}

func buildEntry(key string, value interface{}, topLevel bool) (pxf.Entry, error) {
	if branch, ok := value.(sops.TreeBranch); ok {
		sub, leading, err := branchToEntries(branch, false)
		if err != nil {
			return nil, err
		}
		// A TreeBranch becomes either a Block (identifier key) or a
		// MapEntry holding a BlockVal (non-identifier key).
		if isPXFIdentifier(key) {
			block := &pxf.Block{Name: key, Entries: sub}
			if len(leading) > 0 {
				// Promote the block's own leading comments out of the
				// inner entry list to the block's LeadingComments field.
				block.LeadingComments = append(block.LeadingComments, leading...)
			}
			return block, nil
		}
		if topLevel {
			return nil, fmt.Errorf("PXF top-level keys must be identifiers; got %q", key)
		}
		// Non-identifier key with a TreeBranch value: emit as MapEntry
		// `key: { ... }` and hoist any leading comments before the BlockVal
		// onto the MapEntry.
		me := &pxf.MapEntry{
			Key:   key,
			Value: &pxf.BlockVal{Entries: sub},
		}
		if len(leading) > 0 {
			me.LeadingComments = append(me.LeadingComments, leading...)
		}
		return me, nil
	}
	v, err := goValueToPXFValue(value)
	if err != nil {
		return nil, err
	}
	if isPXFIdentifier(key) {
		return &pxf.Assignment{Key: key, Value: v}, nil
	}
	if topLevel {
		return nil, fmt.Errorf("PXF top-level keys must be identifiers; got %q", key)
	}
	return &pxf.MapEntry{Key: key, Value: v}, nil
}

func goValueToPXFValue(v interface{}) (pxf.Value, error) {
	switch v := v.(type) {
	case nil:
		return &pxf.NullVal{}, nil
	case string:
		return &pxf.StringVal{Value: v}, nil
	case bool:
		return &pxf.BoolVal{Value: v}, nil
	case int:
		return &pxf.IntVal{Raw: strconv.FormatInt(int64(v), 10)}, nil
	case int32:
		return &pxf.IntVal{Raw: strconv.FormatInt(int64(v), 10)}, nil
	case int64:
		return &pxf.IntVal{Raw: strconv.FormatInt(v, 10)}, nil
	case uint:
		return &pxf.IntVal{Raw: strconv.FormatUint(uint64(v), 10)}, nil
	case uint32:
		return &pxf.IntVal{Raw: strconv.FormatUint(uint64(v), 10)}, nil
	case uint64:
		return &pxf.IntVal{Raw: strconv.FormatUint(v, 10)}, nil
	case float32:
		return floatVal(float64(v)), nil
	case float64:
		return floatVal(v), nil
	case []byte:
		return &pxf.BytesVal{Value: v}, nil
	case time.Time:
		return &pxf.TimestampVal{Value: v, Raw: v.Format(time.RFC3339Nano)}, nil
	case time.Duration:
		return &pxf.DurationVal{Value: v, Raw: v.String()}, nil
	case []interface{}:
		elems := make([]pxf.Value, 0, len(v))
		for _, elem := range v {
			if _, ok := elem.(sops.Comment); ok {
				// Comments inside a list cannot be represented faithfully
				// as PXF list element annotations; drop them.
				continue
			}
			ev, err := goValueToPXFValue(elem)
			if err != nil {
				return nil, err
			}
			elems = append(elems, ev)
		}
		return &pxf.ListVal{Elements: elems}, nil
	case sops.TreeBranch:
		sub, leading, err := branchToEntries(v, false)
		if err != nil {
			return nil, err
		}
		bv := &pxf.BlockVal{Entries: sub}
		// Lost-comment guard: if there were leading comments at the start
		// of the branch, we have nowhere to put them on a BlockVal, so
		// reinsert them as Block-entry comments at the top of the list.
		if len(leading) > 0 && len(bv.Entries) > 0 {
			prependLeadingComments(bv.Entries[0], leading)
		}
		return bv, nil
	case fmt.Stringer:
		return &pxf.StringVal{Value: v.String()}, nil
	}
	return nil, fmt.Errorf("unsupported value type %T for PXF encoding", v)
}

// floatVal renders a Go float64 as a PXF FloatVal. PXF requires a literal
// that the lexer recognizes as a float, so whole numbers are emitted with a
// trailing ".0".
func floatVal(f float64) *pxf.FloatVal {
	raw := strconv.FormatFloat(f, 'g', -1, 64)
	if !strings.ContainsAny(raw, ".eE") {
		raw += ".0"
	}
	return &pxf.FloatVal{Raw: raw}
}

func keyToString(key interface{}) (string, error) {
	switch k := key.(type) {
	case string:
		return k, nil
	case fmt.Stringer:
		return k.String(), nil
	case int, int32, int64, uint, uint32, uint64:
		return fmt.Sprintf("%d", k), nil
	case bool:
		return strconv.FormatBool(k), nil
	}
	return "", fmt.Errorf("unsupported key type %T", key)
}

// isPXFIdentifier reports whether s is a valid PXF identifier
// (letter or '_' to start, then letters / digits / '_' / '.').
func isPXFIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case r == '_':
			continue
		case r >= 'a' && r <= 'z':
			continue
		case r >= 'A' && r <= 'Z':
			continue
		case i > 0 && (r >= '0' && r <= '9'):
			continue
		case i > 0 && r == '.':
			continue
		default:
			return false
		}
	}
	return true
}

func commentText(c sops.Comment) string {
	if strings.HasPrefix(c.Value, "#") || strings.HasPrefix(c.Value, "//") {
		return c.Value
	}
	return "#" + c.Value
}

// --- AST mutation helpers --------------------------------------------------

func setLeadingComments(entry pxf.Entry, comments []pxf.Comment) {
	switch e := entry.(type) {
	case *pxf.Assignment:
		e.LeadingComments = append(e.LeadingComments, comments...)
	case *pxf.MapEntry:
		e.LeadingComments = append(e.LeadingComments, comments...)
	case *pxf.Block:
		e.LeadingComments = append(e.LeadingComments, comments...)
	}
}

func prependLeadingComments(entry pxf.Entry, comments []pxf.Comment) {
	switch e := entry.(type) {
	case *pxf.Assignment:
		e.LeadingComments = append(append([]pxf.Comment{}, comments...), e.LeadingComments...)
	case *pxf.MapEntry:
		e.LeadingComments = append(append([]pxf.Comment{}, comments...), e.LeadingComments...)
	case *pxf.Block:
		e.LeadingComments = append(append([]pxf.Comment{}, comments...), e.LeadingComments...)
	}
}

func getLeadingCommentsPtr(entry pxf.Entry) *[]pxf.Comment {
	switch e := entry.(type) {
	case *pxf.Assignment:
		return &e.LeadingComments
	case *pxf.MapEntry:
		return &e.LeadingComments
	case *pxf.Block:
		return &e.LeadingComments
	}
	return new([]pxf.Comment)
}

func attachTrailingComment(entry pxf.Entry, text string) {
	switch e := entry.(type) {
	case *pxf.Assignment:
		e.TrailingComment = combineTrailing(e.TrailingComment, text)
	case *pxf.MapEntry:
		e.TrailingComment = combineTrailing(e.TrailingComment, text)
	}
}

func combineTrailing(existing, addition string) string {
	if existing == "" {
		return addition
	}
	return existing + " " + addition
}

// formatStandaloneValue renders a single PXF value. The pxf package only
// exposes a document-level formatter, so for EmitValue we wrap the value in
// a synthetic assignment, format it, then strip the synthetic prefix.
func formatStandaloneValue(v pxf.Value) []byte {
	doc := &pxf.Document{
		Entries: []pxf.Entry{&pxf.Assignment{Key: "v", Value: v}},
	}
	out := pxf.FormatDocument(doc)
	const prefix = "v = "
	if i := bytes.Index(out, []byte(prefix)); i >= 0 {
		out = out[i+len(prefix):]
	}
	return bytes.TrimRight(out, "\n")
}
