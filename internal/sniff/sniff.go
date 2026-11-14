// Package sniff decides what an upload is from its first bytes, and whether
// Trestle will hold it.
//
// The client's Content-Type and filename are never consulted. The type found
// here is stored on the record and is the only type /m/ ever serves, which is
// what stops "screenshot.png" serving text/html from the estate's origin.
package sniff

import (
	"bytes"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
)

// HeadSize is how much of an upload is read before deciding: all that
// http.DetectContentType looks at.
const HeadSize = 512

// Class picks which size cap applies.
type Class int

const (
	Image Class = iota
	Video
)

// Type is an allowed upload type.
type Type struct {
	MIME  string
	Ext   string
	Class Class
}

// SVG is the one type served as an attachment; api checks for it by value.
var SVG = Type{"image/svg+xml", "svg", Image}

// The ISO-BMFF types recognised from an ftyp box's brands (GENZO-7). None is
// on the default allow-list; an instance opts in with TRESTLE_ALLOWED_TYPES.
var (
	HEIC      = Type{"image/heic", "heic", Image}
	HEIF      = Type{"image/heif", "heif", Image}
	AVIF      = Type{"image/avif", "avif", Image}
	QuickTime = Type{"video/quicktime", "mov", Video}
)

// known is every type Trestle can recognise, in the order a 415 lists them.
var known = []Type{
	{"image/png", "png", Image},
	{"image/jpeg", "jpg", Image},
	{"image/webp", "webp", Image},
	{"image/gif", "gif", Image},
	SVG,
	{"video/mp4", "mp4", Video},
	{"video/webm", "webm", Video},
	HEIC,
	HEIF,
	AVIF,
	QuickTime,
}

// AllowList is the set of types an instance will hold, keyed by MIME type.
// A nil AllowList is the default one.
type AllowList map[string]Type

// allowed is the default allow-list: exactly v1's, so the public instance
// accepts nothing new unless TRESTLE_ALLOWED_TYPES says so.
var allowed = AllowList{
	"image/png":     known[0],
	"image/jpeg":    known[1],
	"image/webp":    known[2],
	"image/gif":     known[3],
	"image/svg+xml": SVG,
	"video/mp4":     known[5],
	"video/webm":    known[6],
}

// detected is what http.DetectContentType names itself: v1's table.
var detected = map[string]Type{
	"image/png":  known[0],
	"image/jpeg": known[1],
	"image/webp": known[2],
	"image/gif":  known[3],
	"video/mp4":  known[5],
	"video/webm": known[6],
}

// DefaultAllowList returns a copy of the default allow-list.
func DefaultAllowList() AllowList { return maps.Clone(allowed) }

// ParseAllowList reads a comma-separated list of MIME types. Empty means the
// default. A type Trestle cannot recognise is an error rather than a no-op:
// an operator who lists image/x-canon-cr2 expects it to be accepted, and it
// never would be.
func ParseAllowList(raw string) (AllowList, error) {
	if strings.TrimSpace(raw) == "" {
		return DefaultAllowList(), nil
	}
	l := AllowList{}
	for _, entry := range strings.Split(raw, ",") {
		mime := strings.ToLower(strings.TrimSpace(entry))
		if mime == "" {
			return nil, fmt.Errorf("an entry is empty")
		}
		i := slices.IndexFunc(known, func(t Type) bool { return t.MIME == mime })
		if i < 0 {
			return nil, fmt.Errorf("%q is not a type Trestle recognises (known: %s)", mime, knownMIMEs())
		}
		l[mime] = known[i]
	}
	return l, nil
}

func knownMIMEs() string {
	out := make([]string, len(known))
	for i, t := range known {
		out[i] = t.MIME
	}
	return strings.Join(out, ", ")
}

func (l AllowList) orDefault() AllowList {
	if l == nil {
		return allowed
	}
	return l
}

// Names lists the allowed types by short name (png, jpeg, svg, quicktime…)
// in a fixed order, for the 415 message.
func (l AllowList) Names() string {
	l = l.orDefault()
	var out []string
	for _, t := range known {
		if _, ok := l[t.MIME]; ok {
			sub := strings.TrimSuffix(t.MIME[strings.IndexByte(t.MIME, '/')+1:], "+xml")
			out = append(out, sub)
		}
	}
	return strings.Join(out, ", ")
}

// MIMEs lists the allowed MIME types in the same fixed order.
func (l AllowList) MIMEs() []string {
	l = l.orDefault()
	var out []string
	for _, t := range known {
		if _, ok := l[t.MIME]; ok {
			out = append(out, t.MIME)
		}
	}
	return out
}

// Detect classifies head against the default allow-list.
func Detect(head []byte) (Type, bool) { return allowed.Detect(head) }

// Detect classifies head (at most HeadSize bytes of the upload). When the
// type is not recognised or not on l, ok is false and the returned MIME says
// what was seen, for the error message.
func (l AllowList) Detect(head []byte) (Type, bool) {
	t, ok := identify(head)
	if !ok {
		return t, false
	}
	if _, ok := l.orDefault()[t.MIME]; !ok {
		return Type{MIME: t.MIME}, false
	}
	return t, true
}

// identify recognises head as one of known, whatever the allow-list.
//
// The v1 checks run first and unchanged, so on the default allow-list every
// input gets exactly v1's answer: the ISO-BMFF brand table only ever sees a
// head v1 refused. In particular anything http.DetectContentType calls
// video/mp4 (a major or compatible brand starting "mp4") stays mp4.
func identify(head []byte) (Type, bool) {
	if len(head) > HeadSize {
		head = head[:HeadSize]
	}
	mime := http.DetectContentType(head)
	if t, ok := detected[mime]; ok {
		// DetectContentType calls anything with an EBML magic number webm,
		// Matroska included; the DocType is what actually says webm.
		if t.MIME == "video/webm" && ebmlDocType(head) != "webm" {
			return Type{MIME: "video/x-matroska"}, false
		}
		return t, true
	}
	// SVG before ftyp, as in v1: a head isSVG accepts starts with '<',
	// whitespace or a BOM, so it can never be an ISO-BMFF file, while an
	// SVG prolog can put "ftyp" at bytes 4-8 ("<!--ftyp-->…").
	if isSVG(head) {
		return SVG, true
	}
	if major, compat, ok := ftypBrands(head); ok {
		// An ftyp box is decided by its brands alone: a brand not in the
		// table is refused here, never handed on to a looser check.
		if t, ok := fromBrands(major, compat); ok {
			return t, true
		}
		return Type{MIME: mime}, false
	}
	return Type{MIME: mime}, false
}

// Caps are the per-class size limits.
type Caps struct {
	Image int64
	Video int64
}

// For returns the cap for t.
func (c Caps) For(t Type) int64 {
	if t.Class == Video {
		return c.Video
	}
	return c.Image
}

// Max is the largest cap: the ceiling applied before the type is known.
func (c Caps) Max() int64 { return max(c.Image, c.Video) }

// isSVG reports whether head is an XML document whose root element is svg.
//
// A hand scan of the prolog rather than encoding/xml: tools routinely write
// root tags with enough namespace attributes to run past 512 bytes, and a
// tokenizer handed a truncated start tag reports an error, not an element.
// So this skips what may precede the root (BOM, whitespace, <?…?>, comments,
// a DOCTYPE) and then only needs to see "<svg" and a name terminator.
func isSVG(head []byte) bool {
	b := bytes.TrimPrefix(head, []byte("\xef\xbb\xbf"))
	for {
		b = bytes.TrimLeft(b, " \t\r\n")
		var ok bool
		switch {
		case bytes.HasPrefix(b, []byte("<?")):
			b, ok = skipPast(b, "?>")
		case bytes.HasPrefix(b, []byte("<!--")):
			b, ok = skipPast(b, "-->")
		case bytes.HasPrefix(b, []byte("<!DOCTYPE")):
			b, ok = skipDoctype(b)
		case bytes.HasPrefix(b, []byte("<svg")):
			rest := b[len("<svg"):]
			return len(rest) == 0 || strings.IndexByte(" \t\r\n/>", rest[0]) >= 0
		default:
			return false
		}
		if !ok {
			return false
		}
	}
}

func skipPast(b []byte, end string) ([]byte, bool) {
	i := bytes.Index(b, []byte(end))
	if i < 0 {
		return nil, false
	}
	return b[i+len(end):], true
}

// skipDoctype steps over <!DOCTYPE …>, including an internal subset in [ ].
func skipDoctype(b []byte) ([]byte, bool) {
	inSubset := false
	for i, c := range b {
		switch {
		case c == '[':
			inSubset = true
		case c == ']':
			inSubset = false
		case c == '>' && !inSubset:
			return b[i+1:], true
		}
	}
	return nil, false
}

// ebmlDocType returns the DocType string from an EBML header, or "" if head
// does not hold a complete one.
func ebmlDocType(head []byte) string {
	const ebmlID, docTypeID = 0x1A45DFA3, 0x4282
	id, b, ok := readID(head)
	if !ok || id != ebmlID {
		return ""
	}
	size, b, ok := readSize(b)
	if !ok {
		return ""
	}
	if size < uint64(len(b)) {
		b = b[:size]
	}
	for len(b) > 0 {
		if id, b, ok = readID(b); !ok {
			return ""
		}
		if size, b, ok = readSize(b); !ok || size > uint64(len(b)) {
			return ""
		}
		if id == docTypeID {
			return string(bytes.TrimRight(b[:size], "\x00"))
		}
		b = b[size:]
	}
	return ""
}

// vintLen is the length of an EBML variable-size integer, from the position
// of the first set bit in its first byte.
func vintLen(first byte) int {
	for n := 1; n <= 8; n++ {
		if first&(0x80>>(n-1)) != 0 {
			return n
		}
	}
	return 0
}

// readID reads an element ID, which keeps its length-marker bit.
func readID(b []byte) (uint64, []byte, bool) {
	if len(b) == 0 {
		return 0, nil, false
	}
	n := vintLen(b[0])
	if n == 0 || n > 4 || n > len(b) {
		return 0, nil, false
	}
	var v uint64
	for _, c := range b[:n] {
		v = v<<8 | uint64(c)
	}
	return v, b[n:], true
}

// readSize reads an element data size, which drops its length-marker bit.
func readSize(b []byte) (uint64, []byte, bool) {
	if len(b) == 0 {
		return 0, nil, false
	}
	n := vintLen(b[0])
	if n == 0 || n > len(b) {
		return 0, nil, false
	}
	v := uint64(b[0] & (0xFF >> n))
	for _, c := range b[1:n] {
		v = v<<8 | uint64(c)
	}
	return v, b[n:], true
}
