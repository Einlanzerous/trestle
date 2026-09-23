// Package sniff decides what an upload is from its first bytes, and whether
// Trestle will hold it.
//
// The client's Content-Type and filename are never consulted. The type found
// here is stored on the record and is the only type /m/ ever serves, which is
// what stops "screenshot.png" serving text/html from the estate's origin.
package sniff

import (
	"bytes"
	"net/http"
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

var allowed = map[string]Type{
	"image/png":  {"image/png", "png", Image},
	"image/jpeg": {"image/jpeg", "jpg", Image},
	"image/webp": {"image/webp", "webp", Image},
	"image/gif":  {"image/gif", "gif", Image},
	"video/mp4":  {"video/mp4", "mp4", Video},
	"video/webm": {"video/webm", "webm", Video},
}

// Detect classifies head (at most HeadSize bytes of the upload). When the
// type is not allowed, ok is false and the returned MIME says what was seen,
// for the error message.
func Detect(head []byte) (t Type, ok bool) {
	if len(head) > HeadSize {
		head = head[:HeadSize]
	}
	mime := http.DetectContentType(head)
	if t, ok := allowed[mime]; ok {
		// DetectContentType calls anything with an EBML magic number webm,
		// Matroska included; the DocType is what actually says webm.
		if t.MIME == "video/webm" && ebmlDocType(head) != "webm" {
			return Type{MIME: "video/x-matroska"}, false
		}
		return t, true
	}
	if isSVG(head) {
		return SVG, true
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
