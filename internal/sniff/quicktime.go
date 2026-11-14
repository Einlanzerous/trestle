package sniff

import "encoding/binary"

// Classic QuickTime (GENZO-26): a .mov that does not begin with an ftyp box.
// QuickTime predates ISO-BMFF and never required ftyp; Apple's own writers
// still emit "wide" then "mdat" first (an iPhone Live Photo movie is one),
// and older or fast-start files begin with "moov", "free", "skip" or "pnot".
//
// isClassicQuickTime accepts head only when ALL of these hold:
//
//  1. head parses from offset 0 as a run of top-level boxes, each with a
//     valid size: a 32-bit size >= 8, or size 1 with a 64-bit largesize >= 16
//     (and < 2^63), or size 0 ("to end of file", so necessarily the last box).
//     A box that ends inside head is followed by the next box header; the
//     run stops at a box that runs past the end of head, or at a trailing
//     header too short to read (head is a prefix of the upload).
//  2. Every box type is in classicTopLevel, and the first is one of
//     classicFirst: wide, mdat, free, skip, pnot, moov.
//  3. Every wide box is exactly 8 bytes (it is a placeholder header that a
//     writer later turns into a 64-bit mdat size; it has no payload).
//  4. There is positive evidence of a movie, at least one of:
//     a. an mdat box header immediately preceded by a wide, free or skip box
//     (the iPhone layout is wide(8) + mdat); or
//     b. a moov box whose first child is visible in head and is a
//     fixed-shape movie header: mvhd of exactly 108 bytes with version 0
//     or 120 bytes with version 1, cmov whose first child is a 12-byte
//     dcom, or rmra whose first child is an rmda that fits inside it.
//
// What this refuses on purpose: a head that is a lone mdat (or free, skip,
// pnot) box running past the window. Its payload is arbitrary bytes, so
// eight bytes of "size + mdat" would be the whole signature; such files are
// QuickTime in practice, but nothing else in the window says so.
//
// Text can never pass: every size field of a text file is >= 0x09090909, so
// its first box runs past any 512-byte window and is the only box seen,
// which leaves only rule 4b, whose movie headers need NUL bytes in their
// size fields. Random bytes pass with negligible probability (the first box
// type alone is 6 in 2^32, and then rule 4 must hold too).
func isClassicQuickTime(head []byte) bool {
	var (
		prev     string
		evidence bool
	)
	for off := 0; ; {
		rest := head[off:]
		if len(rest) < 8 {
			// End of head, or a header cut by it.
			return off > 0 && evidence
		}
		typ := string(rest[4:8])
		size, hdr, ok := boxSize(rest)
		if !ok {
			if hdr == 0 {
				return off > 0 && evidence // largesize cut by the end of head
			}
			return false
		}
		if (off == 0 && !classicFirst[typ]) || !classicTopLevel[typ] {
			return false
		}
		if typ == "wide" && size != 8 {
			return false
		}
		if typ == "mdat" && (prev == "wide" || prev == "free" || prev == "skip") {
			evidence = true
		}
		if typ == "moov" {
			payload := ^uint64(0) // size 0: unbounded, to the end of the file
			if size != 0 {
				payload = size - uint64(hdr)
			}
			if movieHeader(rest[hdr:], payload) {
				evidence = true
			}
		}
		// size 0 runs to the end of the file, so it is the last box.
		if size == 0 || size >= uint64(len(rest)) {
			return evidence
		}
		off += int(size)
		prev = typ
	}
}

// boxSize reads a box header's size. hdr is the header length (8, or 16 with
// a largesize). A box of size 0 extends to the end of the file and comes
// back as size 0. ok is false for an invalid size; hdr is then 0 when the
// header was cut by the end of b rather than invalid.
func boxSize(b []byte) (size uint64, hdr int, ok bool) {
	switch s := binary.BigEndian.Uint32(b[:4]); {
	case s == 0:
		return 0, 8, true
	case s == 1:
		if len(b) < 16 {
			return 0, 0, false
		}
		large := binary.BigEndian.Uint64(b[8:16])
		if large < 16 || large >= 1<<63 {
			return 0, 16, false
		}
		return large, 16, true
	case s < 8:
		return 0, 8, false
	default:
		return uint64(s), 8, true
	}
}

// movieHeader reports whether b, the start of a moov box's payload of
// payload bytes, begins with one of the fixed-shape children a movie box
// starts with, wholly inside the moov.
func movieHeader(b []byte, payload uint64) bool {
	if len(b) < 9 {
		return false
	}
	size := uint64(binary.BigEndian.Uint32(b[:4]))
	if size > payload {
		return false
	}
	switch string(b[4:8]) {
	case "mvhd":
		return size == 108 && b[8] == 0 || size == 120 && b[8] == 1
	case "cmov":
		// Compressed movie: a dcom box (size 12: header + algorithm) first.
		return size >= 8+12 && len(b) >= 16 &&
			binary.BigEndian.Uint32(b[8:12]) == 12 && string(b[12:16]) == "dcom"
	case "rmra":
		// Reference movie: rmda children.
		if size < 8+8 || len(b) < 16 {
			return false
		}
		child := uint64(binary.BigEndian.Uint32(b[8:12]))
		return string(b[12:16]) == "rmda" && child >= 8 && child <= size-8
	}
	return false
}

// classicFirst is what a classic QuickTime file may begin with (the types
// GENZO-26 found in real files). ftyp is not here: an ftyp-first file is
// decided by its brands alone.
var classicFirst = map[string]bool{
	"wide": true, "mdat": true, "free": true, "skip": true, "pnot": true, "moov": true,
}

// classicTopLevel is the QuickTime File Format's top-level atom set, less
// ftyp: what may follow the first box.
var classicTopLevel = map[string]bool{
	"wide": true, "mdat": true, "free": true, "skip": true, "pnot": true, "moov": true,
	"PICT": true, "uuid": true,
}
