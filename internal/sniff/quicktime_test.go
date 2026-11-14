package sniff

import (
	"bytes"
	"encoding/binary"
	"math/rand/v2"
	"net/http"
	"testing"
)

// box builds a box header of the given size and type, then payload.
func box(size uint32, typ string, payload ...byte) []byte {
	b := binary.BigEndian.AppendUint32(nil, size)
	return append(append(b, typ...), payload...)
}

// box64 builds a header with size 1 and a 64-bit largesize.
func box64(large uint64, typ string) []byte {
	return binary.BigEndian.AppendUint64(box(1, typ), large)
}

// mvhd is a movie header's start: size, "mvhd", version, flags.
func mvhd(version byte) []byte {
	size := uint32(108)
	if version == 1 {
		size = 120
	}
	return box(size, "mvhd", version, 0, 0, 0)
}

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

// noise is deterministic arbitrary bytes standing in for media data.
func noise(n int, seed uint64) []byte {
	r := rand.New(rand.NewPCG(seed, seed))
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.Uint32())
	}
	return b
}

// Real-shaped classic QuickTime heads (no leading ftyp). The sizes are the
// ones the public samples carry where there is one.
var (
	// iPhone 14 Pro Live Photo movie (iOS 17): wide(8), then mdat.
	livePhotoMOV = cat(box(8, "wide"), box(5211469, "mdat"), noise(496, 1))
	// Fast-start: moov first, mvhd its first child.
	moovFirstMOV = cat(box(0x5584, "moov"), mvhd(0), noise(484, 2))
	freeMdatMOV  = cat(box(8, "free"), box(433779, "mdat"), noise(496, 3))
	skipMoovMOV  = cat(box(24, "skip"), make([]byte, 16), box(5445, "moov"), mvhd(1), noise(460, 4))
	// QuickTime 2-era preview: pnot(20) naming a PICT, the PICT, then moov.
	pnotMOV = cat(box(20, "pnot", 0x2f, 0x2b, 0x5c, 0x10, 0, 0, 'P', 'I', 'C', 'T', 0, 1),
		box(64, "PICT"), make([]byte, 56), box(9000, "moov"), mvhd(0), noise(400, 5))
	// wide, then an mdat over 4 GiB with a 64-bit size.
	largeMdatMOV = cat(box(8, "wide"), box64(5<<30, "mdat"), noise(488, 6))
	// Sample 3GP (metadata-extractor-images 3gp/sample.3gp): 3gp5 with 3gp4.
	sample3GP = cat(ftyp("3gp5", 0x100, "3gp5", "3gp4"), box(1716, "moov"), mvhd(0))
)

func TestDetectClassicQuickTime(t *testing.T) {
	all := allowAll(t)
	for _, tc := range []struct {
		name string
		head []byte
	}{
		{"wide+mdat (iPhone Live Photo)", livePhotoMOV},
		{"moov first", moovFirstMOV},
		{"free+mdat", freeMdatMOV},
		{"skip+moov (mvhd v1)", skipMoovMOV},
		{"pnot+PICT+moov", pnotMOV},
		{"wide+mdat with a 64-bit size", largeMdatMOV},
		{"wide+mdat to end of file (size 0)", cat(box(8, "wide"), box(0, "mdat"), noise(100, 7))},
		{"moov first with a 64-bit size", cat(box64(0x10000, "moov"), mvhd(0), noise(100, 8))},
		{"moov to end of file (size 0)", cat(box(0, "moov"), mvhd(0), noise(100, 9))},
		{"compressed moov (cmov+dcom)", cat(box(0x400, "moov"), box(0x3f8, "cmov"), box(12, "dcom"), []byte("zlib"), noise(100, 10))},
		{"reference movie (rmra+rmda)", cat(box(0x80, "moov"), box(0x78, "rmra"), box(0x70, "rmda"), noise(100, 11))},
		{"free, wide, mdat", cat(box(16, "free"), make([]byte, 8), box(8, "wide"), box(1000, "mdat"), noise(100, 12))},
		{"mdat that ends in the window, then moov", cat(box(24, "mdat"), noise(16, 13), box(500, "moov"), mvhd(0), noise(50, 14))},
		{"uuid between free and moov", cat(box(8, "free"), box(24, "uuid"), noise(16, 15), box(500, "moov"), mvhd(0))},
		{"just wide+mdat headers (16 bytes)", cat(box(8, "wide"), box(1000, "mdat"))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, ok := all.Detect(tc.head); !ok || got != QuickTime {
				t.Fatalf("Detect = %+v, %v; want video/quicktime", got, ok)
			}
		})
	}
}

// Near-misses: refused even with every type allowed.
func TestClassicQuickTimeNearMisses(t *testing.T) {
	all := allowAll(t)
	for _, tc := range []struct {
		name string
		head []byte
	}{
		{"lone mdat, then arbitrary bytes", cat(box(5211469, "mdat"), noise(504, 20))},
		{"lone mdat with a 64-bit size", cat(box64(5<<30, "mdat"), noise(496, 21))},
		{"lone free running past the window", cat(box(4096, "free"), noise(504, 22))},
		{"lone wide", box(8, "wide")},
		{"wide, then an mdat header cut by the window", cat(box(8, "wide"), box(1000, "mdat"))[:12]},
		{"four zero bytes, free, junk", cat(box(0, "free"), noise(100, 23))},
		{"four zero bytes, mdat, junk", cat(box(0, "mdat"), noise(100, 24))},
		{"size under 8", cat(box(4, "wide"), box(1000, "mdat"))},
		{"size 7 on the second box", cat(box(8, "wide"), box(7, "mdat"), noise(100, 25))},
		{"largesize under 16", cat(box(8, "wide"), box64(8, "mdat"), noise(100, 26))},
		{"largesize past 2^63", cat(box(8, "wide"), box64(1<<63, "mdat"), noise(100, 27))},
		{"wide not 8 bytes", cat(box(16, "wide"), make([]byte, 8), box(1000, "mdat"), noise(100, 28))},
		{"wide then garbage", cat(box(8, "wide"), []byte("garbage!"), noise(100, 29))},
		{"free with a plausible size, then garbage", cat(box(32, "free"), noise(24, 30), []byte("AAAAjunk"), noise(100, 31))},
		{"free+free, no movie", cat(box(8, "free"), box(4096, "free"), noise(100, 32))},
		{"mdat that ends in the window, then garbage", cat(box(24, "mdat"), noise(16, 33), []byte("\x00\x00\x01\x00junk"), noise(50, 34))},
		{"wide+mdat after an unrecognised first box", cat(box(8, "junk"), box(8, "wide"), box(1000, "mdat"))},
		{"uuid first", cat(box(24, "uuid"), noise(16, 35), box(8, "wide"), box(1000, "mdat"))},
		{"PICT first", cat(box(16, "PICT"), noise(8, 36), box(1000, "moov"), mvhd(0))},
		{"moov first, child not a movie header", cat(box(0x5584, "moov"), box(0x100, "trak"), noise(100, 37))},
		{"moov first, mvhd of the wrong size", cat(box(0x5584, "moov"), box(100, "mvhd", 0), noise(100, 38))},
		{"moov first, mvhd size and version disagree", cat(box(0x5584, "moov"), box(108, "mvhd", 1), noise(100, 39))},
		{"moov first, mvhd larger than the moov", cat(box(64, "moov"), mvhd(0), noise(100, 40))},
		{"empty moov, then an mvhd-shaped box", cat(box(8, "moov"), mvhd(0), noise(100, 41))},
		{"cmov without a 12-byte dcom", cat(box(0x400, "moov"), box(0x3f8, "cmov"), box(16, "dcom"), noise(100, 42))},
		{"text beginning with wide", []byte("wide mdat moov free skip pnot -- just words, " + string(bytes.Repeat([]byte("x"), 200)))},
		{"text spelling the iPhone layout", []byte("widewidemdatmdatfreemoov")},
		{"text spelling moov+mvhd", []byte("zzzzmoovaaaamvhd\x00 and then some prose to make it longer than a header")},
		{"ftyp with an unknown brand, then wide+mdat", cat(ftyp("zzzz", 0, "zzzz"), box(8, "wide"), box(1000, "mdat"))},
		{"zip", cat([]byte("PK\x03\x04\x14\x00\x00\x00\x08\x00"), noise(100, 43))},
		{"pdf", []byte("%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj\n")},
		{"jpeg 2000 codestream", cat([]byte("\xff\x4f\xff\x51\x00\x2f\x00\x00"), noise(100, 44))},
		{"jpeg 2000 file", cat(box(12, "jP  ", 0x0d, 0x0a, 0x87, 0x0a), ftyp("jp2 ", 0, "jp2 "))},
		{"dash segment (styp)", cat(box(24, "styp", 'm', 's', 'd', 'h', 0, 0, 0, 0, 'm', 's', 'd', 'h', 'm', 's', 'i', 'x'), box(1000, "moof"))},
		{"fragment (moof first)", cat(box(1000, "moof"), box(16, "mfhd"), noise(100, 45))},
		{"empty", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, ok := all.Detect(tc.head); ok {
				t.Fatalf("Detect = %+v, allowed; want refused", got)
			}
		})
	}
	// Images keep their own type: a PNG or JPEG prefix is never QuickTime.
	for _, head := range [][]byte{pngHead, jpegHead} {
		if got, ok := all.Detect(head); !ok || got.Class != Image {
			t.Errorf("Detect(%q) = %+v, %v", head[:4], got, ok)
		}
	}
}

func TestDetect3GPP(t *testing.T) {
	all := allowAll(t)
	for brand := range threeGPP {
		t.Run(brand, func(t *testing.T) {
			for _, head := range [][]byte{ftyp(brand, 0, brand), ftyp("isom", 0x200, "isom", brand)} {
				if got, ok := all.Detect(head); !ok || got != ThreeGPP {
					t.Fatalf("Detect(%q) = %+v, %v; want video/3gpp", head, got, ok)
				}
			}
		})
	}
	for brand := range threeGPP2 {
		t.Run(brand, func(t *testing.T) {
			for _, head := range [][]byte{ftyp(brand, 0, brand), ftyp("isom", 0x200, "isom", brand)} {
				if got, ok := all.Detect(head); !ok || got != ThreeGPP2 {
					t.Fatalf("Detect(%q) = %+v, %v; want video/3gpp2", head, got, ok)
				}
			}
		})
	}
	mp4 := Type{"video/mp4", "mp4", Video}
	for _, tc := range []struct {
		name string
		head []byte
		want Type
	}{
		{"sample.3gp (3gp5, 3gp4)", sample3GP, ThreeGPP},
		{"3gp5 with isom", ftyp("3gp5", 0, "3gp5", "isom"), ThreeGPP},
		{"3gp4 with isom (refused before GENZO-26)", ftyp("3gp4", 0, "isom", "3gp4"), ThreeGPP},
		{"3g2a declaring 3gp compatibility", ftyp("3g2a", 0, "3g2a", "3gp4"), ThreeGPP2},
		{"3gp major, 3g2 compatible: the major decides", ftyp("3gp6", 0, "3g2b"), ThreeGPP},
		{"generic major, both families compatible", ftyp("isom", 0, "3gp5", "3g2a"), ThreeGPP2},
		// Unchanged from v0.2.0.
		{"3g2 listing mp42 stays mp4", ftyp("3g2a", 0x10000, "3g2a", "mp42"), mp4},
		{"3gp listing mp41 stays mp4", ftyp("3gp5", 0, "3gp5", "mp41"), mp4},
		{"qt with a 3gp brand stays quicktime", ftyp("qt  ", 0, "qt  ", "3gp4"), QuickTime},
		{"heic with a 3gp brand stays heic", ftyp("heic", 0, "mif1", "3gp4"), HEIC},
		{"mif1 with a 3gp brand stays heif", ftyp("mif1", 0, "mif1", "3gp4"), HEIF},
		{"avif stays avif", libavifAVIF, AVIF},
		{"mov with ftyp stays quicktime", iphoneMOV, QuickTime},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, ok := all.Detect(tc.head); !ok || got != tc.want {
				t.Fatalf("Detect = %+v, %v; want %+v", got, ok, tc.want)
			}
		})
	}
	// Still refused: generic ISO media with no 3GPP brand (isom-only is not
	// mp4 by its brands, and was refused before), DASH segment brands.
	for name, head := range map[string][]byte{
		"isom only":           ftyp("isom", 0x200, "isom"),
		"isom, iso2, avc1":    ftyp("isom", 0x200, "isom", "iso2", "avc1"),
		"3gh9 (adaptive)":     ftyp("3gh9", 0, "3gh9", "isom"),
		"3gm9 (segment)":      ftyp("3gm9", 0, "3gm9"),
		"3gp3 (unregistered)": ftyp("3gp3", 0, "3gp3"),
	} {
		t.Run(name, func(t *testing.T) {
			if got, ok := all.Detect(head); ok {
				t.Fatalf("Detect = %+v, allowed; want refused", got)
			}
		})
	}
}

// identifyV020 is identify as released in v0.2.0 (GENZO-7), frozen, with
// fromBrandsV020 its brand table. GENZO-26 may only turn a head v0.2.0
// refused into QuickTime, 3GPP or 3GPP2; everything else must be identical.
func identifyV020(head []byte) (Type, bool) {
	v1 := map[string]Type{
		"image/png":  {"image/png", "png", Image},
		"image/jpeg": {"image/jpeg", "jpg", Image},
		"image/webp": {"image/webp", "webp", Image},
		"image/gif":  {"image/gif", "gif", Image},
		"video/mp4":  {"video/mp4", "mp4", Video},
		"video/webm": {"video/webm", "webm", Video},
	}
	if len(head) > HeadSize {
		head = head[:HeadSize]
	}
	mime := http.DetectContentType(head)
	if t, ok := v1[mime]; ok {
		if t.MIME == "video/webm" && ebmlDocType(head) != "webm" {
			return Type{MIME: "video/x-matroska"}, false
		}
		return t, true
	}
	if isSVG(head) {
		return SVG, true
	}
	if major, compat, ok := ftypBrands(head); ok {
		if t, ok := fromBrandsV020(major, compat); ok {
			return t, true
		}
		return Type{MIME: mime}, false
	}
	return Type{MIME: mime}, false
}

func fromBrandsV020(major string, compat []string) (Type, bool) {
	heic := Type{"image/heic", "heic", Image}
	heif := Type{"image/heif", "heif", Image}
	avif := Type{"image/avif", "avif", Image}
	switch major {
	case "heic", "heix", "hevc", "hevx":
		return heic, true
	case "avif", "avis":
		return avif, true
	case "qt  ":
		return Type{"video/quicktime", "mov", Video}, true
	case "mif1", "msf1":
		var hevc, av1 bool
		for _, b := range compat {
			switch b {
			case "heic", "heix", "hevc", "hevx":
				hevc = true
			case "avif", "avis":
				av1 = true
			}
		}
		switch {
		case hevc && !av1:
			return heic, true
		case av1 && !hevc:
			return avif, true
		default:
			return heif, true
		}
	}
	return Type{}, false
}

// checkAgainstV020 fails unless identify agrees with v0.2.0 on head, or
// turns a v0.2.0 refusal into one of the three GENZO-26 types.
func checkAgainstV020(t *testing.T, head []byte) {
	t.Helper()
	want, wantOK := identifyV020(head)
	got, gotOK := identify(head)
	if got == want && gotOK == wantOK {
		return
	}
	if !wantOK && gotOK && (got == QuickTime || got == ThreeGPP || got == ThreeGPP2) {
		return
	}
	t.Fatalf("identify(%q) = %+v, %v; v0.2.0 = %+v, %v", head, got, gotOK, want, wantOK)
}

// genzo26Corpus is every head these tests build, plus the earlier corpus.
func genzo26Corpus() [][]byte {
	return [][]byte{
		livePhotoMOV, moovFirstMOV, freeMdatMOV, skipMoovMOV, pnotMOV, largeMdatMOV, sample3GP,
		ftyp("3g2a", 0, "3g2a"), ftyp("3g2a", 0x10000, "3g2a", "mp42"), ftyp("isom", 0x200, "isom"),
		ftyp("isom", 0, "isom", "3gp4"), ftyp("qt  ", 0, "qt  ", "3gp4"), ftyp("mif1", 0, "mif1", "3gp4"),
		cat(box(5211469, "mdat"), noise(504, 20)), cat(box(0, "free"), noise(100, 23)),
		[]byte("widewidemdatmdatfreemoov"), []byte("zzzzmoovaaaamvhd\x00"),
		cat(ftyp("zzzz", 0, "zzzz"), box(8, "wide"), box(1000, "mdat")),
		// An SVG whose prolog spells a QuickTime layout stays SVG.
		[]byte("<!--\x00\x00\x00\x08wide\x00\x00\x00\x10mdat--><svg xmlns=\"http://www.w3.org/2000/svg\"/>"),
	}
}

func TestOnlyRefusalsChangeSinceV020(t *testing.T) {
	corpus := [][]byte{
		pngHead, jpegHead, gifHead, webpHead, mp4Head, webmHead, mkvHead, svgHead,
		iphoneHEIC, oldHEIC, nokiaHEIF, plainHEIF, libavifAVIF, avifSeq, iphoneMOV, isomMP4,
		[]byte("<!DOCTYPE html><html></html>"), []byte("hello"), []byte("%PDF-1.7\n"), {}, {0},
	}
	for _, head := range append(corpus, genzo26Corpus()...) {
		checkAgainstV020(t, head)
	}
	// And the default list still agrees with v1 on all of them.
	for _, head := range genzo26Corpus() {
		want, wantOK := detectV1(head)
		got, gotOK := Detect(head)
		if gotOK != wantOK || (wantOK && got != want) {
			t.Errorf("Detect(%q) = %+v, %v; v1 = %+v, %v", head, got, gotOK, want, wantOK)
		}
	}
}

func FuzzOnlyRefusalsChangeSinceV020(f *testing.F) {
	for _, h := range append([][]byte{pngHead, mp4Head, svgHead, iphoneHEIC, iphoneMOV}, genzo26Corpus()...) {
		f.Add(h)
	}
	f.Fuzz(func(t *testing.T, head []byte) {
		checkAgainstV020(t, head)
	})
}

// Arbitrary binary and text do not pass the classic QuickTime rule: random
// 512-byte heads, random printable-ASCII heads, and random heads behind a
// valid first box header of each accepted first type (so the evidence rule,
// not the first-type check, is what refuses them).
func TestClassicQuickTimeRefusesArbitraryBytes(t *testing.T) {
	r := rand.New(rand.NewPCG(26, 26))
	head := make([]byte, HeadSize)
	fill := func(from int) {
		for j := from; j < len(head); j++ {
			head[j] = byte(r.Uint32())
		}
	}
	for i := range 20_000 {
		fill(0)
		if isClassicQuickTime(head) {
			t.Fatalf("random head %d passed: %q", i, head[:32])
		}
		for j := range head {
			head[j] = byte(0x20 + r.IntN(0x5f))
		}
		if isClassicQuickTime(head) {
			t.Fatalf("random text %d passed: %q", i, head[:32])
		}
		for typ := range classicFirst {
			fill(8)
			binary.BigEndian.PutUint32(head, uint32(8+r.IntN(HeadSize)))
			copy(head[4:], typ)
			if isClassicQuickTime(head) {
				t.Fatalf("random %s-first head %d passed: %q", typ, i, head[:32])
			}
		}
	}
}
