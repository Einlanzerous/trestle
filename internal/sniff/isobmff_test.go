package sniff

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
)

// ftyp builds a leading ftyp box: size, "ftyp", major, minor, compatibles.
func ftyp(major string, minor uint32, compat ...string) []byte {
	var b bytes.Buffer
	size := 16 + 4*len(compat)
	b.Write([]byte{byte(size >> 24), byte(size >> 16), byte(size >> 8), byte(size)})
	b.WriteString("ftyp" + major)
	b.Write([]byte{byte(minor >> 24), byte(minor >> 16), byte(minor >> 8), byte(minor)})
	for _, c := range compat {
		b.WriteString(c)
	}
	return b.Bytes()
}

// Real-shaped heads: the ftyp boxes these producers write, followed by the
// start of the next box.
var (
	iphoneHEIC  = append(ftyp("heic", 0, "mif1", "MiHB", "MiHE", "MiPr", "miaf", "heic", "tmap"), "\x00\x00\x00\x00meta"...)
	oldHEIC     = append(ftyp("heic", 0, "mif1", "heic"), "\x00\x00\x01\x0emeta"...)
	nokiaHEIF   = append(ftyp("mif1", 0, "mif1", "heic"), "\x00\x00\x01\x0emeta"...)
	plainHEIF   = append(ftyp("mif1", 0, "mif1", "miaf"), "\x00\x00\x01\x0emeta"...)
	libavifAVIF = append(ftyp("avif", 0, "avif", "mif1", "miaf", "MA1B"), "\x00\x00\x00\xf2meta"...)
	avifSeq     = append(ftyp("avis", 0, "avis", "msf1", "iso8", "mif1", "miaf", "MA1B"), "\x00\x00\x00\xf2meta"...)
	iphoneMOV   = append(ftyp("qt  ", 0x20050300, "qt  "), "\x00\x00\x00\x08wide"...)
	isomMP4     = append(ftyp("isom", 0x200, "isom", "iso2", "avc1", "mp41"), "\x00\x00\x00\x08free"...)
)

func allowAll(t *testing.T) AllowList {
	t.Helper()
	l, err := ParseAllowList(knownMIMEs())
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestDetectISOBMFFBrands(t *testing.T) {
	all := allowAll(t)
	for _, tc := range []struct {
		name string
		head []byte
		want Type
	}{
		{"heic (iPhone)", iphoneHEIC, HEIC},
		{"heic (older iOS)", oldHEIC, HEIC},
		{"heix", ftyp("heix", 0, "mif1", "heix"), HEIC},
		{"hevc sequence", ftyp("hevc", 0, "msf1", "hevc"), HEIC},
		{"hevx", ftyp("hevx", 0, "msf1", "hevx"), HEIC},
		{"heif (mif1, no codec brand)", plainHEIF, HEIF},
		{"heif (msf1, no codec brand)", ftyp("msf1", 0, "msf1", "iso8"), HEIF},
		{"mif1 declaring HEVC", nokiaHEIF, HEIC},
		{"mif1 declaring AV1", ftyp("mif1", 0, "mif1", "avif", "miaf"), AVIF},
		{"mif1 declaring both", ftyp("mif1", 0, "mif1", "avif", "heic"), HEIF},
		{"avif (libavif)", libavifAVIF, AVIF},
		{"avis", avifSeq, AVIF},
		{"mov (iPhone)", iphoneMOV, QuickTime},
		{"mp4 (mp42)", mp4Head, Type{"video/mp4", "mp4", Video}},
		{"mp4 (isom with mp41)", isomMP4, Type{"video/mp4", "mp4", Video}},
		// The v1 mp4 rule runs first: a compatible mp4 brand wins over the
		// major brand, so the default list's answers are unchanged.
		{"qt declaring mp4 compatibility", ftyp("qt  ", 0, "qt  ", "mp42"), Type{"video/mp4", "mp4", Video}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := all.Detect(tc.head)
			if !ok || got != tc.want {
				t.Fatalf("Detect = %+v, %v; want %+v", got, ok, tc.want)
			}
		})
	}
}

// An ftyp box is decided by its brands; anything the table does not know is
// refused even with every type allowed, and is not handed to a looser check.
func TestDetectUnknownFtypIsRefused(t *testing.T) {
	all := allowAll(t)
	for name, head := range map[string][]byte{
		"canon cr3 (RAW, out of scope)": ftyp("crx ", 1, "crx ", "isom"),
		"3gp":                           ftyp("3gp4", 0, "isom", "3gp4"),
		"isom without mp4":              ftyp("isom", 0x200, "isom", "iso2", "avc1"),
		"heim (not in the table)":       ftyp("heim", 0, "mif1", "heim"),
		"jpeg 2000":                     ftyp("jp2 ", 0, "jp2 "),
		"box too small":                 []byte("\x00\x00\x00\x08ftypheic\x00\x00\x00\x00"),
		"size 0":                        []byte("\x00\x00\x00\x00ftypheic\x00\x00\x00\x00mif1"),
		"size not a multiple of 4":      []byte("\x00\x00\x00\x13ftypheic\x00\x00\x00\x00mif1"),
		"truncated before the brand":    []byte("\x00\x00\x00\x18ftyp"),
		"ftyp with svg after it":        append(ftyp("zzzz", 0), `<svg xmlns="http://www.w3.org/2000/svg"/>`...),
	} {
		t.Run(name, func(t *testing.T) {
			if got, ok := all.Detect(head); ok {
				t.Fatalf("Detect = %+v, allowed; want refused", got)
			}
		})
	}
}

// GENZO-7: the default list does not grow. Every new type is recognised and
// then refused, and the refusal names what was seen.
func TestDefaultListRefusesNewTypes(t *testing.T) {
	for name, tc := range map[string]struct {
		head []byte
		mime string
	}{
		"heic": {iphoneHEIC, "image/heic"},
		"heif": {plainHEIF, "image/heif"},
		"avif": {libavifAVIF, "image/avif"},
		"mov":  {iphoneMOV, "video/quicktime"},
	} {
		t.Run(name, func(t *testing.T) {
			for _, l := range []AllowList{nil, DefaultAllowList()} {
				got, ok := l.Detect(tc.head)
				if ok || got.MIME != tc.mime || got.Ext != "" {
					t.Fatalf("Detect = %+v, %v; want refused as %s", got, ok, tc.mime)
				}
			}
			if got, ok := Detect(tc.head); ok {
				t.Fatalf("package Detect = %+v, allowed", got)
			}
		})
	}
}

// detectV1 is Detect as it was before GENZO-7, frozen, so the default list
// can be held to it input for input.
func detectV1(head []byte) (Type, bool) {
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
	return Type{MIME: mime}, false
}

func TestDefaultListAgreesWithV1(t *testing.T) {
	corpus := [][]byte{
		pngHead, jpegHead, gifHead, webpHead, mp4Head, webmHead, mkvHead, svgHead,
		iphoneHEIC, oldHEIC, nokiaHEIF, plainHEIF, libavifAVIF, avifSeq, iphoneMOV, isomMP4,
		ftyp("qt  ", 0, "qt  ", "mp42"), ftyp("heic", 0, "mif1", "mp41"), ftyp("crx ", 1, "crx "),
		[]byte("\x00\x00\x00\x08ftypheic"), []byte("<!DOCTYPE html><html></html>"), []byte("hello"),
		[]byte("%PDF-1.7\n"), []byte(`<?xml version="1.0"?><svg/>`), {}, {0},
		// SVG prologs that put "ftyp" at bytes 4-8 (found in review of #6).
		[]byte("<!--ftyp-->\n<svg xmlns=\"http://www.w3.org/2000/svg\"/>"),
		[]byte(`<?a ftyp?><svg xmlns="http://www.w3.org/2000/svg"/>`),
	}
	for i, head := range corpus {
		want, wantOK := detectV1(head)
		got, gotOK := Detect(head)
		if gotOK != wantOK || (wantOK && got != want) {
			t.Errorf("corpus[%d]: Detect = %+v, %v; v1 = %+v, %v", i, got, gotOK, want, wantOK)
		}
	}
}

func FuzzDefaultListAgreesWithV1(f *testing.F) {
	for _, h := range [][]byte{
		pngHead, mp4Head, webmHead, svgHead, iphoneHEIC, iphoneMOV, libavifAVIF,
		[]byte("<!--ftyp-->\n<svg/>"), []byte("<?a ftyp?><svg/>"),
	} {
		f.Add(h)
	}
	f.Fuzz(func(t *testing.T, head []byte) {
		want, wantOK := detectV1(head)
		got, gotOK := Detect(head)
		if gotOK != wantOK || (wantOK && got != want) {
			t.Fatalf("Detect = %+v, %v; v1 = %+v, %v", got, gotOK, want, wantOK)
		}
	})
}

func TestParseAllowList(t *testing.T) {
	def, err := ParseAllowList("  ")
	if err != nil || def.Names() != "png, jpeg, webp, gif, svg, mp4, webm" || len(def) != 7 {
		t.Fatalf("default = %v (%s), %v", def, def.Names(), err)
	}
	if AllowList(nil).Names() != def.Names() {
		t.Fatalf("nil list names %q", AllowList(nil).Names())
	}

	l, err := ParseAllowList(" image/JPEG, image/heic,video/quicktime ,image/heic")
	if err != nil {
		t.Fatal(err)
	}
	if l.Names() != "jpeg, heic, quicktime" || strings.Join(l.MIMEs(), ",") != "image/jpeg,image/heic,video/quicktime" {
		t.Fatalf("parsed = %s / %v", l.Names(), l.MIMEs())
	}
	if _, ok := l.Detect(pngHead); ok {
		t.Fatal("png allowed by a list without it")
	}
	if _, ok := l.Detect(svgHead); ok {
		t.Fatal("svg allowed by a list without it")
	}

	for _, bad := range []string{"image/x-canon-cr2", "heic", "image/png,,image/gif", "image/svg", "video/x-matroska"} {
		if _, err := ParseAllowList(bad); err == nil {
			t.Errorf("ParseAllowList(%q) accepted", bad)
		}
	}
}

func TestNewTypesUseTheirClassCap(t *testing.T) {
	c := Caps{Image: 10, Video: 100}
	for _, typ := range []Type{HEIC, HEIF, AVIF} {
		if c.For(typ) != 10 {
			t.Errorf("%s cap = %d, want the image cap", typ.MIME, c.For(typ))
		}
	}
	if c.For(QuickTime) != 100 {
		t.Errorf("quicktime cap = %d, want the video cap", c.For(QuickTime))
	}
}
