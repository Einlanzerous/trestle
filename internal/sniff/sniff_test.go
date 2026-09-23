package sniff

import (
	"strings"
	"testing"
)

// Fixtures are the smallest headers that carry each format's signature.
var (
	pngHead  = []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00")
	jpegHead = []byte("\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00")
	gifHead  = []byte("GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff")
	webpHead = []byte("RIFF\x24\x00\x00\x00WEBPVP8 \x18\x00\x00\x00")
	mp4Head  = []byte("\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00mp42isom\x00\x00\x00\x08free")
	// EBML header: EBMLVersion, EBMLReadVersion, MaxIDLength, MaxSizeLength,
	// DocType "webm", DocTypeVersion, DocTypeReadVersion.
	webmHead = []byte("\x1a\x45\xdf\xa3\x9f\x42\x86\x81\x01\x42\xf7\x81\x01\x42\xf2\x81\x04\x42\xf3\x81\x08\x42\x82\x84webm\x42\x87\x81\x04\x42\x85\x81\x02")
	mkvHead  = []byte("\x1a\x45\xdf\xa3\xa3\x42\x86\x81\x01\x42\xf7\x81\x01\x42\xf2\x81\x04\x42\xf3\x81\x08\x42\x82\x88matroska\x42\x87\x81\x04\x42\x85\x81\x02")
	svgHead  = []byte(`<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"/>`)
)

func TestDetectAllowedTypes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		head  []byte
		mime  string
		ext   string
		class Class
	}{
		{"png", pngHead, "image/png", "png", Image},
		{"jpeg", jpegHead, "image/jpeg", "jpg", Image},
		{"gif", gifHead, "image/gif", "gif", Image},
		{"webp", webpHead, "image/webp", "webp", Image},
		{"mp4", mp4Head, "video/mp4", "mp4", Video},
		{"webm", webmHead, "video/webm", "webm", Video},
		{"svg", svgHead, "image/svg+xml", "svg", Image},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := Detect(tc.head)
			if !ok || got.MIME != tc.mime || got.Ext != tc.ext || got.Class != tc.class {
				t.Fatalf("Detect = %+v, %v; want %s/%s class %d", got, ok, tc.mime, tc.ext, tc.class)
			}
		})
	}
}

func TestDetectSVGVariants(t *testing.T) {
	long := `<svg ` + strings.Repeat(`xmlns:a="http://example.com/a" `, 30) + `>`
	for name, doc := range map[string]string{
		"xml declaration":                 `<?xml version="1.0" encoding="UTF-8"?>` + "\n<svg/>",
		"leading comment":                 `<!-- made by hand --><svg></svg>`,
		"doctype":                         `<?xml version="1.0"?><!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd" [ <!ENTITY a "b"> ]><svg/>`,
		"bom":                             "\xef\xbb\xbf<svg>",
		"root tag past the 512-byte head": long,
	} {
		t.Run(name, func(t *testing.T) {
			if got, ok := Detect([]byte(doc)); !ok || got != SVG {
				t.Fatalf("Detect = %+v, %v; want SVG", got, ok)
			}
		})
	}
}

func TestDetectRefuses(t *testing.T) {
	for name, doc := range map[string][]byte{
		"html":           []byte("<!DOCTYPE html><html><script>alert(1)</script></html>"),
		"html with svg":  []byte("<html><body><svg></svg></body></html>"),
		"svg-ish prefix": []byte("<svgfoo/>"),
		"xml not svg":    []byte(`<?xml version="1.0"?><root/>`),
		"plain text":     []byte("hello"),
		"matroska":       mkvHead,
		"quicktime":      []byte("\x00\x00\x00\x14ftypqt  \x00\x00\x00\x00qt  "),
		"pdf":            []byte("%PDF-1.7\n"),
	} {
		t.Run(name, func(t *testing.T) {
			if got, ok := Detect(doc); ok {
				t.Fatalf("Detect = %+v, allowed; want refused", got)
			}
		})
	}
}

func TestDetectReportsWhatItSaw(t *testing.T) {
	got, _ := Detect([]byte("<html></html>"))
	if !strings.HasPrefix(got.MIME, "text/html") {
		t.Fatalf("MIME = %q, want text/html", got.MIME)
	}
}

func TestCaps(t *testing.T) {
	c := Caps{Image: 10, Video: 100}
	if c.For(SVG) != 10 || c.For(allowed["video/webm"]) != 100 || c.Max() != 100 {
		t.Fatalf("caps wrong: %d %d %d", c.For(SVG), c.For(allowed["video/webm"]), c.Max())
	}
}
