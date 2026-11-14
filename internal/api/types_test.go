package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Einlanzerous/trestle/internal/sniff"
)

// Real-shaped heads (see internal/sniff for where each comes from).
var (
	heicHead = []byte("\x00\x00\x00\x2cftypheic\x00\x00\x00\x00mif1MiHBMiHEMiPrmiafheictmap\x00\x00\x00\x00meta")
	heifHead = []byte("\x00\x00\x00\x18ftypmif1\x00\x00\x00\x00mif1miaf\x00\x00\x01\x0emeta")
	avifHead = []byte("\x00\x00\x00\x20ftypavif\x00\x00\x00\x00avifmif1miafMA1B\x00\x00\x00\xf2meta")
	movHead  = []byte("\x00\x00\x00\x14ftypqt  \x20\x05\x03\x00qt  \x00\x00\x00\x08wide")
)

func photoTypes(t *testing.T) func(*Deps) {
	t.Helper()
	l, err := sniff.ParseAllowList("image/jpeg,image/heic,image/heif,image/avif,video/quicktime,video/mp4")
	if err != nil {
		t.Fatal(err)
	}
	return func(d *Deps) { d.Allowed = l }
}

// GENZO-7: the default instance still refuses every new type, with v1's
// message listing v1's types.
func TestDefaultConfigRefusesNewTypes(t *testing.T) {
	e := newEnv(t)
	for name, tc := range map[string]struct {
		head []byte
		mime string
	}{
		"heic": {heicHead, "image/heic"}, "heif": {heifHead, "image/heif"},
		"avif": {avifHead, "image/avif"}, "mov": {movHead, "video/quicktime"},
	} {
		rec := e.do(http.MethodPost, "/v1/uploads", aliceTok, bytes.NewReader(file(tc.head, 700, 1)))
		var b struct{ Error, Message string }
		_ = json.Unmarshal(rec.Body.Bytes(), &b)
		if rec.Code != http.StatusUnsupportedMediaType || b.Error != "unsupported_type" ||
			b.Message != "detected "+tc.mime+"; allowed: png, jpeg, webp, gif, svg, mp4, webm" {
			t.Errorf("%s upload = %d %s", name, rec.Code, rec.Body)
		}
	}
	if n := countFiles(t, e.root); n != 0 {
		t.Fatalf("refused uploads left %d files", n)
	}
}

func TestOptedInTypesUploadAndServe(t *testing.T) {
	for name, mutate := range map[string]func(*Deps){"public": func(*Deps) {}, "private": private} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, photoTypes(t), mutate)
			for _, tc := range []struct {
				name, mime, ext string
				data            []byte
			}{
				{"heic", "image/heic", "heic", file(heicHead, 700, 1)},
				{"heif", "image/heif", "heif", file(heifHead, 700, 2)},
				{"avif", "image/avif", "avif", file(avifHead, 700, 3)},
				{"mov", "video/quicktime", "mov", file(movHead, 8000, 4)}, // over the image cap, under the video cap
				{"mp4", "video/mp4", "mp4", file(mp4Head, 700, 5)},
			} {
				t.Run(tc.name, func(t *testing.T) {
					r := e.upload(aliceTok, "", tc.data, http.StatusCreated)
					if r.ContentType != tc.mime {
						t.Fatalf("response = %+v", r)
					}
					if name == "public" && r.URL != base+"/m/"+r.ID+"."+tc.ext {
						t.Fatalf("url = %q", r.URL)
					}
					b, err := os.ReadFile(filepath.Join(e.root, "index", r.ID+".json"))
					if err != nil {
						t.Fatal(err)
					}
					var stored struct {
						ContentType string `json:"content_type"`
						Ext         string `json:"ext"`
					}
					if err := json.Unmarshal(b, &stored); err != nil || stored.ContentType != tc.mime || stored.Ext != tc.ext {
						t.Fatalf("record = %s", b)
					}
					rec := e.do(http.MethodGet, "/v1/blobs/"+r.ID, aliceTok, nil)
					if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != tc.mime || !bytes.Equal(rec.Body.Bytes(), tc.data) {
						t.Fatalf("blob read = %d %q", rec.Code, rec.Header().Get("Content-Type"))
					}
					if name == "public" {
						rec := e.do(http.MethodGet, "/m/"+r.ID+"."+tc.ext, "", nil)
						if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != tc.mime ||
							rec.Header().Get("Content-Disposition") != `inline; filename="`+r.ID+"."+tc.ext+`"` {
							t.Fatalf("/m/ = %d %v", rec.Code, rec.Header())
						}
					}
				})
			}

			// Types not on this instance's list are refused, SVG and png included,
			// and the message lists this instance's types.
			for _, data := range [][]byte{svgDoc, file(pngHead, 700, 6)} {
				rec := e.do(http.MethodPost, "/v1/uploads", aliceTok, bytes.NewReader(data))
				if rec.Code != http.StatusUnsupportedMediaType ||
					!strings.HasSuffix(strings.TrimSpace(rec.Body.String()), `allowed: jpeg, mp4, heic, heif, avif, quicktime"}`) {
					t.Errorf("off-list upload = %d %s", rec.Code, rec.Body)
				}
			}
		})
	}
}

// New image types use the image cap; QuickTime uses the video cap.
func TestOptedInTypesUseTheirClassCap(t *testing.T) {
	e := newEnv(t, photoTypes(t))
	for _, head := range [][]byte{heicHead, heifHead, avifHead} {
		rec := e.do(http.MethodPost, "/v1/uploads", aliceTok, bytes.NewReader(file(head, 4097, 1)))
		if rec.Code != http.StatusRequestEntityTooLarge || errCode(t, rec) != "too_large" {
			t.Errorf("image over the image cap = %d %s", rec.Code, rec.Body)
		}
		e.upload(aliceTok, "", file(head, 4096, 2), http.StatusCreated)
	}
	e.upload(aliceTok, "", file(movHead, 16384, 3), http.StatusCreated)
	rec := e.do(http.MethodPost, "/v1/uploads", aliceTok, bytes.NewReader(file(movHead, 16385, 4)))
	if rec.Code != http.StatusRequestEntityTooLarge || errCode(t, rec) != "too_large" {
		t.Fatalf("mov over the video cap = %d %s", rec.Code, rec.Body)
	}
}
