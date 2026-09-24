package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Einlanzerous/trestle/internal/blob"
	"github.com/Einlanzerous/trestle/internal/config"
	"github.com/Einlanzerous/trestle/internal/index"
	"github.com/Einlanzerous/trestle/internal/sniff"
)

const (
	aliceTok = "alice-plaintext-token-AAAAAAAAAAAAAAAAAAAAAAAA"
	bobTok   = "bob-plaintext-token-BBBBBBBBBBBBBBBBBBBBBBBBBB"
	wrongTok = "wrong-plaintext-token-CCCCCCCCCCCCCCCCCCCCCCCC"
	base     = "https://media.example.test"
)

var (
	pngHead  = []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00")
	jpegHead = []byte("\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00")
	gifHead  = []byte("GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff")
	webpHead = []byte("RIFF\x24\x00\x00\x00WEBPVP8 \x18\x00\x00\x00")
	mp4Head  = []byte("\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00mp42isom\x00\x00\x00\x08free")
	webmHead = []byte("\x1a\x45\xdf\xa3\x9f\x42\x86\x81\x01\x42\xf7\x81\x01\x42\xf2\x81\x04\x42\xf3\x81\x08\x42\x82\x84webm\x42\x87\x81\x04\x42\x85\x81\x02")
	svgDoc   = []byte(`<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`)
)

// file pads a header out to n bytes; the tail varies with seed so two files
// with the same header hash differently.
func file(head []byte, n int, seed byte) []byte {
	b := bytes.Repeat([]byte{seed}, n)
	copy(b, head)
	return b
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type env struct {
	t     *testing.T
	root  string
	h     http.Handler
	logs  *syncBuf
	mu    sync.Mutex
	clock time.Time
	ready error
	// bodies collects every response body, to assert no token ever leaks.
	bodies strings.Builder
}

func newEnv(t *testing.T, mutate ...func(*Deps)) *env {
	t.Helper()
	e := &env{t: t, root: t.TempDir(), logs: &syncBuf{}, clock: time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)}
	blobs, err := blob.NewLocal(e.root)
	if err != nil {
		t.Fatal(err)
	}
	ix, err := index.Open(filepath.Join(e.root, "index"))
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := config.ParseTokens("alice=" + sha([]byte(aliceTok)) + ",bob=" + sha([]byte(bobTok)))
	if err != nil {
		t.Fatal(err)
	}
	d := Deps{
		Logger:        slog.New(slog.NewJSONHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Index:         ix,
		Blobs:         blobs,
		Tokens:        tokens,
		PublicBaseURL: base,
		Caps:          sniff.Caps{Image: 4096, Video: 16384},
		Quota:         1 << 20,
		Version:       "dev",
		Ready: func() error {
			e.mu.Lock()
			defer e.mu.Unlock()
			return e.ready
		},
		Now: e.now,
	}
	for _, m := range mutate {
		m(&d)
	}
	e.h = NewRouter(d)
	t.Cleanup(func() {
		all := e.logs.String() + e.bodies.String()
		for _, tok := range []string{aliceTok, bobTok, wrongTok} {
			if strings.Contains(all, tok) {
				t.Errorf("a plaintext token reached a log line or a response body")
			}
		}
	})
	return e
}

func (e *env) now() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.clock
}

func (e *env) advance(d time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.clock = e.clock.Add(d)
}

func (e *env) do(method, target, token string, body io.Reader, hdr ...string) *httptest.ResponseRecorder {
	e.t.Helper()
	req := httptest.NewRequest(method, target, body)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	e.bodies.WriteString(rec.Body.String())
	return rec
}

type uploadResp struct {
	ID          string     `json:"id"`
	SHA256      string     `json:"sha256"`
	URL         string     `json:"url"`
	Bytes       int64      `json:"bytes"`
	ContentType string     `json:"content_type"`
	ExpiresAt   *time.Time `json:"expires_at"`
	Existed     bool       `json:"existed"`
}

func (e *env) upload(token, query string, data []byte, wantStatus int) uploadResp {
	e.t.Helper()
	rec := e.do(http.MethodPost, "/v1/uploads"+query, token, bytes.NewReader(data), "Content-Type", "image/png")
	if rec.Code != wantStatus {
		e.t.Fatalf("POST /v1/uploads%s = %d %s, want %d", query, rec.Code, rec.Body, wantStatus)
	}
	var r uploadResp
	if wantStatus == http.StatusCreated {
		if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
			e.t.Fatal(err)
		}
	}
	return r
}

func errCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var b struct{ Error, Message string }
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil || b.Message == "" {
		t.Fatalf("error body %q is not {error,message}: %v", rec.Body, err)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("error Content-Type = %q", ct)
	}
	return b.Error
}

// countFiles counts regular files under dir.
func countFiles(t *testing.T, dir string) int {
	t.Helper()
	n := 0
	err := filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			n++
		}
		return err
	})
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return n
}

func TestUploadAndServeEachAllowedType(t *testing.T) {
	e := newEnv(t)
	for _, tc := range []struct {
		name, mime, ext string
		data            []byte
	}{
		{"png", "image/png", "png", file(pngHead, 700, 1)},
		{"jpeg", "image/jpeg", "jpg", file(jpegHead, 700, 2)},
		{"gif", "image/gif", "gif", file(gifHead, 700, 3)},
		{"webp", "image/webp", "webp", file(webpHead, 700, 4)},
		{"mp4", "video/mp4", "mp4", file(mp4Head, 700, 5)},
		{"webm", "video/webm", "webm", file(webmHead, 700, 6)},
		{"svg", "image/svg+xml", "svg", svgDoc},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := e.upload(aliceTok, "", tc.data, http.StatusCreated)
			h := sha(tc.data)
			if r.ID != h || r.SHA256 != h || r.ContentType != tc.mime || r.Bytes != int64(len(tc.data)) ||
				r.URL != base+"/m/"+h+"."+tc.ext || r.Existed || r.ExpiresAt != nil {
				t.Fatalf("response = %+v", r)
			}

			rec := e.do(http.MethodGet, "/m/"+h+"."+tc.ext, "", nil)
			if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), tc.data) {
				t.Fatalf("GET = %d, body match %v", rec.Code, bytes.Equal(rec.Body.Bytes(), tc.data))
			}
			disposition := `inline; filename="` + h + "." + tc.ext + `"`
			if tc.ext == "svg" {
				disposition = `attachment; filename="` + h + `.svg"`
			}
			want := map[string]string{
				"Content-Type":                 tc.mime,
				"Cache-Control":                "public, max-age=31536000, immutable",
				"ETag":                         `"` + h + `"`,
				"Last-Modified":                "Tue, 22 Sep 2026 12:00:00 GMT",
				"X-Content-Type-Options":       "nosniff",
				"Cross-Origin-Resource-Policy": "cross-origin",
				"Access-Control-Allow-Origin":  "*",
				"Content-Disposition":          disposition,
			}
			for k, v := range want {
				if got := rec.Header().Get(k); got != v {
					t.Errorf("%s = %q, want %q", k, got, v)
				}
			}
			csp := rec.Header().Get("Content-Security-Policy")
			if tc.ext == "svg" && csp != "default-src 'none'; style-src 'unsafe-inline'; sandbox" {
				t.Errorf("SVG CSP = %q", csp)
			}
			if tc.ext != "svg" && csp != "" {
				t.Errorf("non-SVG got a CSP: %q", csp)
			}
		})
	}
}

func TestClientContentTypeIsIgnored(t *testing.T) {
	e := newEnv(t)
	html := []byte("<!DOCTYPE html><html><script>alert(document.cookie)</script></html>")
	rec := e.do(http.MethodPost, "/v1/uploads", aliceTok, bytes.NewReader(html), "Content-Type", "image/png")
	if rec.Code != http.StatusUnsupportedMediaType || errCode(t, rec) != "unsupported_type" {
		t.Fatalf("html upload = %d %s", rec.Code, rec.Body)
	}
	if n := countFiles(t, e.root); n != 0 {
		t.Fatalf("a refused upload left %d files on disk", n)
	}
}

func TestEmptyBody(t *testing.T) {
	e := newEnv(t)
	rec := e.do(http.MethodPost, "/v1/uploads", aliceTok, bytes.NewReader(nil))
	if rec.Code != http.StatusBadRequest || errCode(t, rec) != "empty_body" {
		t.Fatalf("empty = %d %s", rec.Code, rec.Body)
	}
}

func TestSizeCaps(t *testing.T) {
	e := newEnv(t)
	// Over the image cap but under the video cap: the sniffed type's cap wins.
	rec := e.do(http.MethodPost, "/v1/uploads", aliceTok, bytes.NewReader(file(pngHead, 4097, 1)))
	if rec.Code != http.StatusRequestEntityTooLarge || errCode(t, rec) != "too_large" {
		t.Fatalf("over image cap = %d %s", rec.Code, rec.Body)
	}
	e.upload(aliceTok, "", file(pngHead, 4096, 1), http.StatusCreated)
	e.upload(aliceTok, "", file(mp4Head, 8000, 1), http.StatusCreated)

	rec = e.do(http.MethodPost, "/v1/uploads", aliceTok, bytes.NewReader(file(mp4Head, 16385, 2)))
	if rec.Code != http.StatusRequestEntityTooLarge || errCode(t, rec) != "too_large" {
		t.Fatalf("over video cap = %d %s", rec.Code, rec.Body)
	}
	if n := countFiles(t, filepath.Join(e.root, "tmp")); n != 0 {
		t.Fatalf("refused uploads left %d temp files", n)
	}
}

func TestQuota(t *testing.T) {
	e := newEnv(t, func(d *Deps) { d.Quota = 3000 })
	a := file(pngHead, 2000, 1)
	e.upload(aliceTok, "", a, http.StatusCreated)
	rec := e.do(http.MethodPost, "/v1/uploads", aliceTok, bytes.NewReader(file(pngHead, 2000, 2)))
	if rec.Code != http.StatusRequestEntityTooLarge || errCode(t, rec) != "quota_exceeded" {
		t.Fatalf("over quota = %d %s", rec.Code, rec.Body)
	}
	if n := countFiles(t, filepath.Join(e.root, "blobs")); n != 1 {
		t.Fatalf("over-quota upload was committed: %d blobs", n)
	}
	// Re-uploading bytes it already owns still works at the quota.
	e.upload(aliceTok, "?ttl=1h", a, http.StatusCreated)
}

func TestDedupeAndExpiryOnlyExtends(t *testing.T) {
	e := newEnv(t)
	data := file(pngHead, 600, 9)
	first := e.upload(aliceTok, "?ttl=2h", data, http.StatusCreated)
	want := e.now().Add(2 * time.Hour)
	if first.Existed || first.ExpiresAt == nil || !first.ExpiresAt.Equal(want) {
		t.Fatalf("first = %+v", first)
	}

	second := e.upload(bobTok, "?ttl=10m", data, http.StatusCreated)
	if !second.Existed || second.URL != first.URL || !second.ExpiresAt.Equal(want) {
		t.Fatalf("dedupe with a shorter ttl = %+v, want same URL, existed, expiry unchanged", second)
	}

	third := e.upload(bobTok, "?ttl=1d", data, http.StatusCreated)
	if !third.ExpiresAt.Equal(e.now().Add(24 * time.Hour)) {
		t.Fatalf("1d did not extend: %+v", third)
	}

	// A TTL bounds what a cache may keep: after expiry the origin answers 404,
	// and a copy cached for a year would outlive the owner's decision.
	if cc := e.do(http.MethodGet, "/m/"+first.ID+".png", "", nil).Header().Get("Cache-Control"); cc != "public, max-age=86400, immutable" {
		t.Fatalf("Cache-Control with 1d remaining = %q", cc)
	}
	e.advance(12 * time.Hour)
	if cc := e.do(http.MethodGet, "/m/"+first.ID+".png", "", nil).Header().Get("Cache-Control"); cc != "public, max-age=43200, immutable" {
		t.Fatalf("Cache-Control with 12h remaining = %q", cc)
	}
	e.advance(-12 * time.Hour)

	e.advance(24 * time.Hour)
	for _, p := range []string{"/m/" + first.ID, "/m/" + first.ID + ".png"} {
		if rec := e.do(http.MethodGet, p, "", nil); rec.Code != http.StatusNotFound {
			t.Fatalf("GET %s after expiry = %d", p, rec.Code)
		}
	}
	if rec := e.do(http.MethodGet, "/v1/uploads/"+first.ID, aliceTok, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("API GET after expiry = %d", rec.Code)
	}
}

func TestPermanentWinsOverTTL(t *testing.T) {
	e := newEnv(t)
	data := file(pngHead, 600, 8)
	e.upload(aliceTok, "?ttl=1h", data, http.StatusCreated)
	if r := e.upload(bobTok, "", data, http.StatusCreated); r.ExpiresAt != nil {
		t.Fatalf("no-ttl upload did not make it permanent: %+v", r)
	}
	if r := e.upload(aliceTok, "?ttl=1h", data, http.StatusCreated); r.ExpiresAt != nil {
		t.Fatalf("a ttl shortened a permanent blob: %+v", r)
	}
}

func TestBadTTL(t *testing.T) {
	e := newEnv(t)
	for _, ttl := range []string{"abc", "0d", "-1h", "0s", "1.5d"} {
		rec := e.do(http.MethodPost, "/v1/uploads?ttl="+ttl, aliceTok, bytes.NewReader(file(pngHead, 100, 1)))
		if rec.Code != http.StatusBadRequest || errCode(t, rec) != "bad_ttl" {
			t.Errorf("ttl=%s = %d %s", ttl, rec.Code, rec.Body)
		}
	}
}

func TestMultipartUpload(t *testing.T) {
	e := newEnv(t)
	data := file(gifHead, 900, 3)
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("file", "innocent.png")
	_, _ = fw.Write(data)
	// ttl after the file: it must still be honoured.
	_ = mw.WriteField("ttl", "3d")
	_ = mw.Close()

	rec := e.do(http.MethodPost, "/v1/uploads", aliceTok, &body, "Content-Type", mw.FormDataContentType())
	if rec.Code != http.StatusCreated {
		t.Fatalf("multipart = %d %s", rec.Code, rec.Body)
	}
	var r uploadResp
	_ = json.Unmarshal(rec.Body.Bytes(), &r)
	if r.ContentType != "image/gif" || r.SHA256 != sha(data) || !r.ExpiresAt.Equal(e.now().Add(72*time.Hour)) {
		t.Fatalf("multipart response = %+v", r)
	}

	var none bytes.Buffer
	mw = multipart.NewWriter(&none)
	_ = mw.WriteField("ttl", "1h")
	_ = mw.Close()
	rec = e.do(http.MethodPost, "/v1/uploads", aliceTok, &none, "Content-Type", mw.FormDataContentType())
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("multipart without file = %d %s", rec.Code, rec.Body)
	}
}

func TestServePathMatching(t *testing.T) {
	e := newEnv(t)
	r := e.upload(aliceTok, "", file(pngHead, 600, 1), http.StatusCreated)
	for path, want := range map[string]int{
		"/m/" + r.ID:                    http.StatusOK,
		"/m/" + r.ID + ".png":           http.StatusOK,
		"/m/" + r.ID + ".html":          http.StatusNotFound,
		"/m/" + r.ID + ".jpg":           http.StatusNotFound,
		"/m/" + r.ID + ".":              http.StatusNotFound,
		"/m/" + strings.Repeat("0", 64): http.StatusNotFound,
		"/m/" + strings.ToUpper(r.ID):   http.StatusNotFound,
		"/m/not-a-hash.png":             http.StatusNotFound,
		"/m/" + r.ID + ".png/extra":     http.StatusNotFound,
		"/m/":                           http.StatusNotFound,
	} {
		if rec := e.do(http.MethodGet, path, "", nil); rec.Code != want {
			t.Errorf("GET %s = %d, want %d", path, rec.Code, want)
		}
	}
}

func TestSecondFilePartIsRefused(t *testing.T) {
	e := newEnv(t)
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("file", "a.png")
	_, _ = fw.Write(file(pngHead, 600, 1))
	fw, _ = mw.CreateFormFile("file", "b.png")
	_, _ = fw.Write(file(pngHead, 600, 2))
	_ = mw.Close()
	rec := e.do(http.MethodPost, "/v1/uploads", aliceTok, &body, "Content-Type", mw.FormDataContentType())
	if rec.Code != http.StatusBadRequest || errCode(t, rec) != "bad_request" {
		t.Fatalf("two file parts = %d %s", rec.Code, rec.Body)
	}
	if n := countFiles(t, e.root); n != 0 {
		t.Fatalf("a refused upload left %d files", n)
	}
}

// Multi-range would be answered as multipart/byteranges, a Content-Type the
// record never had; it gets the whole blob with the record's type instead.
func TestMultiRangeServesTheWholeBlob(t *testing.T) {
	e := newEnv(t)
	data := file(pngHead, 600, 4)
	r := e.upload(aliceTok, "", data, http.StatusCreated)
	rec := e.do(http.MethodGet, "/m/"+r.ID+".png", "", nil, "Range", "bytes=0-1,10-20")
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "image/png" || !bytes.Equal(rec.Body.Bytes(), data) {
		t.Fatalf("multi-range = %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
}

func TestRangeHeadAndConditional(t *testing.T) {
	e := newEnv(t)
	data := file(mp4Head, 5000, 7)
	r := e.upload(aliceTok, "", data, http.StatusCreated)
	path := "/m/" + r.ID + ".mp4"

	rec := e.do(http.MethodGet, path, "", nil, "Range", "bytes=0-3")
	if rec.Code != http.StatusPartialContent || !bytes.Equal(rec.Body.Bytes(), data[:4]) ||
		rec.Header().Get("Content-Range") != "bytes 0-3/5000" {
		t.Fatalf("range = %d %q %q", rec.Code, rec.Body.Bytes(), rec.Header().Get("Content-Range"))
	}

	rec = e.do(http.MethodHead, path, "", nil)
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 || rec.Header().Get("Content-Length") != "5000" ||
		rec.Header().Get("Content-Type") != "video/mp4" {
		t.Fatalf("HEAD = %d len %d headers %v", rec.Code, rec.Body.Len(), rec.Header())
	}

	rec = e.do(http.MethodGet, path, "", nil, "If-None-Match", `"`+r.ID+`"`)
	if rec.Code != http.StatusNotModified {
		t.Fatalf("If-None-Match = %d", rec.Code)
	}
}

func TestOwnerScopedAPI(t *testing.T) {
	e := newEnv(t)
	shared := file(pngHead, 600, 1)
	mine := file(pngHead, 600, 2)
	s := e.upload(aliceTok, "", shared, http.StatusCreated)
	m := e.upload(aliceTok, "", mine, http.StatusCreated)
	e.upload(bobTok, "", shared, http.StatusCreated)

	list := func(tok string) []string {
		rec := e.do(http.MethodGet, "/v1/uploads", tok, nil)
		var b struct {
			Uploads []struct {
				ID string `json:"id"`
			} `json:"uploads"`
		}
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &b) != nil {
			t.Fatalf("list = %d %s", rec.Code, rec.Body)
		}
		var ids []string
		for _, u := range b.Uploads {
			ids = append(ids, u.ID)
		}
		return ids
	}
	if got := list(bobTok); len(got) != 1 || got[0] != s.ID {
		t.Fatalf("bob's list = %v", got)
	}
	if got := list(aliceTok); len(got) != 2 {
		t.Fatalf("alice's list = %v", got)
	}
	if strings.Contains(e.do(http.MethodGet, "/v1/uploads", aliceTok, nil).Body.String(), "owners") {
		t.Fatal("the API revealed owners")
	}

	if rec := e.do(http.MethodGet, "/v1/uploads/"+m.ID, aliceTok, nil); rec.Code != http.StatusOK {
		t.Fatalf("owner GET = %d", rec.Code)
	}
	if rec := e.do(http.MethodGet, "/v1/uploads/"+m.ID, bobTok, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("non-owner GET = %d, want 404", rec.Code)
	}
	if rec := e.do(http.MethodDelete, "/v1/uploads/"+m.ID, bobTok, nil); rec.Code != http.StatusNotFound || errCode(t, rec) != "not_found" {
		t.Fatalf("non-owner DELETE = %d, want 404", rec.Code)
	}
	if rec := e.do(http.MethodGet, "/m/"+m.ID+".png", "", nil); rec.Code != http.StatusOK {
		t.Fatalf("non-owner delete removed the blob: %d", rec.Code)
	}

	// Shared: alice leaving keeps it for bob; bob leaving deletes it.
	if rec := e.do(http.MethodDelete, "/v1/uploads/"+s.ID, aliceTok, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("alice DELETE = %d %s", rec.Code, rec.Body)
	}
	if rec := e.do(http.MethodGet, "/m/"+s.ID+".png", "", nil); rec.Code != http.StatusOK {
		t.Fatalf("shared blob gone after one owner left: %d", rec.Code)
	}
	if rec := e.do(http.MethodDelete, "/v1/uploads/"+s.ID, bobTok, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("bob DELETE = %d %s", rec.Code, rec.Body)
	}
	if rec := e.do(http.MethodGet, "/m/"+s.ID+".png", "", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("blob served after its last owner left: %d", rec.Code)
	}
	if _, err := os.Stat(filepath.Join(e.root, "blobs", s.ID[:2], s.ID)); !os.IsNotExist(err) {
		t.Fatal("blob file survived its last owner")
	}
	if _, err := os.Stat(filepath.Join(e.root, "index", s.ID+".json")); !os.IsNotExist(err) {
		t.Fatal("record file survived its last owner")
	}
}

func TestAuth(t *testing.T) {
	e := newEnv(t)
	for name, hdr := range map[string]string{
		"missing":     "",
		"wrong token": "Bearer " + wrongTok,
		"basic":       "Basic " + aliceTok,
		"empty":       "Bearer ",
	} {
		for _, m := range []string{http.MethodGet, http.MethodPost} {
			req := httptest.NewRequest(m, "/v1/uploads", bytes.NewReader(file(pngHead, 100, 1)))
			if hdr != "" {
				req.Header.Set("Authorization", hdr)
			}
			rec := httptest.NewRecorder()
			e.h.ServeHTTP(rec, req)
			e.bodies.WriteString(rec.Body.String())
			if rec.Code != http.StatusUnauthorized || errCode(t, rec) != "unauthorized" ||
				rec.Header().Get("WWW-Authenticate") == "" {
				t.Errorf("%s %s = %d %s", name, m, rec.Code, rec.Body)
			}
		}
	}
	if n := countFiles(t, e.root); n != 0 {
		t.Fatalf("unauthenticated uploads left %d files", n)
	}
	// Case-insensitive scheme.
	if rec := e.do(http.MethodGet, "/v1/uploads", "", nil, "Authorization", "bearer "+aliceTok); rec.Code != http.StatusOK {
		t.Fatalf("lowercase bearer = %d", rec.Code)
	}
}

func TestLogsNameTheActor(t *testing.T) {
	e := newEnv(t)
	r := e.upload(aliceTok, "", file(pngHead, 600, 1), http.StatusCreated)
	e.upload(bobTok, "", file(pngHead, 600, 1), http.StatusCreated)
	e.do(http.MethodGet, "/m/"+r.ID+".png", "", nil)
	e.do(http.MethodGet, "/v1/uploads", wrongTok, nil)

	var sawUpload, sawServe bool
	for _, line := range strings.Split(strings.TrimSpace(e.logs.String()), "\n") {
		var l struct {
			Path   string   `json:"path"`
			Method string   `json:"method"`
			Token  string   `json:"token"`
			SHA    string   `json:"sha256"`
			Owners []string `json:"owners"`
			Status int      `json:"status"`
			Bytes  int64    `json:"bytes"`
		}
		if err := json.Unmarshal([]byte(line), &l); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		if l.Method == http.MethodPost && l.Token == "alice" && l.SHA == r.ID {
			sawUpload = true
		}
		if strings.HasPrefix(l.Path, "/m/") && l.SHA == r.ID && len(l.Owners) == 2 && l.Status == 200 && l.Bytes == 600 {
			sawServe = true
		}
	}
	if !sawUpload || !sawServe {
		t.Fatalf("upload line %v, serve line %v in:\n%s", sawUpload, sawServe, e.logs.String())
	}
}

func TestProbes(t *testing.T) {
	check := func(t *testing.T, rec *httptest.ResponseRecorder, code int, status string, sha any) {
		t.Helper()
		if rec.Code != code || rec.Header().Get("Content-Type") != "application/json" {
			t.Fatalf("probe = %d %q", rec.Code, rec.Header().Get("Content-Type"))
		}
		var b map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
			t.Fatal(err)
		}
		if len(b) != 3 || b["status"] != status || b["version"] != "dev" || b["sha"] != sha {
			t.Fatalf("probe body = %v", b)
		}
		if _, ok := b["sha"]; !ok {
			t.Fatal("sha missing; it must be present as null")
		}
	}

	e := newEnv(t)
	check(t, e.do(http.MethodGet, "/healthz", "", nil), 200, "ok", nil)
	check(t, e.do(http.MethodGet, "/readyz", "", nil), 200, "ok", nil)
	e.mu.Lock()
	e.ready = errors.New("disk full")
	e.mu.Unlock()
	check(t, e.do(http.MethodGet, "/readyz", "", nil), 503, "degraded", nil)
	check(t, e.do(http.MethodGet, "/healthz", "", nil), 200, "ok", nil)

	full := strings.Repeat("ab", 20)
	e2 := newEnv(t, func(d *Deps) { d.Commit = full })
	check(t, e2.do(http.MethodGet, "/healthz", "", nil), 200, "ok", full)
}

func TestParseTTL(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for in, want := range map[string]time.Duration{"7d": 7 * 24 * time.Hour, "720h": 720 * time.Hour, "90m": 90 * time.Minute} {
		got, err := parseTTL(in, now)
		if err != nil || !got.Equal(now.Add(want)) {
			t.Errorf("parseTTL(%q) = %v, %v", in, got, err)
		}
	}
	if got, err := parseTTL("", now); got != nil || err != nil {
		t.Errorf("empty ttl = %v, %v; want permanent", got, err)
	}
}
