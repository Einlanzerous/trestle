package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// GENZO-6: GET/HEAD /v1/blobs/{sha256}, the owner's authenticated read.
func TestBlobReadIsBearerGatedAndOwnerScoped(t *testing.T) {
	for name, mutate := range map[string]func(*Deps){"public": func(*Deps) {}, "private": private} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, mutate)
			mine := file(pngHead, 600, 1)
			bobs := file(pngHead, 600, 2)
			m := e.upload(aliceTok, "", mine, http.StatusCreated)
			b := e.upload(bobTok, "", bobs, http.StatusCreated)
			short := e.upload(aliceTok, "?ttl=1h", file(pngHead, 600, 3), http.StatusCreated)

			for _, m2 := range []string{http.MethodGet, http.MethodHead} {
				for _, tok := range []string{"", wrongTok} {
					rec := e.do(m2, "/v1/blobs/"+m.ID, tok, nil)
					if rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") == "" {
						t.Errorf("%s without a valid token = %d", m2, rec.Code)
					}
					if bytes.Contains(rec.Body.Bytes(), mine[:8]) {
						t.Errorf("%s without a valid token leaked bytes", m2)
					}
				}
			}

			for what, p := range map[string]string{
				"another token's blob": "/v1/blobs/" + b.ID,
				"unknown":              "/v1/blobs/" + strings.Repeat("0", 64),
				"not a hash":           "/v1/blobs/not-a-hash",
				"uppercase":            "/v1/blobs/" + strings.ToUpper(m.ID),
				"with an extension":    "/v1/blobs/" + m.ID + ".png",
			} {
				for _, m2 := range []string{http.MethodGet, http.MethodHead} {
					rec := e.do(m2, p, aliceTok, nil)
					if rec.Code != http.StatusNotFound {
						t.Errorf("%s %s = %d, want 404", m2, what, rec.Code)
					}
					if m2 == http.MethodGet && errCode(t, rec) != "not_found" {
						t.Errorf("%s error code", what)
					}
				}
			}

			// Bob owning other bytes does not let him read alice's, and the
			// 404 is the same one an unknown hash gets.
			unknown := e.do(http.MethodGet, "/v1/blobs/"+strings.Repeat("0", 64), bobTok, nil)
			notYours := e.do(http.MethodGet, "/v1/blobs/"+m.ID, bobTok, nil)
			if notYours.Code != http.StatusNotFound || notYours.Body.String() != unknown.Body.String() {
				t.Errorf("not-yours = %d %s, unknown = %s", notYours.Code, notYours.Body, unknown.Body)
			}

			rec := e.do(http.MethodGet, "/v1/blobs/"+m.ID, aliceTok, nil)
			if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), mine) {
				t.Fatalf("owner GET = %d, body match %v", rec.Code, bytes.Equal(rec.Body.Bytes(), mine))
			}

			if rec := e.do(http.MethodGet, "/v1/blobs/"+short.ID, aliceTok, nil); rec.Code != http.StatusOK {
				t.Fatalf("live ttl blob = %d", rec.Code)
			}
			e.advance(time.Hour)
			if rec := e.do(http.MethodGet, "/v1/blobs/"+short.ID, aliceTok, nil); rec.Code != http.StatusNotFound {
				t.Fatalf("expired blob = %d, want 404", rec.Code)
			}
			if rec := e.do(http.MethodHead, "/v1/blobs/"+short.ID, aliceTok, nil); rec.Code != http.StatusNotFound {
				t.Fatalf("expired blob HEAD = %d, want 404", rec.Code)
			}

			// A dropped ownership stops the read at once.
			if rec := e.do(http.MethodDelete, "/v1/uploads/"+m.ID, aliceTok, nil); rec.Code != http.StatusNoContent {
				t.Fatalf("DELETE = %d", rec.Code)
			}
			if rec := e.do(http.MethodGet, "/v1/blobs/"+m.ID, aliceTok, nil); rec.Code != http.StatusNotFound {
				t.Fatalf("read after DELETE = %d", rec.Code)
			}
		})
	}
}

func TestBlobReadHeaders(t *testing.T) {
	e := newEnv(t, private)
	for _, tc := range []struct {
		name, mime, ext string
		data            []byte
	}{
		{"png", "image/png", "png", file(pngHead, 700, 1)},
		{"mp4", "video/mp4", "mp4", file(mp4Head, 700, 5)},
		{"svg", "image/svg+xml", "svg", svgDoc},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := e.upload(aliceTok, "", tc.data, http.StatusCreated)
			rec := e.do(http.MethodGet, "/v1/blobs/"+r.ID, aliceTok, nil)
			if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), tc.data) {
				t.Fatalf("GET = %d", rec.Code)
			}
			disposition := `inline; filename="` + r.ID + "." + tc.ext + `"`
			if tc.ext == "svg" {
				disposition = `attachment; filename="` + r.ID + `.svg"`
			}
			for k, v := range map[string]string{
				"Content-Type":                 tc.mime,
				"Cache-Control":                "private, no-cache",
				"ETag":                         `"` + r.ID + `"`,
				"Last-Modified":                "Tue, 22 Sep 2026 12:00:00 GMT",
				"X-Content-Type-Options":       "nosniff",
				"Cross-Origin-Resource-Policy": "same-origin",
				"Content-Disposition":          disposition,
				"Access-Control-Allow-Origin":  "",
			} {
				if got := rec.Header().Get(k); got != v {
					t.Errorf("%s = %q, want %q", k, got, v)
				}
			}
			if strings.Contains(rec.Header().Get("Cache-Control"), "public") {
				t.Error("an authenticated read is cacheable by shared caches")
			}
			csp := rec.Header().Get("Content-Security-Policy")
			if tc.ext == "svg" && csp != svgCSP {
				t.Errorf("SVG CSP = %q", csp)
			}
			if tc.ext != "svg" && csp != "" {
				t.Errorf("non-SVG got a CSP: %q", csp)
			}
		})
	}
}

func TestBlobReadRangeHeadAndConditional(t *testing.T) {
	e := newEnv(t, private)
	data := file(mp4Head, 5000, 7)
	r := e.upload(aliceTok, "", data, http.StatusCreated)
	path := "/v1/blobs/" + r.ID

	rec := e.do(http.MethodGet, path, aliceTok, nil, "Range", "bytes=100-199")
	if rec.Code != http.StatusPartialContent || !bytes.Equal(rec.Body.Bytes(), data[100:200]) ||
		rec.Header().Get("Content-Range") != "bytes 100-199/5000" || rec.Header().Get("Content-Type") != "video/mp4" {
		t.Fatalf("range = %d %q %q", rec.Code, rec.Header().Get("Content-Range"), rec.Header().Get("Content-Type"))
	}

	rec = e.do(http.MethodGet, path, aliceTok, nil, "Range", "bytes=0-1,10-20")
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "video/mp4" || !bytes.Equal(rec.Body.Bytes(), data) {
		t.Fatalf("multi-range = %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}

	rec = e.do(http.MethodHead, path, aliceTok, nil)
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 || rec.Header().Get("Content-Length") != "5000" ||
		rec.Header().Get("Content-Type") != "video/mp4" {
		t.Fatalf("HEAD = %d len %d headers %v", rec.Code, rec.Body.Len(), rec.Header())
	}

	rec = e.do(http.MethodGet, path, aliceTok, nil, "If-None-Match", `"`+r.ID+`"`)
	if rec.Code != http.StatusNotModified || rec.Body.Len() != 0 {
		t.Fatalf("If-None-Match = %d", rec.Code)
	}
	// Revalidation still checks the token and the ownership.
	if rec := e.do(http.MethodGet, path, bobTok, nil, "If-None-Match", `"`+r.ID+`"`); rec.Code != http.StatusNotFound {
		t.Fatalf("non-owner If-None-Match = %d, want 404", rec.Code)
	}
}

// The serve log line names hash, actor, owners, bytes and status, and never a
// token (newEnv's cleanup asserts no plaintext reached a log or a body).
func TestBlobReadLogLine(t *testing.T) {
	e := newEnv(t, private)
	data := file(pngHead, 600, 1)
	r := e.upload(aliceTok, "", data, http.StatusCreated)
	e.do(http.MethodGet, "/v1/blobs/"+r.ID, aliceTok, nil)

	var saw bool
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
		if l.Method == http.MethodGet && strings.HasPrefix(l.Path, "/v1/blobs/") && l.Token == "alice" &&
			l.SHA == r.ID && len(l.Owners) == 1 && l.Status == 200 && l.Bytes == 600 {
			saw = true
		}
	}
	if !saw {
		t.Fatalf("no blob-read line naming actor, hash, owners, bytes and status in:\n%s", e.logs.String())
	}
}
