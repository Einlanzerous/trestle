package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func private(d *Deps) { d.Private, d.PublicBaseURL = true, "" }

// GENZO-5: with TRESTLE_PUBLIC_SERVE=false nothing is served without a token.
// /m/ is not mounted, so a blob that exists answers exactly like one that
// does not.
func TestPrivateInstanceMountsNoPublicServe(t *testing.T) {
	e := newEnv(t, private)
	data := file(pngHead, 600, 1)
	rec := e.do(http.MethodPost, "/v1/uploads", aliceTok, strings.NewReader(string(data)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("upload = %d %s", rec.Code, rec.Body)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if u, ok := raw["url"]; !ok || string(u) != "null" {
		t.Fatalf("private upload url = %s (present %v), want null", u, ok)
	}
	h := sha(data)
	if got := strings.Trim(string(raw["sha256"]), `"`); got != h {
		t.Fatalf("sha256 = %s", got)
	}

	unknown := strings.Repeat("0", 64)
	for _, p := range []string{"/m/" + h, "/m/" + h + ".png", "/m/" + unknown, "/m/" + unknown + ".png", "/m/"} {
		for _, m := range []string{http.MethodGet, http.MethodHead} {
			for _, tok := range []string{"", aliceTok} {
				rec := e.do(m, p, tok, nil)
				if rec.Code != http.StatusNotFound {
					t.Errorf("%s %s (token %v) = %d, want 404", m, p, tok != "", rec.Code)
				}
				if m == http.MethodGet && strings.Contains(rec.Body.String(), "\x89PNG") {
					t.Errorf("%s %s served blob bytes", m, p)
				}
			}
		}
	}

	// The API is unchanged apart from the url, and list/get say null too.
	for _, p := range []string{"/v1/uploads", "/v1/uploads/" + h} {
		rec := e.do(http.MethodGet, p, aliceTok, nil)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"url":null`) || strings.Contains(rec.Body.String(), "/m/") {
			t.Errorf("GET %s = %d %s", p, rec.Code, rec.Body)
		}
	}

	// Probes stay unauthenticated.
	for _, p := range []string{"/healthz", "/readyz"} {
		if rec := e.do(http.MethodGet, p, "", nil); rec.Code != http.StatusOK {
			t.Errorf("GET %s = %d", p, rec.Code)
		}
	}
}

// The public default still carries a string url; null is only for private.
func TestPublicInstanceURLIsAString(t *testing.T) {
	e := newEnv(t)
	rec := e.do(http.MethodPost, "/v1/uploads", aliceTok, strings.NewReader(string(file(pngHead, 600, 2))))
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(raw["url"]), `"`+base+`/m/`) {
		t.Fatalf("public url = %s", raw["url"])
	}
}
