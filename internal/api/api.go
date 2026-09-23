// Package api is Trestle's HTTP surface: the bearer-gated /v1 API, the public
// /m/ serve path and the two probes, on one mux. Traefik splits the surfaces
// by host; the binary serves them all.
package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/Einlanzerous/trestle/internal/blob"
	"github.com/Einlanzerous/trestle/internal/config"
	"github.com/Einlanzerous/trestle/internal/index"
	"github.com/Einlanzerous/trestle/internal/sniff"
)

// Deps is everything the handlers need, built by the composition root.
type Deps struct {
	Logger        *slog.Logger
	Index         *index.Index
	Blobs         blob.Store
	Tokens        []config.Token
	PublicBaseURL string
	Caps          sniff.Caps
	Quota         int64

	// Version is already resolved to bare semver or "dev"; Commit is the
	// 40-hex sha or "" (reported as null).
	Version string
	Commit  string

	// Ready reports whether the data dir is writable, for /readyz.
	Ready func() error

	// Now is the clock every expiry decision reads; tests move it.
	Now func() time.Time
}

type api struct{ Deps }

// NewRouter builds the handler.
//
// /m/{file} is one pattern rather than /m/{hash} plus /m/{hash}.{ext}
// because a ServeMux wildcard must be a whole path segment; the handler
// splits on the dot. A GET pattern also answers HEAD.
func NewRouter(d Deps) http.Handler {
	if d.Now == nil {
		d.Now = time.Now
	}
	a := &api{d}
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", a.healthz)
	mux.HandleFunc("GET /readyz", a.readyz)

	mux.HandleFunc("POST /v1/uploads", a.auth(a.upload))
	mux.HandleFunc("GET /v1/uploads", a.auth(a.list))
	mux.HandleFunc("GET /v1/uploads/{id}", a.auth(a.get))
	mux.HandleFunc("DELETE /v1/uploads/{id}", a.auth(a.delete))

	mux.HandleFunc("GET /m/{file}", a.media)

	return a.logRequests(mux)
}

type health struct {
	Status  string  `json:"status"`
	Version string  `json:"version"`
	SHA     *string `json:"sha"`
}

// healthBody carries the identity on every probe answer, the 503 included:
// a degraded service is still running a version, and it is the one most
// worth identifying (PRINCIPLES §4).
func (a *api) healthBody(status string) health {
	h := health{Status: status, Version: a.Version}
	if a.Commit != "" {
		c := a.Commit
		h.SHA = &c
	}
	return h
}

func (a *api) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, a.healthBody("ok"))
}

func (a *api) readyz(w http.ResponseWriter, _ *http.Request) {
	if a.Ready != nil {
		if err := a.Ready(); err != nil {
			a.Logger.Warn("readiness probe failed", "error", err)
			writeJSON(w, http.StatusServiceUnavailable, a.healthBody("degraded"))
			return
		}
	}
	writeJSON(w, http.StatusOK, a.healthBody("ok"))
}

type errorBody struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError is the one shape every refusal takes. Messages are composed
// from constants and sniffed types only; nothing a caller sent in a header
// is echoed, so a token cannot reach a response body.
func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, errorBody{Error: code, Message: msg})
}
