package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// reqInfo is filled in by handlers for the request log line.
type reqInfo struct {
	token  string
	hash   string
	owners []string
}

type infoKey struct{}
type callerKey struct{}

func info(r *http.Request) *reqInfo {
	if ri, ok := r.Context().Value(infoKey{}).(*reqInfo); ok {
		return ri
	}
	return &reqInfo{}
}

func caller(r *http.Request) string {
	name, _ := r.Context().Value(callerKey{}).(string)
	return name
}

// auth gates a /v1 handler on a bearer token.
//
// The presented token is hashed and compared against every configured digest
// in constant time, with no early exit, so neither the match nor its position
// leaks through timing. From here on the caller is its name: tokens never
// reach a log line or an error message.
func (a *api) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := a.authenticate(r.Header.Get("Authorization"))
		if name == "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="trestle"`)
			writeError(w, http.StatusUnauthorized, "unauthorized", "a valid bearer token is required")
			return
		}
		info(r).token = name
		next(w, r.WithContext(context.WithValue(r.Context(), callerKey{}, name)))
	}
}

func (a *api) authenticate(header string) string {
	scheme, token, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(token))
	match := ""
	for _, t := range a.Tokens {
		if subtle.ConstantTimeCompare(sum[:], t.Hash[:]) == 1 {
			match = t.Name
		}
	}
	return match
}

// statusWriter records what was sent, for the log line.
type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (s *statusWriter) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(p []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	n, err := s.ResponseWriter.Write(p)
	s.bytes += int64(n)
	return n, err
}

func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// logRequests writes one line per request. On /m/ it names the hash and its
// owners, so every publicly served blob is attributable to the token that
// put it there; on /v1 it names the token. Probes log at debug so a poller
// does not drown the log.
func (a *api) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ri := &reqInfo{}
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r.WithContext(context.WithValue(r.Context(), infoKey{}, ri)))

		if sw.status == 0 {
			sw.status = http.StatusOK
		}
		attrs := []slog.Attr{
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", sw.status),
			slog.Int64("bytes", sw.bytes),
			slog.Int64("duration_ms", time.Since(start).Milliseconds()),
		}
		if ri.token != "" {
			attrs = append(attrs, slog.String("token", ri.token))
		}
		if ri.hash != "" {
			attrs = append(attrs, slog.String("sha256", ri.hash), slog.Any("owners", ri.owners))
		}
		level := slog.LevelInfo
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			level = slog.LevelDebug
		}
		a.Logger.LogAttrs(r.Context(), level, "request", attrs...)
	})
}
