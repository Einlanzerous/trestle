package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Einlanzerous/trestle/internal/blob"
	"github.com/Einlanzerous/trestle/internal/index"
	"github.com/Einlanzerous/trestle/internal/sniff"
)

// multipartSlack is headroom over the largest cap for multipart framing and
// the ttl field, so a file exactly at the cap is not refused for its
// envelope.
const multipartSlack = 64 << 10

// maxTTLDays keeps days*24h inside a time.Duration.
const maxTTLDays = 100_000

type uploadView struct {
	ID          string     `json:"id"`
	SHA256      string     `json:"sha256"`
	URL         string     `json:"url"`
	Bytes       int64      `json:"bytes"`
	ContentType string     `json:"content_type"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at"`
}

type uploadResponse struct {
	uploadView
	Existed bool `json:"existed"`
}

// view deliberately omits owners: the API does not confirm who else uploaded
// the same bytes.
func (a *api) view(r index.Record) uploadView {
	return uploadView{
		ID:          r.SHA256,
		SHA256:      r.SHA256,
		URL:         a.PublicBaseURL + "/m/" + r.SHA256 + "." + r.Ext,
		Bytes:       r.Bytes,
		ContentType: r.ContentType,
		CreatedAt:   r.CreatedAt,
		ExpiresAt:   r.ExpiresAt,
	}
}

// upload is POST /v1/uploads: raw bytes, or multipart/form-data with a
// `file` part, and an optional ttl as a query parameter or form field.
//
// The body is never read whole. It is capped at the largest type cap while
// streaming, sniffed from its first 512 bytes (415 before a byte reaches
// disk), then capped at the sniffed type's own limit, hashed as it is
// written to a temp file, and committed only once the index accepts it.
func (a *api) upload(w http.ResponseWriter, r *http.Request) {
	owner := caller(r)
	ttl := r.URL.Query().Get("ttl")
	if _, err := parseTTL(ttl, time.Time{}); err != nil {
		writeError(w, http.StatusBadRequest, "bad_ttl", err.Error())
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, a.Caps.Max()+multipartSlack)

	var src io.Reader = r.Body
	var mr *multipart.Reader
	if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt == "multipart/form-data" {
		var err error
		if mr, err = r.MultipartReader(); err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", "malformed multipart body")
			return
		}
		part, formTTL, err := nextFilePart(mr)
		if err != nil {
			a.readFailed(w, err)
			return
		}
		if part == nil {
			writeError(w, http.StatusBadRequest, "bad_request", "multipart body has no file part")
			return
		}
		if formTTL != "" {
			ttl = formTTL
		}
		src = part
	}

	head := make([]byte, sniff.HeadSize)
	n, err := io.ReadFull(src, head)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		a.readFailed(w, err)
		return
	}
	head = head[:n]
	if n == 0 {
		writeError(w, http.StatusBadRequest, "empty_body", "the upload has no bytes")
		return
	}
	typ, ok := sniff.Detect(head)
	if !ok {
		writeError(w, http.StatusUnsupportedMediaType, "unsupported_type",
			fmt.Sprintf("detected %s; allowed: png, jpeg, webp, gif, svg, mp4, webm", typ.MIME))
		return
	}

	limit := a.Caps.For(typ)
	body := http.MaxBytesReader(w, io.NopCloser(io.MultiReader(bytes.NewReader(head), src)), limit)
	bw, err := a.Blobs.NewWriter(r.Context())
	if err != nil {
		a.internal(w, "open temp blob", err)
		return
	}
	defer func() { _ = bw.Abort() }()

	h := sha256.New()
	size, err := io.Copy(io.MultiWriter(bw, h), body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeError(w, http.StatusRequestEntityTooLarge, "too_large",
				fmt.Sprintf("%s uploads are capped at %d bytes", typ.MIME, limit))
			return
		}
		a.readFailed(w, err)
		return
	}

	// A ttl field may follow the file part; it has to be read before the
	// upload is recorded.
	if mr != nil {
		formTTL, err := trailingTTL(mr)
		if err != nil {
			a.readFailed(w, err)
			return
		}
		if formTTL != "" {
			ttl = formTTL
		}
	}
	now := a.Now()
	expiresAt, err := parseTTL(ttl, now)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_ttl", err.Error())
		return
	}

	hash := hex.EncodeToString(h.Sum(nil))
	info(r).hash = hash
	rec, existed, err := a.Index.Add(index.Upload{
		SHA256:      hash,
		Bytes:       size,
		ContentType: typ.MIME,
		Ext:         typ.Ext,
		Owner:       owner,
		ExpiresAt:   expiresAt,
	}, a.Quota, now, func() error { return bw.Commit(hash) })
	if errors.Is(err, index.ErrQuota) {
		writeError(w, http.StatusRequestEntityTooLarge, "quota_exceeded",
			fmt.Sprintf("this upload would take the token past its %d-byte quota", a.Quota))
		return
	}
	if err != nil {
		a.internal(w, "record upload", err)
		return
	}
	info(r).owners = rec.Owners
	writeJSON(w, http.StatusCreated, uploadResponse{uploadView: a.view(rec), Existed: existed})
}

// nextFilePart advances to the `file` part, collecting a ttl field seen on
// the way. A nil part means the body ended without one.
func nextFilePart(mr *multipart.Reader) (*multipart.Part, string, error) {
	var ttl string
	for {
		p, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			return nil, ttl, nil
		}
		if err != nil {
			return nil, "", err
		}
		switch p.FormName() {
		case "file":
			return p, ttl, nil
		case "ttl":
			if ttl, err = readField(p); err != nil {
				return nil, "", err
			}
		}
	}
}

// trailingTTL reads the parts after the file for a ttl field.
func trailingTTL(mr *multipart.Reader) (string, error) {
	var ttl string
	for {
		p, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			return ttl, nil
		}
		if err != nil {
			return "", err
		}
		if p.FormName() == "ttl" {
			if ttl, err = readField(p); err != nil {
				return "", err
			}
		}
	}
}

func readField(p *multipart.Part) (string, error) {
	b, err := io.ReadAll(io.LimitReader(p, 64))
	return strings.TrimSpace(string(b)), err
}

// parseTTL turns a Go duration or an `Nd` day count into an absolute expiry.
// Empty means permanent (nil): there is no default TTL.
func parseTTL(s string, now time.Time) (*time.Time, error) {
	if s == "" {
		return nil, nil
	}
	var d time.Duration
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n < 1 || n > maxTTLDays {
			return nil, fmt.Errorf("ttl %q is not a positive day count", s)
		}
		d = time.Duration(n) * 24 * time.Hour
	} else {
		var err error
		if d, err = time.ParseDuration(s); err != nil || d <= 0 {
			return nil, fmt.Errorf("ttl %q is not a positive Go duration or Nd day count", s)
		}
	}
	t := now.Add(d).UTC()
	return &t, nil
}

func (a *api) readFailed(w http.ResponseWriter, err error) {
	var mbe *http.MaxBytesError
	if errors.As(err, &mbe) {
		writeError(w, http.StatusRequestEntityTooLarge, "too_large",
			fmt.Sprintf("uploads are capped at %d bytes", a.Caps.Max()))
		return
	}
	a.Logger.Warn("upload read failed", "error", err)
	writeError(w, http.StatusBadRequest, "bad_request", "could not read the upload body")
}

func (a *api) internal(w http.ResponseWriter, what string, err error) {
	a.Logger.Error(what, "error", err)
	writeError(w, http.StatusInternalServerError, "internal", "internal error")
}

func (a *api) list(w http.ResponseWriter, r *http.Request) {
	recs := a.Index.Owned(caller(r), a.Now())
	out := make([]uploadView, 0, len(recs))
	for _, rec := range recs {
		out = append(out, a.view(rec))
	}
	writeJSON(w, http.StatusOK, map[string]any{"uploads": out})
}

// get and delete answer 404, not 403, for a record the caller does not own:
// /m/ already reveals existence by hash, but the API does not confirm who
// else uploaded what.
func (a *api) get(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	rec, ok := a.Index.Get(id, a.Now())
	if !ok || !rec.Owns(caller(r)) {
		writeError(w, http.StatusNotFound, "not_found", "no such upload")
		return
	}
	info(r).hash = id
	writeJSON(w, http.StatusOK, a.view(rec))
}

func (a *api) delete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !blob.ValidHash(id) {
		writeError(w, http.StatusNotFound, "not_found", "no such upload")
		return
	}
	err := a.Index.Disown(id, caller(r), a.Now(), func() error {
		return a.Blobs.Delete(r.Context(), id)
	})
	if errors.Is(err, index.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "no such upload")
		return
	}
	if err != nil {
		a.internal(w, "delete upload", err)
		return
	}
	info(r).hash = id
	w.WriteHeader(http.StatusNoContent)
}
