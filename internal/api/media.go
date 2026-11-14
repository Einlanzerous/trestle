package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Einlanzerous/trestle/internal/blob"
	"github.com/Einlanzerous/trestle/internal/index"
	"github.com/Einlanzerous/trestle/internal/sniff"
)

// svgCSP sandboxes an SVG for browsers that render an attachment inline
// anyway; Content-Disposition: attachment is the primary defence.
const svgCSP = "default-src 'none'; style-src 'unsafe-inline'; sandbox"

// media is GET/HEAD /m/{sha256} and /m/{sha256}.{ext}: public, blobs only.
//
// Unknown, expired, or an extension that disagrees with the record are all
// 404. The type served is the one sniffed at upload and stored on the
// record, so …/x.png can never serve text/html; expiry is checked here
// rather than left to the sweep, so an expired URL dies on time.
func (a *api) media(w http.ResponseWriter, r *http.Request) {
	hash, ext, hasExt := strings.Cut(r.PathValue("file"), ".")
	if !blob.ValidHash(hash) {
		writeError(w, http.StatusNotFound, "not_found", "no such media")
		return
	}
	rec, ok := a.Index.Get(hash, a.Now())
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "no such media")
		return
	}
	if hasExt && ext != rec.Ext {
		ri := info(r)
		ri.hash, ri.owners = hash, rec.Owners
		writeError(w, http.StatusNotFound, "not_found", "no such media")
		return
	}
	a.serveBlob(w, r, hash, rec, true)
}

// blobRead is GET/HEAD /v1/blobs/{sha256}: the authenticated read, for the
// owner of a blob on either kind of instance. On a private instance it is
// the only way bytes leave the service.
//
// Owner-scoped like /v1/uploads/{id}: unknown, expired and not-yours are
// all the same 404, so the API does not confirm who else uploaded what. A
// HEAD answers "do I already hold this hash?" without moving the bytes.
func (a *api) blobRead(w http.ResponseWriter, r *http.Request) {
	hash := r.PathValue("sha256")
	if !blob.ValidHash(hash) {
		writeError(w, http.StatusNotFound, "not_found", "no such blob")
		return
	}
	rec, ok := a.Index.Get(hash, a.Now())
	if !ok || !rec.Owns(caller(r)) {
		writeError(w, http.StatusNotFound, "not_found", "no such blob")
		return
	}
	a.serveBlob(w, r, hash, rec, false)
}

// serveBlob writes the bytes of a record already found live, with the
// headers both read paths share. public picks the /m/ contract (shared
// caches, cross-origin embedding) or the authenticated one (private cache
// that revalidates every use, same-origin, no CORS).
func (a *api) serveBlob(w http.ResponseWriter, r *http.Request, hash string, rec index.Record, public bool) {
	ri := info(r)
	ri.hash, ri.owners = hash, rec.Owners

	f, _, err := a.Blobs.Open(r.Context(), hash)
	if errors.Is(err, blob.ErrNotFound) {
		a.Logger.Warn("record without blob", "sha256", hash)
		writeError(w, http.StatusNotFound, "not_found", "no such media")
		return
	}
	if err != nil {
		a.internal(w, "open blob", err)
		return
	}
	defer func() { _ = f.Close() }()

	h := w.Header()
	h.Set("Content-Type", rec.ContentType)
	if public {
		h.Set("Cache-Control", cacheControl(rec.ExpiresAt, a.Now()))
	} else {
		// private keeps it out of every shared cache; no-cache makes a
		// client's own cache revalidate each use, so a DELETE or an expiry
		// takes effect on the next read rather than a year later. The ETag
		// makes that revalidation a 304 with no body.
		h.Set("Cache-Control", "private, no-cache")
	}
	h.Set("ETag", `"`+hash+`"`)
	h.Set("X-Content-Type-Options", "nosniff")
	if public {
		h.Set("Cross-Origin-Resource-Policy", "cross-origin")
		h.Set("Access-Control-Allow-Origin", "*")
	} else {
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
	}
	filename := hash + "." + rec.Ext
	// SVG is never served inline: navigated to directly it would run script
	// in the estate's origin. <img> ignores the disposition, so embedding
	// loses nothing.
	if rec.ContentType == sniff.SVG.MIME {
		h.Set("Content-Disposition", `attachment; filename="`+filename+`"`)
		h.Set("Content-Security-Policy", svgCSP)
	} else {
		h.Set("Content-Disposition", `inline; filename="`+filename+`"`)
	}
	// A multi-range request would be answered as multipart/byteranges, the
	// one way ServeContent sends a Content-Type other than the record's.
	// Single ranges are all video seeking needs, so a multi-range request
	// gets the whole blob.
	if strings.Contains(r.Header.Get("Range"), ",") {
		r.Header.Del("Range")
	}
	http.ServeContent(w, r, "", rec.CreatedAt, f)
}

// cacheControl is a year and immutable for a permanent blob. A blob with a
// TTL caps max-age at the time remaining, because the origin will answer 404
// after expiry and a cached copy that outlives it — on Cloudflare's edge or in
// a browser — would keep serving bytes the owner asked to have removed.
func cacheControl(expiresAt *time.Time, now time.Time) string {
	const year = 31536000
	if expiresAt == nil {
		return "public, max-age=31536000, immutable"
	}
	remaining := int64(expiresAt.Sub(now).Seconds())
	if remaining > year {
		remaining = year
	}
	if remaining < 0 {
		remaining = 0
	}
	return fmt.Sprintf("public, max-age=%d, immutable", remaining)
}
