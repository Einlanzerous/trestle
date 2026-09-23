# Trestle v1 — design of record

**Tickets:** SERV-134 (the gap), IDEA-51 (the spike this executes; working
name was *Gantry*, renamed *Trestle* on 2026-09-22). IDEA-53 (photo library)
is downstream and constrains nothing here beyond §A1/§A4 of IDEA-51.

**What it is.** Take bytes from an authenticated caller, give back a stable
public URL, keep serving it. Agents upload screenshots and short videos and
paste the URL into a GitHub PR body, a Switchyard comment, or a README. That
is the whole job.

A *trestle* carries a line over a gap on a plain, open framework. On theme with
Switchyard, Interlock and Catenary.

## Shape

- **Go, single static binary**, house pattern. stdlib `net/http` only — no
  framework, no ORM, no database.
- Module `github.com/Einlanzerous/trestle`, binary `trestle`, env prefix
  `TRESTLE_`, port **4014** (next free in the estate's 40xx block after
  catenary's 4012/4013; cf-access-guard holds 4020).
- **Two surfaces in one process, split by Traefik, not by the binary:**
  - `/v1/*` — the authenticated API. Bearer token on every route.
  - `/m/*` — the public serve path. No auth, ever.
  - `/healthz`, `/readyz` — probes, unauthenticated, JSON.

## Storage: content hash is the key (IDEA-51 §A1)

Both the blob store and the index key on the **SHA-256 of the bytes**, hex.
Names never enter a storage key. The same bytes uploaded twice by anyone is
the same blob, the same record, the same URL.

`internal/blob` is one interface with one implementation in v1:

```go
type Store interface {
    // NewWriter streams to a temp location; Commit(hash) moves it into place
    // (idempotent if the hash already exists), Abort discards it.
    NewWriter(ctx) (Writer, error)
    Open(ctx, hash) (io.ReadSeekCloser, int64, error)   // ErrNotFound
    Delete(ctx, hash) error                             // idempotent
}
```

**Local disk** under `TRESTLE_DATA_DIR`:

```
<data>/blobs/<hh>/<sha256>      hh = first two hex chars
<data>/tmp/<random>             in-flight uploads; swept at boot
<data>/index/<sha256>.json      the record (below)
```

Writes are temp-file + `rename`, so a crash mid-upload leaves nothing
half-written where a reader could find it.

**R2 is deferred, not rejected.** IDEA-51 asked for both backends measured.
No R2 credential exists in Signet today (CANT-47, Catenary's own R2
decision, is still open), so an R2 implementation would be untested against
the real thing. The interface above is the seam it slots into; the ticket
that adds it also measures it. Local disk is what the estate's likely rate
(screenshots per PR, a video a month) needs.

## The index: flat files, not SQLite (IDEA-51 "pick the lighter one")

One JSON file per blob, loaded into memory at boot, written atomically on
change. No queries beyond "by hash" and "by owner", no joins, no migrations,
and a backup is `tar` of the data dir. SQLite would add a dependency and a
second file format for a table that will hold thousands of rows, not millions.

```json
{
  "sha256": "…",
  "bytes": 12345,
  "content_type": "image/png",
  "ext": "png",
  "created_at": "2026-09-22T00:00:00Z",
  "expires_at": null,
  "owners": ["catenary-agent", "swy-reviewer"]
}
```

- `owners` is the set of token **names** that uploaded these bytes. Ownership
  is what `DELETE` and the bare index are scoped to.
- `expires_at` is the latest of every upload's requested expiry; an upload
  with no `ttl` makes the blob permanent (`null`). Later uploads can only
  extend or make permanent, never shorten — a URL already pasted somewhere
  must not be shortened by a stranger re-uploading the same bytes.

## API

### `POST /v1/uploads`

- `Authorization: Bearer <token>`; 401 otherwise.
- Body: raw bytes (any `Content-Type`), or `multipart/form-data` with a
  `file` part. Optional `ttl` as a query parameter or form field: a Go
  duration, plus a `d` suffix for days (`7d`, `720h`).
- **The client's `Content-Type` is never trusted.** The type is sniffed from
  the first 512 bytes (`http.DetectContentType`, plus an SVG check: an XML
  document whose root element is `svg`). The sniffed type is what the record
  stores and what `/m/` serves. Off the allow-list → **415**.
- Allow-list and default caps (env-overridable, see Config):

  | type | ext | cap |
  |---|---|---|
  | `image/png` `image/jpeg` `image/webp` `image/gif` | png jpg webp gif | `TRESTLE_MAX_IMAGE_BYTES`, default 10 MiB |
  | `image/svg+xml` | svg | same image cap |
  | `video/mp4` `video/webm` | mp4 webm | `TRESTLE_MAX_VIDEO_BYTES`, default 100 MiB |

  Over the cap for the sniffed type → **413**. The cap is enforced while
  streaming (`http.MaxBytesReader` at the video cap, then the type cap once
  the type is known), never by reading the whole body first.
- Per-token quota: the sum of `bytes` across records the token owns. Over
  `TRESTLE_QUOTA_BYTES_PER_TOKEN` (default 2 GiB) → **413** with
  `"error":"quota_exceeded"`. A shared blob counts fully against each owner;
  that is deliberate and simple.
- Response **201** (also on dedupe — the caller got what it asked for):

  ```json
  {"id":"<sha256>","sha256":"<sha256>","url":"https://media…/m/<sha256>.png",
   "bytes":12345,"content_type":"image/png","expires_at":null,"existed":false}
  ```

  `url` is `TRESTLE_PUBLIC_BASE_URL` + `/m/<sha256>.<ext>`. **The canonical
  URL carries the extension** because Cloudflare's default cache eligibility
  is by extension, and an immutable blob behind the tunnel should be served
  from the edge, not the box.

### `GET /v1/uploads` · `GET /v1/uploads/{id}` · `DELETE /v1/uploads/{id}`

Owner-scoped. The list is the "bare index of what a token owns" IDEA-51 keeps
in scope; nothing more. `DELETE` removes the caller's ownership; when the last
owner is gone the blob and record are deleted. A record the caller does not
own is **404**, not 403 — the public path already reveals existence by hash,
but the API does not confirm who else uploaded what.
After a `DELETE` of a permanent blob, edge and browser caches may keep
serving it for up to a year under `immutable`; purging it is a
Cloudflare-side action, not something the origin can force.

### `GET /m/{sha256}` and `GET /m/{sha256}.{ext}`

- Unknown, expired, or `ext` disagreeing with the record → **404**. The
  extension in a path is **derived from the record**, never from a client
  filename (IDEA-51 §A3), so `…/x.png` can never serve `text/html`.
- `HEAD` and byte ranges via `http.ServeContent`, so video seeks.
- Headers on every hit:
  - `Content-Type` from the record.
  - `Cache-Control: public, max-age=31536000, immutable` for a permanent blob;
    a blob with a TTL caps `max-age` at the seconds remaining, so no edge or
    browser cache outlives the origin's 404.
  - `ETag: "<sha256>"`, `Last-Modified` from `created_at`.
  - `X-Content-Type-Options: nosniff`
  - `Cross-Origin-Resource-Policy: cross-origin`, `Access-Control-Allow-Origin: *`
    — the whole point is embedding from other origins.
  - `Content-Disposition: inline; filename="<sha256>.<ext>"`
- **SVG is the exception: `Content-Disposition: attachment` and
  `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; sandbox`.**
  An SVG navigated to directly runs script in the estate's origin; `<img>`
  embedding ignores `Content-Disposition` entirely, so attachment costs
  nothing for the use case and closes the direct-navigation case. The CSP is
  belt-and-braces for browsers that render attachments inline anyway.
  Sanitising was rejected: a sanitiser is a parser that has to be right
  forever, and the ticket's use case never needs an SVG to be a document.
- The serve log line names the hash, the owners, the bytes sent and the
  status, so a served blob is always attributable to the token that put it
  there (the "public file host by accident" mitigation IDEA-51 asks to
  measure rather than assume).

### Probes

`GET /healthz` → `{"status":"ok","version":"0.1.0","sha":"<40 hex>"}`,
bare semver, `sha` `null` outside a release build, both fields on the 503
path too (PRINCIPLES §4). `GET /readyz` additionally checks the data dir is
writable.

## Auth: token names, hashes in config

`TRESTLE_TOKENS` is `name=sha256hex,name=sha256hex,…`. The **service holds
hashes**; the consumer holds the plaintext, in Signet, minted per consumer
(PRINCIPLES §5: never share a token across components). Comparison is
constant-time over digests. The name is the actor in every log line and the
`owners` entry on every record.

`trestle token mint --name <consumer>` prints the plaintext to stdout once
and the `name=hash` line to stderr, so `> token` captures only the secret.
`trestle token hash` derives the hash from a token on stdin, for a value
Signet already holds.

## Retention

A timer inside `serve` (`TRESTLE_SWEEP_INTERVAL`, default 1h) deletes expired
records and their blobs; `trestle sweep` runs one pass and exits, for a
stopped service. `serve` holds an exclusive lock on `<data>/.lock` for its
lifetime and `sweep` refuses while it is held: two processes sweeping and
uploading one data dir can delete a blob a live upload just deduplicated
against.
Expiry is honoured on the serve path the moment it passes — the sweep is
about disk, not about correctness.

No default TTL. SERV-134 wants a URL "stable enough to sit in a ticket for a
year"; a caller that wants less says so.

## Config (env-only, no files)

| variable | default | notes |
|---|---|---|
| `TRESTLE_PORT` | `4014` | |
| `TRESTLE_DATA_DIR` | — | required |
| `TRESTLE_PUBLIC_BASE_URL` | — | required; scheme+host, no trailing slash, e.g. `https://media.zerogravity.industries` |
| `TRESTLE_TOKENS` | — | required, at least one entry |
| `TRESTLE_MAX_IMAGE_BYTES` | `10485760` | |
| `TRESTLE_MAX_VIDEO_BYTES` | `104857600` | |
| `TRESTLE_QUOTA_BYTES_PER_TOKEN` | `2147483648` | |
| `TRESTLE_SWEEP_INTERVAL` | `1h` | |
| `TRESTLE_LOG_LEVEL` | `info` | debug/info/warn/error |
| `TRESTLE_LOG_FORMAT` | `json` | json/text |
| `TRESTLE_SHUTDOWN_GRACE` | `20s` | |

Every refusal names the variable. Tokens never reach a log line.

## The agent-facing client

Two-line curl, and a subcommand that is the same thing with the env read for
you:

```sh
curl -sS -H "Authorization: Bearer $TRESTLE_TOKEN" \
  --data-binary @shot.png http://127.0.0.1:4014/v1/uploads | jq -r .url

TRESTLE_URL=http://127.0.0.1:4014 TRESTLE_TOKEN=… trestle upload shot.png [--ttl 30d]
```

The PR-opening flow is the caller's concern.

## Deployment (construct-server, SERV ticket)

- Compose block `trestle`, image `ghcr.io/einlanzerous/trestle:${TRESTLE_TAG}`,
  volume `trestle_data:/data`, **`ports: 127.0.0.1:4014:4014`** — agents run
  on the box and upload over loopback; nothing else reaches the API in v1.
- Public serve host **`media.zerogravity.industries`** on the tunnel, router
  `trestle-media` on the `internal` entrypoint with rule
  `Host(media…) && (PathPrefix(/m/) || Path(/healthz))` and **no
  `cf-access-jwt`**: GitHub's camo proxy holds no credential. That makes it
  the third entry in `check-edge-auth.sh`'s exemption allowlist after the
  webhook path and placard, argued for there. The path restriction is what
  bounds it: `/v1/` does not exist on that host.
- The Access-gated API host `trestle.zerogravity.industries` (browser access
  to the bare index; off-box agents via an Access service token) is a
  separate SERV ticket, because it needs an Access application and an AUD
  that only exists once the application does.

## Out (unchanged from IDEA-51)

Albums, galleries, a web UI, transcoding, thumbnails, resizing, user
accounts, anything Catenary-specific, replacing Switchyard's attachment
table. Named paths (`/a/{album}/{name}`) are IDEA-51 §A3's design of record
for the follow-on project and are not built here; nothing here forecloses
them because names never reach a storage key.
