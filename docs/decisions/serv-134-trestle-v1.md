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

### Public and private instances

*Amended 2026-11-14 (GENZO-5).* The same binary runs in two shapes, chosen
by `TRESTLE_PUBLIC_SERVE`:

- **Public** (`true`, the default — everything above, unchanged): `/m/` is
  mounted and every upload answers with a public URL.
- **Private** (`false`): `/m/` is **not mounted at all**, so every `/m/…`
  request is the mux's 404 whether or not the blob exists. Nothing on a
  private instance serves bytes without a bearer token. Its first consumer is
  the Genzo photo library (`trestle-genzo`), which holds the only token.
  `TRESTLE_PUBLIC_BASE_URL` has no meaning there: it is not required, and
  setting it alongside `TRESTLE_PUBLIC_SERVE=false` refuses the boot, so a
  switch flipped by accident on the public instance fails loudly instead of
  turning every pasted link into a 404. The upload response's `url` is JSON
  `null` (below), and the owner reads bytes back through the authenticated
  `GET /v1/blobs/{sha256}` (GENZO-6). Probes stay unauthenticated on both.

A bad `TRESTLE_PUBLIC_SERVE` value (anything `strconv.ParseBool` does not
accept) refuses the boot, naming the variable.

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

**Durability of a 201 (GENZO-30).** When `POST /v1/uploads` answers 201, the
upload survives a power loss or kernel crash, on a filesystem that honours
`fsync` (ext4, xfs, btrfs on Linux, with the drive's write cache flushed
on `fsync` as the kernel does by default). Before `Add` returns, in this
order:

1. the temp file holding the bytes is fsynced;
2. the first time a process uses a shard, `blobs/<hh>` is created if needed
   and `blobs/` is fsynced (a shard found on disk may have been created by a
   process that died before syncing it);
3. the temp file is renamed to `blobs/<hh>/<sha256>` and `blobs/<hh>` is
   fsynced, also when the blob was already there (a process that died
   between its rename and that fsync may have left it);
4. the record is written to a temp file in `index/`, fsynced, renamed to
   `<sha256>.json`, and `index/` is fsynced.

A rename or unlink is only durable once its directory is fsynced; fsyncing
the file is not enough. A 200/201 that changed no record (the same owner
re-uploading the same bytes) writes nothing to `index/`, and that is safe
only because the record in memory is then the durable one: memory changes
only after the fsync succeeds, and `index.Open` fsyncs `index/` once at boot
(a dead process may have left a renamed but unsynced record). A failed
`index/` fsync after a successful rename or unlink fails the request with
500, leaves memory at the old state, and marks the hash stale: disk may now
differ from memory either way (a removed record memory still holds, a
rewritten one it does not). An upload of a stale hash always rewrites and
syncs its record, never answers from memory, and a write or removal that
syncs clears the mark.

**Removals.** `DELETE` of the last owner and the sweep unlink the record,
fsync `index/` (the sweep once for all the records it removes), and only
then delete the blob. The blob unlink is not fsynced: a lost one brings back
a record-less blob, which the boot reconcile reclaims, never a record
without its blob. `tmp/` is never fsynced; serve purges it at boot.
`<data>` itself is not fsynced into its parent: it is expected to be a
volume that already exists. `blobs/`, `tmp/` and `index/` are made durable
in `<data>` at boot.

Not covered: a filesystem or device that lies about `fsync` (some
consumer SSDs without power-loss protection, `nobarrier`/`data=writeback`
mounts with a volatile cache, network filesystems), and corruption of bytes
already on disk. The cost, measured with `BenchmarkUpload` on ext4 over LVM
on NVMe: a 64 KiB upload goes from about 1.4 ms to 2.7 to 3.3 ms (two
directory fsyncs in the steady state); a 4 MiB upload, about 12 ms either
way, is dominated by the file fsync and the difference is within the noise.

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
  document whose root element is `svg`, plus the ISO-BMFF brand table
  and the classic QuickTime box walk below). The sniffed type is what the record stores and what `/m/` serves.
  Off the instance's allow-list → **415**.
- Default allow-list and caps (env-overridable, see Config):

  | type | ext | cap |
  |---|---|---|
  | `image/png` `image/jpeg` `image/webp` `image/gif` | png jpg webp gif | `TRESTLE_MAX_IMAGE_BYTES`, default 10 MiB |
  | `image/svg+xml` | svg | same image cap |
  | `video/mp4` `video/webm` | mp4 webm | `TRESTLE_MAX_VIDEO_BYTES`, default 100 MiB |

- **Per-instance allow-list** (*amended 2026-11-14, GENZO-7*).
  `TRESTLE_ALLOWED_TYPES` is a comma-separated list of MIME types; unset is
  exactly the table above, so the public instance accepts nothing new. A
  type Trestle cannot recognise refuses the boot, naming the variable. Four
  more types are recognised, for a photo library to opt in to:

  | type | ext | cap |
  |---|---|---|
  | `image/heic` `image/heif` `image/avif` | heic heif avif | image cap |
  | `video/quicktime` | mov | video cap |

  They are read from the leading ISO-BMFF `ftyp` box. **The v1 checks run
  first, unchanged**: anything `http.DetectContentType` already calls
  `video/mp4` (a major or compatible brand starting `mp4`) stays mp4, so on
  the default list every input gets exactly the v1 answer (a test holds the
  default list to a frozen copy of the v1 sniffer, and a fuzz target does the
  same). Only an `ftyp` box v1 refused reaches the brand table:

  | major brand | type |
  |---|---|
  | `heic` `heix` `hevc` `hevx` | `image/heic` |
  | `avif` `avis` | `image/avif` |
  | `qt  ` | `video/quicktime` |
  | `mif1` `msf1` | by the compatible brands: HEVC brands (`heic` `heix` `hevc` `hevx`) and no AV1 brand → `image/heic`; AV1 brands (`avif` `avis`) and no HEVC brand → `image/avif`; neither, or both → `image/heif` |
  | anything else, or a malformed box | **refused** |

  `mif1`/`msf1` are the generic HEIF structural brands; the compatible brands
  say which codec the file declares, and the codec is what a reader needs a
  decoder for, which is what the type is for. A file that declares HEVC is
  labelled `image/heic` (ISO/IEC 23008-12's type for HEVC-coded HEIF); one
  that declares nothing specific, or contradicts itself, gets the generic
  container type `image/heif` rather than a guess. All four are image or
  video containers with no active content, so the label decides decoding,
  never what the browser may execute. An `ftyp` box whose brands are not in
  the table is refused outright and **never handed to a looser check**. RAW
  formats (e.g. Canon CR3's `crx ` brand) are out of scope and refused.

- **Classic QuickTime and 3GP/3G2** (*amended 2026-11-14, GENZO-26*). A
  private photo-library instance (Genzo) found v0.2.0 refusing two kinds of
  real phone video as `application/octet-stream` even with
  `video/quicktime` allowed. Two more types are recognised, off by default
  like GENZO-7's, so the default list (and the public instance) accepts
  nothing new:

  | type | ext | cap |
  |---|---|---|
  | `video/3gpp` `video/3gpp2` | 3gp 3g2 | video cap |

  **3GP/3G2 by brand.** The brand table above gains two rows. As the major
  brand they decide like any other; only when the major brand is none of
  the table's (typically a generic `isom`) are the compatible brands
  consulted — any 3GPP2 brand → `video/3gpp2`, else any 3GPP brand →
  `video/3gpp`:

  | brand | type |
  |---|---|
  | `3gp4`–`3gp9`, `3ge6` `3ge7` `3ge9`, `3gg6` `3gg9`, `3gr6` `3gr9`, `3gs6` `3gs9`, `3gt8` `3gt9`, `3gf9` `3gtv` `3gvr` | `video/3gpp` |
  | `3g2a` `3g2b` `3g2c` | `video/3gpp2` |

  The 3GPP set is the MP4 registration authority's (mp4ra.org) whole-file
  3GPP brands; `3gh9`, `3gm9` and `3gmA` mark adaptive-streaming init and
  media segments, not a playable file, and stay refused. `3g2a` is
  registered there; `3g2b`/`3g2c` are the later revisions of 3GPP2
  C.S0050. A file whose brands already made it `video/mp4` keeps that
  answer (a 3G2 that lists `mp42` is still `video/mp4`), and a `qt  `,
  HEIF or AVIF major brand still decides over a compatible 3GP brand.
  **`isom`-only files (no `mp4*` and no 3GPP brand) stay refused**: they
  were refused before, and calling them `video/mp4` would change what the
  default (public) instance accepts.

  **Classic QuickTime (no leading `ftyp`) → `video/quicktime`.** QuickTime
  predates ISO-BMFF and never required `ftyp`; Apple's writers still emit
  `wide` then `mdat` first (an iPhone Live Photo movie), and fast-start or
  older files begin with `moov`, `free`, `skip` or `pnot`. The check runs
  last, so it only ever sees a head every earlier check refused (an
  `ftyp`-first file is still decided by its brands alone). It looks at the
  same 512-byte head as everything else — the window is not grown — and
  accepts only when **all** of these hold:

  1. The head parses from offset 0 as top-level boxes with valid sizes: a
     32-bit size ≥ 8; or size 1 with a 64-bit largesize ≥ 16 and < 2^63; or
     size 0 (to end of file, so the last box). Each box that ends inside
     the head is followed by another valid box header; the walk stops at a
     box that runs past the head, or a header the head cuts short.
  2. The first box is `wide`, `mdat`, `free`, `skip`, `pnot` or `moov`;
     every later one is one of those or `PICT`, `uuid` (QuickTime's
     top-level atom set, less `ftyp`).
  3. Every `wide` box is exactly 8 bytes (it is a placeholder header with no
     payload).
  4. There is positive evidence of a movie: an `mdat` header immediately
     after a `wide`, `free` or `skip` box; **or** a `moov` whose first child
     is visible and is a fixed-shape movie header — `mvhd` of exactly 108
     bytes with version 0 or 120 bytes with version 1, `cmov` whose first
     child is a 12-byte `dcom`, or `rmra` whose first child is an `rmda` —
     and fits inside the `moov`.

  *False positives.* A lone `mdat` (or `free`, `skip`, `pnot`) running past
  the head is **refused**: its payload is arbitrary media bytes, so eight
  bytes of "size + `mdat`" would be the whole signature. Text can never
  pass: every 32-bit size in text is ≥ 0x09090909, so its first box runs
  past any 512-byte head and is the only box seen, leaving only the `moov`
  route, whose movie headers need NUL bytes in their size fields. Random
  binary must first hit one of six types at bytes 4–8 (6 in 2^32) and then
  satisfy rule 4. The neighbours that do look like boxes are not in the
  set: JPEG 2000 (`jP  `, then `ftyp`), DASH segments (`styp`), fragments
  (`moof`). Tests cover these, and random binary, random text and random
  bytes behind a valid first header are all refused. The bytes are stored
  and served as `video/quicktime` with `nosniff`, so even a false positive
  is a video-type label on non-active content, and a hand-crafted file
  could already claim QuickTime with an `ftyp qt  ` box.

  *Known limit.* A classic file whose evidence lies past 512 bytes (a
  `free` of 500+ bytes before `mdat`, a `pnot` preview `PICT` that large)
  or that starts with a lone `mdat` (`mdat` first, `moov` at the end) is
  refused. None of the public samples has that shape; growing the window
  for it would mean reading more before the 415 for every upload.

  *Default behaviour.* An instance that allows `video/quicktime` now accepts
  classic QuickTime; that is the intended change. The default list does not
  allow `video/quicktime`, `video/3gpp` or `video/3gpp2`, so the public
  instance accepts nothing new; the only visible difference there is the
  415 message, which now names `video/quicktime`, `video/3gpp` or
  `video/3gpp2` where it said `application/octet-stream`. Tests hold the
  new sniffer to a frozen copy of v0.2.0's: it may only turn a head v0.2.0
  refused into one of the three types above, and a fuzz target does the
  same (alongside the existing v1 comparison for the default list).

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

  `url` is `TRESTLE_PUBLIC_BASE_URL` + `/m/<sha256>.<ext>`. On a private
  instance it is JSON `null` (*GENZO-5*): there is nothing to fetch it from,
  and a string that looks like a URL would get pasted somewhere and 404. The
  `sha256` is the handle; `trestle upload` prints it instead of a URL. **The canonical
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

### `GET /v1/blobs/{sha256}` · `HEAD /v1/blobs/{sha256}`

*Added 2026-11-14 (GENZO-6).* The owner's authenticated read, on public and
private instances alike; on a private instance it is the only way bytes
leave the service.

- Bearer-gated (401 without a valid token) and **owner-scoped**: unknown,
  expired and not-yours are the same **404** as `/v1/uploads/{id}`. `HEAD`
  answers "do I already hold this hash?" without moving the bytes; a 404
  there means "upload it" — dedupe makes that cheap if someone else holds it.
- Bare hash only; there is no `.{ext}` form, because nothing here needs an
  extension for an edge cache.
- `http.ServeContent`, so `HEAD`, single byte ranges (video seeking) and
  `If-None-Match` work; a multi-range request gets the whole blob, as on `/m/`.
- Headers:
  - `Content-Type` from the record; `ETag: "<sha256>"`; `Last-Modified` from
    `created_at`; `X-Content-Type-Options: nosniff`.
  - `Cache-Control: private, no-cache`. `private` keeps it out of every shared
    cache. `no-cache` rather than a `max-age`: the bytes behind a hash never
    change, but the *right to read them* does — a `DELETE` or an expiry must
    take effect on the next read, not when a client's cache gets round to it.
    The ETag makes each revalidation a body-less 304, and the token and
    ownership are checked on it too.
  - `Cross-Origin-Resource-Policy: same-origin` and **no**
    `Access-Control-Allow-Origin`: there is no cross-origin embedding use case
    for an authenticated read.
  - `Content-Disposition: inline; filename="<sha256>.<ext>"`, except SVG,
    which gets `attachment` and the same sandboxing CSP as `/m/` (invariant 4).
- The request log line names the hash, the actor (token name), the owners,
  the bytes sent and the status — never a token.

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
| `TRESTLE_PUBLIC_SERVE` | `true` | `false` makes a private instance: `/m/` not mounted, `url` null (GENZO-5) |
| `TRESTLE_PUBLIC_BASE_URL` | — | required when public; scheme+host, no trailing slash, e.g. `https://trestle.zerogravity.industries`. Must be unset when `TRESTLE_PUBLIC_SERVE=false` |
| `TRESTLE_TOKENS` | — | required, at least one entry |
| `TRESTLE_ALLOWED_TYPES` | v1's seven | comma-separated MIME types; unknown type refuses the boot (GENZO-7; `video/3gpp`, `video/3gpp2` recognised since GENZO-26) |
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
- Public serve host **`trestle.zerogravity.industries`** on the tunnel, router
  `trestle-media` on the `internal` entrypoint with rule
  `Host(media…) && (PathPrefix(/m/) || Path(/healthz))` and **no
  `cf-access-jwt`**: GitHub's camo proxy holds no credential. That makes it
  the third entry in `check-edge-auth.sh`'s exemption allowlist after the
  webhook path and placard, argued for there. The path restriction is what
  bounds it: `/v1/` does not exist on that host.
- The Access-gated API host `trestle-api.zerogravity.industries` (browser access
  to the bare index; off-box agents via an Access service token) is a
  separate SERV ticket, because it needs an Access application and an AUD
  that only exists once the application does.

## Out (unchanged from IDEA-51)

Albums, galleries, a web UI, transcoding, thumbnails, resizing, user
accounts, anything Catenary-specific, replacing Switchyard's attachment
table. Named paths (`/a/{album}/{name}`) are IDEA-51 §A3's design of record
for the follow-on project and are not built here; nothing here forecloses
them because names never reach a storage key.
