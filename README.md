# Trestle

Take bytes from an authenticated caller, give back a stable public URL, keep
serving it. Agents upload screenshots and short videos and paste the URL into
a GitHub PR body, a Switchyard comment or a README. That is the whole job.

Single static Go binary, stdlib only. Tracked as **SERV-134** (the gap) and
**IDEA-51** (the spike). The design of record is
[`docs/decisions/serv-134-trestle-v1.md`](docs/decisions/serv-134-trestle-v1.md);
read it before changing the API, the storage layout or the serve headers.

## For agents: uploading

```sh
curl -sS -H "Authorization: Bearer $TRESTLE_TOKEN" \
  --data-binary @shot.png http://127.0.0.1:4014/v1/uploads | jq -r .url
```

or, with the env read for you:

```sh
TRESTLE_URL=http://127.0.0.1:4014 TRESTLE_TOKEN=… trestle upload shot.png [--ttl 30d]
```

Both print the public URL (on a [private instance](#private-instances),
`url` is `null` and `trestle upload` prints the sha256 instead), e.g.
`https://trestle.zerogravity.industries/m/<sha256>.png`. With no `ttl` the
upload is permanent. `ttl` is a Go duration (`720h`) or a day count (`30d`).

The same bytes always get the same URL, whoever uploads them. A later
upload can only extend the expiry or make it permanent, never shorten it.

## Allowed types

The type comes from the bytes, never from the client's `Content-Type` or
filename. Anything else is refused with **415**.

| type | ext | cap |
|---|---|---|
| `image/png` `image/jpeg` `image/webp` `image/gif` `image/svg+xml` | png jpg webp gif svg | `TRESTLE_MAX_IMAGE_BYTES` |
| `video/mp4` `video/webm` | mp4 webm | `TRESTLE_MAX_VIDEO_BYTES` |

That is the default. An instance can choose its own list with
`TRESTLE_ALLOWED_TYPES` (comma-separated MIME types), which can also name
four types recognised from the ISO-BMFF `ftyp` brand and accepted nowhere by
default:

| type | ext | cap |
|---|---|---|
| `image/heic` `image/heif` `image/avif` | heic heif avif | `TRESTLE_MAX_IMAGE_BYTES` |
| `video/quicktime` | mov | `TRESTLE_MAX_VIDEO_BYTES` |

An `ftyp` brand Trestle does not know is refused, never guessed at; anything
that already sniffed as `video/mp4` still does. The brand rules are in the
design of record.

SVGs are served with `Content-Disposition: attachment` and a sandboxing CSP.
They still embed with `<img>` and in Markdown.

## API

Every `/v1` route needs `Authorization: Bearer <token>`. Errors are JSON:
`{"error":"code","message":"…"}`.

| route | |
|---|---|
| `POST /v1/uploads` | raw body, or `multipart/form-data` with a `file` part; `ttl` as a query parameter or form field. **201** `{id, sha256, url, bytes, content_type, created_at, expires_at, existed}`. 400 `bad_ttl`/`empty_body`, 401, 413 `too_large`/`quota_exceeded`, 415 `unsupported_type`. |
| `GET /v1/uploads` | `{"uploads":[…]}`: what this token owns, newest first |
| `GET /v1/uploads/{id}` | one upload this token owns; 404 otherwise |
| `DELETE /v1/uploads/{id}` | drop this token's ownership; the blob goes when its last owner does. 204, or 404 if not yours |
| `GET`/`HEAD /v1/blobs/{sha256}` | the bytes of a blob this token owns, with byte ranges; 404 when unknown, expired or not yours. `Cache-Control: private, no-cache`, no CORS. `HEAD` asks "do I hold this hash?". Public and private instances |
| `GET`/`HEAD /m/{sha256}[.{ext}]` | public instance only. Serves the bytes with byte ranges. 404 when the blob is unknown, expired, or the extension disagrees with the record |
| `GET /healthz` | `{"status":"ok","version":"0.1.0","sha":"<40 hex>"\|null}` |
| `GET /readyz` | same shape; 503 `"degraded"` when the data dir is not writable |

A token's quota is the sum of the bytes it owns. A shared blob counts in full
against every owner.

## Operating

```sh
trestle serve                          # the server
trestle sweep                          # one sweep pass on a STOPPED service (refuses while serve runs)
trestle token mint --name <consumer> > token   # plaintext → stdout, name=sha256 → stderr
trestle token hash < token             # sha256 of a token Signet already holds
trestle version
```

The service holds only token **hashes**. Mint one token per consumer, put
the plaintext in Signet and add the `name=hash` line to `TRESTLE_TOKENS`. The
name is the actor in every log line and the owner on every record. Tokens
never appear in logs or errors.

### Configuration (env-only)

| variable | default | notes |
|---|---|---|
| `TRESTLE_PORT` | `4014` | |
| `TRESTLE_DATA_DIR` | required | `blobs/`, `index/`, `tmp/` live here |
| `TRESTLE_PUBLIC_SERVE` | `true` | `false` runs a private instance (below) |
| `TRESTLE_PUBLIC_BASE_URL` | required when public | scheme+host, no trailing slash; must be unset when `TRESTLE_PUBLIC_SERVE=false` |
| `TRESTLE_TOKENS` | required | `name=sha256hex,name=sha256hex,…` |
| `TRESTLE_ALLOWED_TYPES` | the seven above | comma-separated MIME types; an unknown one refuses the boot |
| `TRESTLE_MAX_IMAGE_BYTES` | `10485760` | |
| `TRESTLE_MAX_VIDEO_BYTES` | `104857600` | |
| `TRESTLE_QUOTA_BYTES_PER_TOKEN` | `2147483648` | |
| `TRESTLE_SWEEP_INTERVAL` | `1h` | disk reclamation only; expiry is enforced on every read |
| `TRESTLE_LOG_LEVEL` | `info` | debug/info/warn/error |
| `TRESTLE_LOG_FORMAT` | `json` | json/text |
| `TRESTLE_SHUTDOWN_GRACE` | `20s` | |

The upload client reads `TRESTLE_URL` and `TRESTLE_TOKEN`. Any config error
refuses the boot, and the message names the variable.

### Private instances

`TRESTLE_PUBLIC_SERVE=false` runs the same binary as a private store. `/m/`
is not mounted, so every `/m/…` path is 404 whether or not the blob exists,
and nothing is served without a bearer token. `TRESTLE_PUBLIC_BASE_URL` is
not required (and refuses the boot if set), and an upload's `url` is JSON
`null`: the `sha256` is the handle, and the owner reads the bytes back with
`GET /v1/blobs/{sha256}`. The probes stay unauthenticated. The
first private instance is `trestle-genzo`, the photo library's store.

### Storage

```
<data>/blobs/<hh>/<sha256>   the bytes; the content hash is the only key
<data>/index/<sha256>.json   the record: type, ext, owners, expiry
<data>/tmp/                  in-flight uploads; purged when serve boots
<data>/.lock                 held by serve for its lifetime; keeps a second process out
```

Every write is a temp file plus a rename. A 201 is answered only once the
blob and its record, file and directory entries both, are fsynced: an upload
the service has acknowledged survives a power loss on a filesystem that
honours `fsync` (see the design of record, "Durability of a 201"). A backup
is a `tar` of the data dir.

## Development

```sh
go test -race ./...
gofmt -l . && go vet ./... && golangci-lint run
```

Tests use `httptest` and `t.TempDir()`, with no external services.
