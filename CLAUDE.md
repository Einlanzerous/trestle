# CLAUDE.md — Trestle

A small estate service that takes bytes from an authenticated caller, gives
back a stable public URL, and keeps serving it. Agents upload screenshots and
short videos and paste the URL into a GitHub PR body, a Switchyard comment or
a README. Single static Go binary, sibling to the other construct-server Go
services.

Tracked in Switchyard under **SERV-134** (the gap) and **IDEA-51** (the spike
this executes; it was filed as *Gantry* and renamed). The design of record is
`docs/decisions/serv-134-trestle-v1.md` — read it before changing the API,
the storage layout or the serve headers.

## Layout

- `cmd/trestle/` — entrypoint + subcommands (`serve`, `sweep`, `token`,
  `upload`, `version`). Composition root: `setup()` wires config → store →
  index → handlers.
- `internal/config/` — env-only config, `TRESTLE_`-prefixed. No config files.
- `internal/blob/` — the `Store` interface and the local-disk implementation.
  Keyed by SHA-256 hex, always. R2 slots in behind the same interface.
- `internal/index/` — the flat-file record index: one JSON per blob under
  `<data>/index/`, in memory at boot, atomic writes.
- `internal/api/` — the HTTP surface: `/v1/*` (bearer-gated), `/m/*`
  (public), probes.
- `internal/sniff/` — content-type detection and the allow-list.
- `deploy/` — the `Dockerfile` and `README.md` (decisions the construct-server
  block needs). **No compose fragment and no Traefik labels here**: the block
  and every router live in `construct-server`, and a second copy is the one
  that goes stale (Catenary's `deploy/README.md` says why).

## Conventions (construct-server house style)

- Go 1.26, stdlib `net/http`. No framework, no ORM, no database.
- Config is env-only, `TRESTLE_`-prefixed; every refusal names the variable.
- Logs: `slog`, JSON to stdout by default. Health: `GET /healthz` returns
  `{"status","version","sha"}` with bare semver and a 40-char sha or `null`
  (PRINCIPLES §4). `GET /readyz` checks the data dir.
- Release-please + GHCR image `ghcr.io/einlanzerous/trestle`. Conventional
  commits with the ticket key in the subject: `feat(api): SERV-134 — …`.
- `make verify` (gofmt, vet, golangci-lint, `go test -race`) green before
  anything is handed over; CI runs the same list.

## Invariants — don't break these

1. **The storage key is the content hash, and nothing else ever is.** Names,
   albums, filenames and extensions live in the index or in the URL, never in
   a blob path (IDEA-51 §A1). Putting a name in the key welds a mutable thing
   to an immutable one.
2. **The client's `Content-Type` and filename are never trusted.** The type
   is sniffed at upload, stored on the record, and served from the record.
   The extension in a `/m/` path must match the record or the answer is 404.
   This is what stops `screenshot.png` serving `text/html` from the estate's
   origin.
3. **`/m/` is public and serves only blobs.** No listing, no index, no API
   under it. It is the one unauthenticated surface on the estate that serves
   agent-uploaded bytes, and the exposure is bounded by the allow-list, the
   size caps, the per-token quota and the serve log naming the owner.
4. **SVG is never served inline.** `Content-Disposition: attachment` plus a
   sandboxing CSP. `<img>` embedding ignores the disposition, so the use case
   loses nothing.
5. **Expiry only ever extends.** A later upload of the same bytes can make a
   blob permanent or push its expiry out; it can never bring it in. A URL
   already pasted somewhere must not be shortened by a stranger.
6. **Tokens never reach a log line or an error message.** The service holds
   hashes; the name is the actor.

## Testing

`go test -race ./...` — everything runs against a temp dir and `httptest`, no
external services. `make verify` is the full local gate.
