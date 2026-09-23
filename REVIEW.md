# Review instructions

What a review of *this* repo is for. The shared reviewer (construct-server
`docs/pr-reviewer.md`) supplies the procedure; this file supplies the
judgement. `CLAUDE.md` states the invariants — read it first, and the design
of record at `docs/decisions/serv-134-trestle-v1.md` before reviewing a
change to the API, the storage layout, or the serve headers. Six of the
invariants are what most of this file is about.

## What CI already proves

Do not spend the review re-proving these.

| job | proves |
|---|---|
| `verify` / *build, vet, test* | `gofmt -l`, `go build ./...`, `go vet ./...`, `go test -race ./... -count=1` — against a temp dir and `httptest` only. No external services, so there is no short-circuit-to-green case here: `ci.yml` has no path filter and nothing it depends on can be down. |
| `lint` | golangci-lint v2, `standard` set, plus `actionlint` over every workflow file |

What none of them prove: that a test asserts the property the ticket asked
for, or any of the properties below. No Go test observes them by
construction — they are checked by reading.

## Always check

### 1. The six invariants (CLAUDE.md)

For any change touching `internal/blob/`, `internal/index/`, `internal/api/`
or `internal/sniff/`, check directly against these:

1. **The storage key is the content hash, and nothing else ever is.** A
   name, an album, a filename or an extension reaching a blob path — rather
   than the index or the URL — is 🔴. It welds a mutable thing to an
   immutable one.
2. **The client's `Content-Type` and filename are never trusted.** The type
   is sniffed once, at upload, and served from the record thereafter. Code
   that echoes a client-supplied `Content-Type`, or that derives the served
   type from a `/m/` path's extension rather than the record, is 🔴 — it is
   what stops `screenshot.png` serving `text/html` from the estate's origin.
3. **`/m/` is public and serves only blobs.** No listing, no index, no API
   under it, ever. A route under `/m/` that returns anything but blob bytes
   is 🔴 on sight.
4. **SVG is never served inline.** `Content-Disposition: attachment` plus
   the sandboxing CSP. A change that serves SVG `inline`, or that adds a
   sanitizer instead of the disposition header, is a finding — sanitizing
   was rejected on the design doc's own reasoning: a sanitizer has to be
   right forever, and the use case never needs an SVG to be a document.
5. **Expiry only ever extends.** Any path where a later upload's `ttl` can
   shorten an existing record's `expires_at`, rather than only extend it or
   make it permanent, is 🔴 — a URL already pasted somewhere must not be
   shortened by a stranger re-uploading the same bytes.
6. **Tokens never reach a log line or an error message.** The service holds
   hashes (`TRESTLE_TOKENS` is `name=sha256hex`); the name is the actor. Any
   log line, panic message, or error string interpolating a token or its
   hash is 🔴.

### 2. The serve-header contract (`GET /m/{sha256}[.{ext}]`)

The design doc pins an exact header set for every hit: `Content-Type` from
the record, `Cache-Control: public, max-age=31536000, immutable`, `ETag`,
`Last-Modified`, `X-Content-Type-Options: nosniff`,
`Cross-Origin-Resource-Policy: cross-origin`,
`Access-Control-Allow-Origin: *`, and `Content-Disposition: inline` —
except SVG, which gets `attachment` and its own CSP instead. A diff that
drops one of these, or narrows the CORS/CORP pair, is a finding even if the
body is otherwise correct — the whole point of `/m/` is embedding from
other origins.

The extension in a `/m/{sha256}.{ext}` path is **derived from the record,
never from the request** (IDEA-51 §A3): a mismatch is 404, not a redirect.

### 3. `/m/` is the estate's one unauthenticated surface serving agent-uploaded bytes

Its exposure is bounded by four things CLAUDE.md names: the allow-list, the
size caps (streamed via `http.MaxBytesReader`, never a whole-body read
before the check), the per-token quota, and the serve log naming the owner.
A change that removes or weakens any one of the four without discussion is a
finding, not an optimization — this is the "public file host by accident"
mitigation IDEA-51 asks to measure rather than assume.

### 4. Guards are applied at the route table

`/v1/*` is bearer-gated on every route; `/m/*`, `/healthz`, `/readyz` are
not, and must not become gated by accident either. A handler is guarded by
the line that registers it, not by having a guard-shaped name — read the
route table, not the handler.

### 5. Version reporting (PRINCIPLES §4)

`/healthz` and `/readyz` report bare semver (never `v`-prefixed) and a full
40-character `sha` or JSON `null`, on the 503 path too. A blank `VERSION`
build arg must map to `"dev"` in code — the Dockerfile's `ARG` default
cannot do this, since it is bypassed in exactly the case that matters (a
real publish build). Check both together if either changes.

## Severity

- **🔴 Important** — breaks one of the six invariants, widens what `/m/` or
  `/v1/*` exposes, leaks a token, or does not do what the ticket asked.
- **🟡 Nit** — conventions, clarity, a comment that will mislead. Never
  blocking.
- **🟣 Pre-existing** — real, not introduced here. At most two per review.

Cap nits at five; beyond that say "plus N similar" in the summary. A review
that buries one Important finding under a dozen nits has failed at its job.

## Verification bar

Report a finding only when you can point at the line that causes it and name
the concrete failure — the input, state, or sequence that produces the wrong
outcome. "This could be risky" is not a finding. Where a probe is cheap, run
it — this repo builds fast and has no external dependencies to fake.

## Summary shape

Open with a one-line tally — `2 important, 1 nit` — or **No blocking
issues**. Then findings, most severe first, each with the file, the concrete
failure, and what would fix it. Close with what you checked and could not
fault.

If the diff is clean, say so in one line and stop. Do not pad.
