# SPIKE — does GitHub render Trestle URLs? (SERV-208, IDEA-51 finding 1)

Run **2026-09-23 04:52–04:56 UTC** (2026-09-22 local), pre-deploy: `trestle`
built from `main` (`fc7e71d`) in a container, exposed through a Cloudflare
**quick tunnel** (`*.trycloudflare.com`), referenced from
[PR #2](https://github.com/Einlanzerous/trestle/pull/2) (body and one comment).
Everything below about camo is **GitHub's behaviour on that day**; GitHub can
change camo at any time without notice. The post-deploy run against
`media.zerogravity.industries` is not done yet (see 3). The tunnel is gone
by the time you read this, so the PR's images are broken, as expected.

Assets: PNG 640×320 (6 363 B), MP4 3 s H.264/AAC (40 323 B), SVG with a `<script>` (280 B).

## 1a · Image — **yes**

Rendered `body_html` (`Accept: application/vnd.github.full+json`); the PR
comment's `body_html` was **byte-identical** to the body's (7 532 B each).

| # | reference | result |
|---|---|---|
| R1 | `![png](…/m/<hash>.png)` | rewritten to `camo.githubusercontent.com/<hmac>/<hex url>`, wrapped in a link to the camo URL |
| R2 | `<img src=…/m/<hash>.png>` | same camo URL as R1 (camo keys on the URL); `width` kept |
| R3 | bare `…/m/<hash>.png` on its own line | **not** an image: an autolink to the origin, `rel="nofollow"` |
| R4 | `![png](…/m/<hash>)` (no extension) | rewritten to camo, served `image/png` — camo does not care about the extension |
| R8 | `![svg](…/m/<hash>.svg)` | rewritten to camo; renders |
| R9 | `<img src=….svg>` | same camo URL as R8 |

Named path (`/a/{album}/{name}`) and 302-to-hash shapes (IDEA-51 §A2):
**not measured, deferred with §A3** — neither exists in v1.

Camo, first `HEAD` (a MISS; camo issued a `GET` to the origin), PNG:

```
HTTP/2 200
cache-control: public, max-age=31536000, immutable
content-security-policy: default-src 'none'; img-src data:; style-src 'unsafe-inline'
content-type: image/png
last-modified: Wed, 23 Sep 2026 04:52:23 GMT
x-content-type-options: nosniff
x-frame-options: deny
server: github.com
accept-ranges: bytes
age: 0
x-served-by: cache-chi-kmdw8640075-CHI
x-cache: MISS
x-timer: S1790139265.681510,VS0,VE149
content-length: 6363
```

Eight seconds later every camo URL was `x-cache: HIT`, `age: 8`. R4 and R8
returned the same set (`VE297`/`VE187` on the miss); the SVG kept
`content-type: image/svg+xml`.

Origin, same PNG through the tunnel:

```
HTTP/2 200
content-type: image/png
content-length: 6363
cf-cache-status: DYNAMIC
accept-ranges: bytes
access-control-allow-origin: *
cache-control: public, max-age=31536000, immutable
content-disposition: inline; filename="01e4d9ed….png"
etag: "01e4d9ed59483a83ce84051a5bd510c1afa8a935ec9298a2cef611519b853b03"
cross-origin-resource-policy: cross-origin
x-content-type-options: nosniff
```

What made the difference: a 200 with a correct `image/*` type over public
HTTPS with no credential. Camo **passes through** `content-type`,
`cache-control` (our `immutable`, one year) and `last-modified`; it **drops**
`etag`, `content-disposition`, `access-control-allow-origin` and
`cross-origin-resource-policy`, and **adds** its own locked-down CSP. So the
SVG's `attachment` + `sandbox` defence does not travel through camo, and does
not need to: camo's CSP (`default-src 'none'`) blocks the `<script>`, and an
`<img>` never runs SVG script anyway. The camo body is the SVG byte-for-byte,
script included — camo does not sanitise.

Camo fetches **lazily**: its origin `GET`s came at 04:54:24, on first request
of the camo URLs, not at PR creation (04:53:44). Earlier hits at 04:53:55 on
every asset, MP4 included, are unattributed (likely the PR's checks): the
serve log has no `User-Agent`.

## 1b · Video — **no** (degrades to a link, as expected)

| # | reference | result |
|---|---|---|
| R5 | bare `…/m/<hash>.mp4` | autolink to the origin, `rel="nofollow"`; no player |
| R6 | `[trestle-test.mp4](….mp4)` | plain link to the origin; no player |
| R7 | `<video src=….mp4 controls>` | **stripped entirely** — rendered as an empty `<p dir="auto"></p>` |

No camo URL is minted for video. GitHub's inline player is only for
`user-attachments` assets on its own CDN. The link itself works: the origin
serves `video/mp4`, `content-disposition: inline`, `accept-ranges: bytes`
(a `Range: bytes=0-1023` gave `206`), so clicking it plays in the browser.

**Practical PR shape:** a poster frame uploaded as a PNG and embedded with
image syntax, the MP4 linked directly beneath:

```md
![demo — poster](https://media…/m/<poster>.png)
[▶ demo.mp4 (3 s)](https://media…/m/<video>.mp4)
```

## 2 · Round trip — **~0.15 s**, local disk

`curl` upload over loopback, then the first public `GET` of the returned URL
through the tunnel. Fresh bytes each run (so no dedupe hit):

| run | upload | upload → first public 200 |
|---|---|---|
| 1 | 0.006 s | 0.135 s |
| 2 | 0.006 s | 0.161 s |
| 3 | 0.006 s | 0.158 s |

Renderable as soon as pasted; camo fetches on first view. R2: SERV-209.

## 3 · Latency — cold vs warm (quick tunnel, local disk)

Each is a new `curl` process (new TLS connection); "cold" is the first
request for a just-uploaded object.

| path | first | next four |
|---|---|---|
| PNG 6 KiB, tunnel → origin | 0.165 s | 0.066–0.085 s |
| MP4 39 KiB, tunnel → origin | 0.206 s | 0.068–0.089 s |
| PNG, loopback (no tunnel) | 0.0005 s | 0.0003–0.0004 s |
| PNG via camo, miss (edge `VE`) | 0.149–0.297 s | — |
| PNG via camo, hit | — | 0.032–0.034 s |

The tunnel returned `cf-cache-status: DYNAMIC` for `.png` and `.mp4` alike:
quick tunnels do not cache, so every hit reached the box. Whether the real
zone serves `/m/<hash>.png` from the edge (the reason the canonical URL
carries the extension) is **not measured here** and is the one thing the
post-deploy run must check. Readers of a PR mostly hit camo, not us.

## 4 · Other surfaces — **not measured here**

- **README:** same GitHub Markdown renderer as PR bodies and comments (shown
  identical above), so images via camo, video as a link. Inferred.
- **Switchyard comment:** Switchyard renders Markdown in comments; how it
  treats a remote `<img>`/image syntax (proxy, CSP `img-src`, sanitiser) was
  not tested. Not measured here.

## 5 · Exposure — what a leaked upload token buys

From `internal/sniff` and `internal/api/uploads.go`:

**Bounded:**
- Only types sniffed from the first 512 bytes as PNG, JPEG, WebP, GIF, SVG
  (XML whose root is `<svg`), MP4 or WebM (EBML DocType checked); anything
  else is **415** before a byte hits disk. Client `Content-Type` and filename
  are ignored; the served type and extension come from the record.
- ≤ 10 MiB per image, ≤ 100 MiB per video, enforced while streaming.
- ≤ 2 GiB per token (sum of owned bytes), then **413** `quota_exceeded`.
- Every `/m/` serve line names the hash and its `owners` (token names), so
  whatever is served is attributable to the token that uploaded it.
- URLs are content-addressed SHA-256: unguessable, but **permanent until
  deleted** (no default TTL). Cleanup is `DELETE` with that token, or removing
  the record on disk.
- SVG direct navigation is `attachment` + `sandbox` CSP: no script in the
  estate's origin.

**Not bounded:**
- **Bandwidth and request rate on `/m/`**: no rate limit, no per-object
  egress cap. A 100 MiB video hotlinked from elsewhere is served for free,
  and (per 3) the quick tunnel caches nothing.
- **Hotlinking a legitimately uploaded file**: any public URL, ours included,
  can be embedded anywhere; no token is needed to serve it.
- **Content beyond byte 512**: only the head is sniffed. This run appended
  arbitrary bytes after a PNG's `IEND` and it was accepted and served as
  `image/png`. Browsers will not execute it (`nosniff`), but a valid header
  is a carrier for up to 10/100 MiB of anything.
- **Content itself**: an attacker can host any image or video that fits the
  caps, i.e. up to 2 GiB of abuse material per leaked token, until someone
  notices. Revocation is removing the token from `TRESTLE_TOKENS` and
  restarting; it does not delete what was uploaded.

## 6 · Storage cost — local disk

Assumed rate: ~15 PRs/week × 2 screenshots × ~300 KiB, plus one 20 MiB video
a month. Index JSON is ~300 B/record — noise.

| | per month | per year |
|---|---|---|
| screenshots (30/wk × 300 KiB) | ≈ 38 MiB | ≈ 457 MiB |
| video (1 × 20 MiB) | 20 MiB | 240 MiB |
| **total** | **≈ 58 MiB** | **≈ 0.68 GiB** |

The compose volume lands on the root LV, on the box's 1 TB NVMe
(`nvme1n1`): 936 GiB, 335 GiB free on 2026-09-22. A year of Trestle is
~0.2 % of that free space. The binding limit is the **per-token quota**: if one agent token
does all of it, 2 GiB lasts ~3 years. R2 is SERV-209.

## 7 · Recommendation — **graduate** (images as specified; video as poster + link)

Finding 1a is a clean yes: GitHub rewrites every image-shaped reference to a
Trestle URL through camo, camo keeps our `immutable` one-year cache header,
and a pasted screenshot renders within one round trip of ~0.15 s — which is
the whole of SERV-134's gap. Video does not render inline (1b), but that is
GitHub's rule for every non-GitHub host, not a Trestle failure, and the
linked MP4 plays from the origin with ranges, so the poster-PNG-plus-link
shape keeps video worth hosting rather than narrowing to images only. Before
or during deploy: confirm edge caching on the real zone (3), log
`User-Agent` on `/m/` so fetches are attributable, and put a rate limit on
the public host in Traefik, since bandwidth is the one exposure the service
itself does not bound (5).
