# syntax=docker/dockerfile:1

# Production image: one self-contained static Go binary.
# Build from the repo root:
#   docker build -f deploy/Dockerfile -t trestle:latest .

# 1) Build the static binary. stdlib net/http only, no cgo dependency
#    anywhere in this repo (CLAUDE.md), so CGO is disabled unconditionally.
FROM golang:1.26-bookworm AS build
WORKDIR /app
# `go.sum*` (glob) rather than `go.sum`: Trestle has no external dependencies
# today, so there may be no go.sum to copy yet. BuildKit's glob COPY (enabled
# by the `# syntax` line above) is a no-op when nothing matches, where a
# literal filename would fail the build the day it's true and succeed only
# by accident once a dependency is added and go.sum exists.
COPY go.mod go.sum* ./
RUN go mod download
COPY . .

# Build identity. Both default to EMPTY rather than a placeholder: an image
# built outside the publish workflow must not be able to claim a release
# version (PRINCIPLES §4). main.version maps empty back to "dev".
ARG VERSION=
ARG GIT_SHA=
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w \
      -X main.version=${VERSION} \
      -X main.commit=${GIT_SHA}" \
    -o /out/trestle ./cmd/trestle

# 2) Runtime: slim Alpine with ca-certificates and wget (busybox) for the
#    compose healthcheck. Not scratch: the compose healthcheck runs `wget`
#    against /healthz, and a wget-based check against a scratch image can
#    never pass — the container sits `unhealthy` forever and anything
#    gating on `service_healthy` stalls behind it. Catenary's deploy/README.md
#    records the same trap ("the health-check and the image must be chosen
#    together") from CANT-16/CANT-78. Busybox wget in Alpine settles it and
#    keeps this compose block the same shape as every other Go service on
#    the box.
FROM alpine:3.23 AS runtime
RUN apk add --no-cache ca-certificates \
 && adduser -D -u 10001 trestle \
 && mkdir -p /data \
 && chown trestle:trestle /data
COPY --from=build /out/trestle /usr/local/bin/trestle
USER trestle
VOLUME /data
ENV TRESTLE_PORT=4014 TRESTLE_DATA_DIR=/data
EXPOSE 4014
ENTRYPOINT ["trestle"]
CMD ["serve"]
