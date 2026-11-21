# syntax=docker/dockerfile:1.7

# =============================================================================
# Stage 1: Deterministic Static Go Builder (CGO_ENABLED=0, Zero External Deps)
# =============================================================================
FROM golang:1.23-alpine AS builder

WORKDIR /src

COPY go.mod Makefile ./
COPY cmd/ ./cmd/
COPY internal/ ./internal/

ARG VERSION=1.0.0
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

RUN if grep -Eq '^[[:space:]]*require[[:space:]]' go.mod; then \
      echo "FATAL: zero-dependency contract violated in go.mod" >&2; \
      exit 1; \
    fi && \
    CGO_ENABLED=0 go build \
      -trimpath \
      -ldflags="-s -w \
        -X github.com/PedroMartinezag/dock-prune-daemon/internal/buildinfo.Version=${VERSION} \
        -X github.com/PedroMartinezag/dock-prune-daemon/internal/buildinfo.Commit=${COMMIT} \
        -X github.com/PedroMartinezag/dock-prune-daemon/internal/buildinfo.BuildDate=${BUILD_DATE}" \
      -o /out/dock-prune-daemon \
      ./cmd/dock-prune-daemon

# =============================================================================
# Stage 2: Hardened Shell-less Distroless Runtime (No Shell, No Package Manager)
# =============================================================================
FROM gcr.io/distroless/static-debian12:latest

LABEL org.opencontainers.image.title="dock-prune-daemon" \
      org.opencontainers.image.description="Autonomous zero-dependency Go container storage control plane with OCI Layer DAG math, Linux PSI pacing & Ed25519 Merkle audit logs." \
      org.opencontainers.image.source="https://github.com/PedroMartinezag/dock-prune-daemon" \
      org.opencontainers.image.authors="Pedro Martinez (@PedroMartinezag)" \
      org.opencontainers.image.licenses="Apache-2.0" \
      io.dockprune.keep="true"

COPY --from=builder /out/dock-prune-daemon /usr/local/bin/dock-prune-daemon

VOLUME ["/var/lib/dock-prune-daemon"]
EXPOSE 9402

ENTRYPOINT ["/usr/local/bin/dock-prune-daemon"]
CMD ["daemon", "--listen-addr", "0.0.0.0:9402"]
