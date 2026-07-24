# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM golang:1.25.12-alpine AS builder

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

WORKDIR /src

RUN apk add --no-cache ca-certificates tzdata

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -trimpath \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}" \
    -o /out/nodeping-agent ./cmd/nodeping-agent

FROM alpine:3.22

RUN apk add --no-cache bash ca-certificates coreutils curl minisign tzdata iputils traceroute mtr \
    && command -v ping >/dev/null 2>&1 \
    && command -v traceroute >/dev/null 2>&1 \
    && command -v mtr >/dev/null 2>&1 \
    && addgroup -S nodeping \
    && adduser -S -G nodeping -h /var/lib/nodeping-agent nodeping \
    && mkdir -p /var/lib/nodeping-agent \
    && chown -R nodeping:nodeping /var/lib/nodeping-agent

COPY --from=builder /out/nodeping-agent /usr/local/lib/nodeping-agent/nodeping-agent
COPY deploy/nodeping-agent/update-nodeping-agent.sh /usr/local/bin/nodeping-agent-update
COPY deploy/nodeping-agent/container-entrypoint.sh /usr/local/bin/nodeping-agent-entrypoint
RUN chmod 0755 \
    /usr/local/lib/nodeping-agent/nodeping-agent \
    /usr/local/bin/nodeping-agent-update \
    /usr/local/bin/nodeping-agent-entrypoint \
    && ln -s /usr/local/lib/nodeping-agent/nodeping-agent /usr/local/bin/nodeping-agent

ENV NODEPING_AGENT_TOKEN_FILE=/var/lib/nodeping-agent/agent-token
ENV NODEPING_INSTALL_MODE=docker
VOLUME ["/var/lib/nodeping-agent"]

USER nodeping
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 CMD /usr/local/lib/nodeping-agent/nodeping-agent liveness >/dev/null || exit 1
ENTRYPOINT ["/usr/local/bin/nodeping-agent-entrypoint"]
